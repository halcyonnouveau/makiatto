use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use camino::Utf8PathBuf;
use geo::{Distance, Haversine, Point, point};
use hickory_proto::rr::{
    LowerName, Name, RData, Record,
    rdata::{self, MX, TXT, caa::Property},
};
use hickory_server::{
    ServerFuture,
    authority::MessageResponseBuilder,
    proto::op::{Header, MessageType, OpCode, ResponseCode},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};
use maxminddb::Reader;
use miette::{IntoDiagnostic, Result};
use opentelemetry::{KeyValue, global};
use tokio::net::{TcpSocket, UdpSocket};
use tracing::{Level, debug, error, info, instrument, span, warn};
use url::Url;

use crate::{
    config::Config,
    corrosion::{self, schema::DnsRecord},
    web::certificate::CertificateStore,
};

#[derive(thiserror::Error, Debug, miette::Diagnostic)]
pub enum Error {
    #[error("Invalid OpCode {0:}")]
    InvalidOpCode(OpCode),
    #[error("Invalid MessageType {0:}")]
    InvalidMessageType(MessageType),
    #[error("IO error: {0:}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct DnsPeer {
    point: Point,
    ipv4: Arc<str>,
    ipv6: Option<Arc<str>>,
}

#[derive(Debug)]
pub struct DnsRequest {
    op_code: OpCode,
    message_type: MessageType,
    ip: IpAddr,
    name: LowerName,
}

#[derive(Debug)]
pub struct Handler {
    peers: Arc<[DnsPeer]>,
    records: HashMap<String, Vec<DnsRecord>>,
    reader: Reader<Vec<u8>>,
}

impl Handler {
    #[must_use]
    pub fn new(
        peers: Arc<[DnsPeer]>,
        records: HashMap<String, Vec<DnsRecord>>,
        reader: Reader<Vec<u8>>,
    ) -> Self {
        Self {
            peers,
            records,
            reader,
        }
    }

    fn create_failure_response() -> ResponseInfo {
        let mut header = Header::new();
        header.set_response_code(ResponseCode::ServFail);
        header.into()
    }

    fn caa_from_string(input: &str) -> Option<rdata::CAA> {
        let mut parts = input.split_whitespace();
        let issuer_critical = parts.next()? == "1";
        let tag = Property::from(parts.next()?.to_string());
        let value = parts.next()?;

        match tag {
            Property::Issue => Some(rdata::CAA::new_issue(
                issuer_critical,
                Some(Name::from_str_relaxed(value).unwrap()),
                Vec::new(),
            )),
            Property::IssueWild => Some(rdata::CAA::new_issuewild(
                issuer_critical,
                Some(Name::from_str_relaxed(value).unwrap()),
                Vec::new(),
            )),
            Property::Iodef => Some(rdata::CAA::new_iodef(
                issuer_critical,
                Url::parse(value).unwrap(),
            )),
            Property::Unknown(_) => None,
        }
    }

    fn soa_from_string(input: &str) -> Option<rdata::SOA> {
        let mut parts = input.split_whitespace();
        let mname = Name::from_str_relaxed(parts.next()?).unwrap();
        let rname = Name::from_str_relaxed(parts.next()?).unwrap();
        let serial = parts.next()?.parse().ok()?;
        let refresh = parts.next()?.parse().ok()?;
        let retry = parts.next()?.parse().ok()?;
        let expire = parts.next()?.parse().ok()?;
        let minimum = parts.next()?.parse().ok()?;

        Some(rdata::SOA::new(
            mname, rname, serial, refresh, retry, expire, minimum,
        ))
    }

    fn srv_from_string(input: &str) -> Option<rdata::SRV> {
        let mut parts = input.split_whitespace();
        let priority = parts.next()?.parse().ok()?;
        let weight = parts.next()?.parse().ok()?;
        let port = parts.next()?.parse().ok()?;
        let target = Name::from_str_relaxed(parts.next()?).unwrap();

        Some(rdata::SRV::new(priority, weight, port, target))
    }

    fn generate_record(
        name: &LowerName,
        record_type: &str,
        value: &str,
        ttl: u32,
        preference: Option<i32>,
    ) -> Record {
        let rdata: Option<RData> = match record_type {
            "A" => Some(RData::A(rdata::A(Ipv4Addr::from_str(value).unwrap()))),
            "AAAA" => Some(RData::AAAA(rdata::AAAA(Ipv6Addr::from_str(value).unwrap()))),
            "CAA" => Some(RData::CAA(Self::caa_from_string(value).unwrap())),
            "CNAME" => Some(RData::CNAME(rdata::CNAME(
                Name::from_str_relaxed(value).unwrap(),
            ))),
            "MX" => Some(RData::MX(MX::new(
                preference
                    .expect("preference needs MX record")
                    .try_into()
                    .unwrap(),
                Name::from_str_relaxed(value).unwrap(),
            ))),
            "NS" => Some(RData::NS(rdata::NS(Name::from_str_relaxed(value).unwrap()))),
            "SOA" => Some(RData::SOA(
                Self::soa_from_string(value).expect("Should be a valid SOA record"),
            )),
            "SRV" => Some(RData::SRV(
                Self::srv_from_string(value).expect("Should be a valid SRV record"),
            )),
            "TXT" => Some(RData::TXT(TXT::new(vec![value.to_string()]))),
            _ => None,
        };

        Record::from_rdata(name.into(), ttl, rdata.expect("Invalid record type"))
    }

    #[instrument(skip(self), fields(query_name = %request.name, client_ip = %request.ip))]
    fn build_records(&self, request: &DnsRequest) -> Result<Vec<Record>> {
        // make sure the request is a query
        if request.op_code != OpCode::Query {
            return Err(Error::InvalidOpCode(request.op_code).into());
        }

        // make sure the message type is a query
        if request.message_type != MessageType::Query {
            return Err(Error::InvalidMessageType(request.message_type).into());
        }

        // get coordinates of request
        let coords = {
            let _span = span!(Level::DEBUG, "geoip_lookup", ip = %request.ip).entered();
            let lookup = self.reader.lookup::<maxminddb::geoip2::City>(request.ip);
            match lookup {
                Ok(Some(response)) => {
                    if let Some(location) = response.location {
                        let lat = location.latitude.unwrap_or(0.0);
                        let lon = location.longitude.unwrap_or(0.0);
                        debug!("GeoIP lookup found: lat={lat}, lon={lon}");
                        point!(x: lat, y: lon)
                    } else {
                        debug!("GeoIP lookup found no location data");
                        point!(x: 0.0, y: 0.0)
                    }
                }
                Ok(None) => {
                    debug!("GeoIP lookup found no data for IP");
                    point!(x: 0.0, y: 0.0)
                }
                Err(e) => {
                    debug!("GeoIP lookup failed: {e}");
                    point!(x: 0.0, y: 0.0)
                }
            }
        };

        let lookup_name = request.name.to_string().trim_end_matches('.').to_string();

        let Some(records) = self.records.get(&lookup_name) else {
            return Ok(vec![]);
        };

        if records.is_empty() {
            return Ok(vec![]);
        }

        let closest_peer = self.peers.iter().min_by(|&a, &b| {
            let dist_a = Haversine.distance(coords, a.point);
            let dist_b = Haversine.distance(coords, b.point);
            dist_a
                .partial_cmp(&dist_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(records
            .iter()
            .filter_map(|record| {
                if !record.geo_enabled {
                    return Some(Self::generate_record(
                        &request.name,
                        &record.record_type,
                        &record.value,
                        record.ttl,
                        Some(record.priority),
                    ));
                }

                let peer = closest_peer?;

                let value = match record.record_type.as_str() {
                    "A" => &peer.ipv4,
                    "AAAA" => match &peer.ipv6 {
                        Some(ipv6) if !ipv6.is_empty() => ipv6,
                        Some(_) | None => return None,
                    },
                    _ => &record.value,
                };

                Some(Self::generate_record(
                    &request.name,
                    &record.record_type,
                    value,
                    record.ttl,
                    Some(record.priority),
                ))
            })
            .collect())
    }

    fn record_dns_metrics(
        &self,
        query_name: &str,
        query_type: &str,
        response_code: &str,
        duration: Duration,
    ) {
        let meter = global::meter("dns");

        let attributes = vec![
            KeyValue::new("query_type", query_type.to_string()),
            KeyValue::new("response_code", response_code.to_string()),
            KeyValue::new(
                "geo_enabled",
                self.records
                    .get(query_name)
                    .is_some_and(|records| records.iter().any(|r| r.geo_enabled))
                    .to_string(),
            ),
        ];

        let counter = meter
            .u64_counter("server.query.count")
            .with_description("Total number of DNS queries")
            .build();

        counter.add(1, &attributes);

        let histogram = meter
            .f64_histogram("server.query.duration")
            .with_unit("s")
            .with_description("DNS query response time in milliseconds")
            .build();

        histogram.record(duration.as_millis_f64(), &attributes);

        if self
            .records
            .get(query_name)
            .is_some_and(|records| records.iter().any(|r| r.geo_enabled))
        {
            let peer_gauge = meter
                .u64_gauge("server.peers.available")
                .with_description("Number of available peers for geo-routing")
                .build();
            peer_gauge.record(self.peers.len() as u64, &[]);
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    #[instrument(
        name = "dns_request",
        skip(self, handler),
        fields(query_name, query_type, error, slow)
    )]
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut handler: R,
    ) -> ResponseInfo {
        let start_time = std::time::Instant::now();
        let query_name = request
            .queries()
            .first()
            .map(|q| q.name().to_string())
            .unwrap_or_default();
        let query_type = request
            .queries()
            .first()
            .map(|q| q.query_type().to_string())
            .unwrap_or_default();
        let client_ip = request.src().ip();

        let span = tracing::Span::current();
        span.record("query_name", &query_name);
        span.record("query_type", &query_type);

        let dns_request = DnsRequest {
            op_code: request.op_code(),
            message_type: request.message_type(),
            ip: client_ip,
            name: request.queries().first().unwrap().name().clone(),
        };

        let records = match self.build_records(&dns_request) {
            Ok(res) => res,
            Err(e) => {
                span.record("error", e.to_string());
                error!("Failed to build DNS records: {e}");

                self.record_dns_metrics(&query_name, &query_type, "SERVFAIL", start_time.elapsed());
                return Self::create_failure_response();
            }
        };

        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let response = builder.build(header, records.iter(), &[], &[], &[]);

        match handler.send_response(response).await {
            Ok(info) => {
                let duration = start_time.elapsed();

                if duration > Duration::from_millis(100) {
                    span.record("slow", duration.as_millis());
                    warn!("Slow DNS query detected: {}ms", duration.as_millis());
                }

                self.record_dns_metrics(&query_name, &query_type, "NOERROR", duration);
                info
            }
            Err(e) => {
                span.record("error", e.to_string());
                error!("Failed to send DNS response: {e}");

                self.record_dns_metrics(&query_name, &query_type, "SERVFAIL", start_time.elapsed());
                Self::create_failure_response()
            }
        }
    }
}

pub(crate) async fn download_geolite(path: &Utf8PathBuf) -> Result<()> {
    info!("Downloading GeoLite2 database...");

    let parent = path.parent().unwrap();
    tokio::fs::create_dir_all(parent)
        .await
        .map_err(|e| miette::miette!("Couldn't create GeoLite dir: {e}"))?;

    let client = reqwest::Client::new();

    let response = client
        .get("https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb")
        .send()
        .await
        .map_err(|e| miette::miette!("Failed to download GeoLite2 database: {e}"))?;

    if !response.status().is_success() {
        return Err(miette::miette!(
            "Failed to download GeoLite2 database: HTTP {}",
            response.status()
        ));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| miette::miette!("Failed to read response body: {e}"))?;

    tokio::fs::write(path, bytes)
        .await
        .map_err(|e| miette::miette!("Failed to write GeoLite2 database to {path}: {e}"))?;

    info!("GeoLite2 database downloaded successfully");
    Ok(())
}

/// Start a DNS server instance and return a handle to control it
///
/// # Errors
/// Returns an error if the DNS server fails to start, bind to port 53, or encounters runtime errors
///
/// # Panics
/// Panics if the socket address "[::]:853" or "[::]:53" cannot be parsed, which should never happen
#[allow(clippy::too_many_lines)]
pub async fn start(
    config: Arc<Config>,
    mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
) -> Result<()> {
    if !config.dns.geolite_path.exists() {
        download_geolite(&config.dns.geolite_path).await?;
    }

    let peers: Vec<DnsPeer> = corrosion::get_peers()
        .await
        .unwrap_or_else(|_| Arc::from([]))
        .iter()
        .map(|p| DnsPeer {
            point: point!(x: p.latitude, y: p.longitude),
            ipv4: p.ipv4.clone(),
            ipv6: p.ipv6.clone(),
        })
        .collect();

    let records = corrosion::get_dns_records().await.unwrap_or_default();
    let reader = Reader::open_readfile(&*config.dns.geolite_path).into_diagnostic()?;

    let cert_store = {
        let store = CertificateStore::new();
        if let Err(e) = store.load_certificates().await {
            error!("Failed to load certificates for DNS: {e}");
            None
        } else {
            info!("Loaded certificates for DNS virtual hosts");
            Some(store)
        }
    };

    let tls_config = if let Some(ref cert_store) = cert_store {
        match cert_store.build_tls_config().await {
            Ok(tls_config) => {
                let cert_resolver = tls_config.cert_resolver.clone();

                let socket = TcpSocket::new_v6()
                    .map_err(|e| miette::miette!("Failed to create IPv6 socket: {e}"))?;

                socket
                    .set_reuseaddr(true)
                    .map_err(|e| miette::miette!("Failed to set SO_REUSEADDR: {e}"))?;

                #[cfg(target_os = "linux")]
                socket
                    .set_reuseport(true)
                    .map_err(|e| miette::miette!("Failed to set SO_REUSEPORT: {e}"))?;

                socket
                    .bind("[::]:853".parse().unwrap())
                    .map_err(|e| miette::miette!("Failed to bind DoT TCP socket: {e}"))?;

                let dot_listener = socket
                    .listen(1024)
                    .map_err(|e| miette::miette!("Failed to listen on DoT socket: {e}"))?;

                let doq_socket = UdpSocket::bind("[::]:853")
                    .await
                    .map_err(|e| miette::miette!("Failed to bind DoQ UDP socket: {e}"))?;

                Some((dot_listener, doq_socket, cert_resolver))
            }
            Err(e) => {
                info!("DNS secure protocols disabled: {e}");
                None
            }
        }
    } else {
        None
    };

    let handler = Handler::new(Arc::from(peers), records, reader);
    let mut server = ServerFuture::new(handler);

    server.register_socket(
        UdpSocket::bind("[::]:53")
            .await
            .map_err(|e| miette::miette!("Failed to bind UDP socket: {e}"))?,
    );

    let dns_socket = TcpSocket::new_v6()
        .map_err(|e| miette::miette!("Failed to create IPv6 socket for DNS: {e}"))?;

    dns_socket
        .set_reuseaddr(true)
        .map_err(|e| miette::miette!("Failed to set SO_REUSEADDR for DNS: {e}"))?;

    #[cfg(target_os = "linux")]
    dns_socket
        .set_reuseport(true)
        .map_err(|e| miette::miette!("Failed to set SO_REUSEPORT for DNS: {e}"))?;

    dns_socket
        .bind("[::]:53".parse().unwrap())
        .map_err(|e| miette::miette!("Failed to bind DNS TCP socket: {e}"))?;

    let dns_listener = dns_socket
        .listen(1024)
        .map_err(|e| miette::miette!("Failed to listen on DNS socket: {e}"))?;

    server.register_listener(dns_listener, Duration::from_secs(5));

    if let Some((dot_listener, doq_socket, cert_resolver)) = tls_config {
        server
            .register_tls_listener(dot_listener, Duration::from_secs(5), cert_resolver.clone())
            .map_err(|e| miette::miette!("Failed to register DoT listener: {e}"))?;

        server
            .register_quic_listener(doq_socket, Duration::from_secs(1), cert_resolver, None)
            .map_err(|e| miette::miette!("Failed to register DoQ listener: {e}"))?;

        info!("DNS over TLS (DoT) and DNS over QUIC (DoQ) enabled on port 853");
    }

    let geolite_path = config.dns.geolite_path.clone();
    let geolite_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(21 * 24 * 60 * 60));
        interval.tick().await;

        loop {
            interval.tick().await;
            info!("Redownloading GeoLite database (scheduled update)");
            if let Err(e) = download_geolite(&geolite_path).await {
                error!("Failed to redownload GeoLite database: {e}");
            }
        }
    });

    info!("DNS server started");

    tokio::select! {
        result = server.block_until_done() => {
            result.map_err(|e| miette::miette!("DNS server error: {e}"))?;
        }
        _ = shutdown_rx.recv() => {
            info!("DNS server received shutdown signal");
        }
        _ = geolite_task => {
            error!("Geolite task received shutdown signal");
        }
    }

    Ok(())
}
