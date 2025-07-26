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
use tokio::net::{TcpListener, UdpSocket};
use tracing::{error, info};
use url::Url;

use crate::{
    config::Config,
    corrosion::{self, DnsRecord},
    service::{BasicServiceCommand, ServiceManager},
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
    ipv4: String,
    ipv6: Option<String>,
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
        let lookup = self.reader.lookup::<maxminddb::geoip2::City>(request.ip);
        let coords = match lookup {
            Ok(Some(response)) => match response.location {
                Some(location) => point!(
                    x: location.latitude.unwrap_or(0.0),
                    y: location.longitude.unwrap_or(0.0),
                ),
                None => point!(x: 0.0, y: 0.0),
            },
            Ok(None) | Err(_) => point!(x: 0.0, y: 0.0),
        };

        let lookup_name = request.name.to_string().trim_end_matches('.').to_string();
        let records = self.records.get(&lookup_name).cloned().unwrap_or_default();

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
                        &record.base_value,
                        record.ttl,
                        record.priority,
                    ));
                }

                let peer = closest_peer?;

                if record.record_type == "AAAA" && peer.ipv6.is_none() {
                    return None;
                }

                let value = match record.record_type.as_str() {
                    "A" => &peer.ipv4,
                    "AAAA" => peer.ipv6.as_ref().unwrap(),
                    _ => &record.base_value,
                };

                Some(Self::generate_record(
                    &request.name,
                    &record.record_type,
                    value,
                    record.ttl,
                    record.priority,
                ))
            })
            .collect())
    }
}

pub type DnsManager = ServiceManager<BasicServiceCommand>;

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut handler: R,
    ) -> ResponseInfo {
        let dns_request = DnsRequest {
            op_code: request.op_code(),
            message_type: request.message_type(),
            ip: request.src().ip(),
            name: request.queries().first().unwrap().name().clone(),
        };

        let records = match self.build_records(&dns_request) {
            Ok(res) => res,
            Err(e) => {
                error!("Failed to build DNS records: {e}");
                return Self::create_failure_response();
            }
        };

        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let response = builder.build(header, records.iter(), &[], &[], &[]);

        match handler.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                error!("Failed to send DNS response: {e}");
                Self::create_failure_response()
            }
        }
    }
}

pub(crate) async fn download_geolite(path: &Utf8PathBuf) -> Result<()> {
    info!("Downloading GeoLite2 database...");
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
pub async fn start(config: Arc<Config>, tripwire: tripwire::Tripwire) -> Result<()> {
    if !config.dns.geolite_path.exists() {
        download_geolite(&config.dns.geolite_path).await?;
    }

    let peers: Vec<DnsPeer> = corrosion::get_peers(&config)
        .unwrap_or_else(|_| Arc::from([]))
        .iter()
        .map(|p| DnsPeer {
            point: point!(x: p.latitude, y: p.longitude),
            ipv4: p.ipv4.to_string(),
            ipv6: p.ipv6.as_ref().map(ToString::to_string),
        })
        .collect();

    let records = corrosion::get_dns_records(&config).unwrap_or_default();
    let reader = Reader::open_readfile(&*config.dns.geolite_path).into_diagnostic()?;
    let handler = Handler::new(Arc::from(peers), records, reader);
    let mut server = ServerFuture::new(handler);

    server.register_socket(
        UdpSocket::bind("[::]:53")
            .await
            .map_err(|e| miette::miette!("Failed to bind UDP socket: {e}"))?,
    );

    server.register_listener(
        TcpListener::bind("[::]:53")
            .await
            .map_err(|e| miette::miette!("Failed to bind TCP socket: {e}"))?,
        Duration::from_secs(5),
    );

    // TODO: Add TLS/QUIC support when we have certificates
    // This will require integrating with the certificate management system
    //
    // if Path::new(PRIV_PATH).exists() && Path::new(CERT_PATH).exists() {
    //     let key = tls_server::read_key_from_pem(Path::new(PRIV_PATH))?;
    //     let cert = tls_server::read_cert(Path::new(CERT_PATH))?;

    //     server.register_quic_listener(
    //         UdpSocket::bind("[::]:853").await?,
    //         Duration::from_secs(1),
    //         (cert.clone(), key.clone()),
    //         None,
    //     )?;

    //     server.register_tls_listener_with_tls_config(
    //         TcpListener::bind("[::]:853").await?,
    //         Duration::from_secs(5),
    //         Arc::new(tls_server::new_acceptor(cert, key)?),
    //     )?;
    // }

    info!("DNS server started");

    tokio::select! {
        result = server.block_until_done() => {
            result.map_err(|e| miette::miette!("DNS server error: {e}"))?;
        }
        () = tripwire => {
            info!("DNS server received shutdown signal");
        }
    }

    Ok(())
}
