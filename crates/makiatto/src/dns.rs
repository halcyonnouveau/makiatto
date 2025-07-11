use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use camino::Utf8PathBuf;
use corro_agent::{
    deadpool_sqlite::{self, Pool},
    rusqlite,
};
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
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::Mutex,
};
use tracing::{error, info};
use url::Url;

use crate::config::Config;

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
pub struct Peer {
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
    reader: Reader<Vec<u8>>,
    db_pool: Pool,
}

impl Handler {
    #[must_use]
    pub fn new(reader: Reader<Vec<u8>>, db_pool: Pool) -> Self {
        Self { reader, db_pool }
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

    async fn get_peers(&self) -> Result<Vec<Peer>> {
        let conn = self
            .db_pool
            .get()
            .await
            .map_err(|e| miette::miette!("Failed to get database connection: {}", e))?;

        let peers = conn
            .interact(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT latitude, longitude, ipv4, ipv6 FROM peers WHERE is_active = 1",
                )?;
                let peer_iter = stmt.query_map([], |row| {
                    let latitude: f64 = row.get(0)?;
                    let longitude: f64 = row.get(1)?;
                    let ipv4: String = row.get(2)?;
                    let ipv6: Option<String> = row.get(3)?;

                    Ok(Peer {
                        point: point!(x: latitude, y: longitude),
                        ipv4,
                        ipv6,
                    })
                })?;

                let mut peers = Vec::new();
                for peer in peer_iter {
                    peers.push(peer?);
                }
                Ok::<Vec<Peer>, rusqlite::Error>(peers)
            })
            .await
            .map_err(|e| miette::miette!("Database interaction failed: {}", e))?
            .map_err(|e| miette::miette!("Failed to query peers: {}", e))?;

        Ok(peers)
    }

    async fn get_records(&self, name: &str) -> Result<Vec<DnsRecord>> {
        let name = name.to_string();

        let conn = self
            .db_pool
            .get()
            .await
            .map_err(|e| miette::miette!("Failed to get database connection: {}", e))?;

        let records = conn
            .interact(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT dr.record_type, dr.default_value, dr.ttl, dr.priority, dr.geo_enabled
                     FROM dns_records dr
                     JOIN domains d ON dr.domain_id = d.id
                     WHERE dr.name = ?1 OR (dr.name = '' AND d.name = ?2)",
                )?;

                let record_iter = stmt.query_map([&name, &name], |row| {
                    let record_type: String = row.get(0)?;
                    let default_value: String = row.get(1)?;
                    let ttl: u32 = row.get(2)?;
                    let priority: Option<i32> = row.get(3)?;
                    let geo_enabled: bool = row.get::<_, i32>(4)? == 1;

                    Ok(DnsRecord {
                        record_type,
                        default_value,
                        ttl,
                        priority,
                        geo_enabled,
                    })
                })?;

                let mut records = Vec::new();
                for record in record_iter {
                    records.push(record?);
                }
                Ok::<Vec<DnsRecord>, rusqlite::Error>(records)
            })
            .await
            .map_err(|e| miette::miette!("Database interaction failed: {}", e))?
            .map_err(|e| miette::miette!("Failed to query DNS records: {}", e))?;

        Ok(records)
    }

    async fn build_records(&self, request: DnsRequest) -> Result<Vec<Record>> {
        // make sure the request is a query
        if request.op_code != OpCode::Query {
            return Err(Error::InvalidOpCode(request.op_code).into());
        }

        // make sure the message type is a query
        if request.message_type != MessageType::Query {
            return Err(Error::InvalidMessageType(request.message_type).into());
        }

        let request_ip = request.ip;

        let lookup = self.reader.lookup::<maxminddb::geoip2::City>(request_ip);

        // get coordinates of request
        let coords = match lookup {
            Ok(response) => match response.unwrap().location {
                Some(location) => point!(
                    x: location.latitude.unwrap_or(0.0),
                    y: location.longitude.unwrap_or(0.0),
                ),
                None => point!(x: 0.0, y: 0.0),
            },
            Err(_) => point!(x: 0.0, y: 0.0),
        };

        let peers = self.get_peers().await?;
        let records = self.get_records(&request.name.to_string()).await?;

        if peers.is_empty() || records.is_empty() {
            return Ok(vec![]);
        }

        let closest_peer = peers
            .iter()
            .min_by(|&a, &b| {
                let dist_a = Haversine.distance(coords, a.point);
                let dist_b = Haversine.distance(coords, b.point);
                dist_a
                    .partial_cmp(&dist_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap();

        Ok(records
            .iter()
            .map(|record| {
                if !record.geo_enabled {
                    return Self::generate_record(
                        &request.name,
                        &record.record_type,
                        &record.default_value,
                        record.ttl,
                        record.priority,
                    );
                }

                let value = match record.record_type.as_str() {
                    "A" => &closest_peer.ipv4,
                    "AAAA" => &closest_peer
                        .clone()
                        .ipv6
                        .unwrap_or(record.default_value.clone()),
                    _ => &record.default_value,
                };

                Self::generate_record(
                    &request.name,
                    &record.record_type,
                    value,
                    record.ttl,
                    record.priority,
                )
            })
            .collect())
    }
}

#[derive(Debug)]
struct DnsRecord {
    record_type: String,
    default_value: String,
    ttl: u32,
    priority: Option<i32>,
    geo_enabled: bool,
}

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

        let records = match self.build_records(dns_request).await {
            Ok(res) => res,
            Err(e) => {
                error!("Failed to build DNS records: {}", e);
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
                error!("Failed to send DNS response: {}", e);
                Self::create_failure_response()
            }
        }
    }
}

/// Download `GeoLite2` database for geolocation
///
/// # Errors
/// Returns an error if the download fails or if the file cannot be written
pub fn download_geolite(path: &Utf8PathBuf) -> Result<()> {
    info!("Downloading GeoLite2 database...");

    let status = std::process::Command::new("curl")
        .arg("-L")
        .arg("-o")
        .arg(path.as_str())
        .arg("https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb")
        .status()
        .map_err(|e| miette::miette!("Failed to execute curl: {e}"))?;

    if !status.success() {
        return Err(miette::miette!("Failed to download GeoLite2 database"));
    }

    info!("GeoLite2 database downloaded successfully");
    Ok(())
}

/// Run the DNS server
///
/// # Errors
/// Returns an error if the server fails to start or bind to the configured address
pub async fn run_dns(config: Config, tripwire: tripwire::Tripwire) -> Result<()> {
    info!("Starting DNS server on {}", config.dns.addr);

    if !config.dns.geolite_path.exists() {
        download_geolite(&config.dns.geolite_path)?;
    }

    let reader = Reader::open_readfile(&*config.dns.geolite_path).into_diagnostic()?;

    let pool = deadpool_sqlite::Config::new(&config.corrosion.db.path)
        .create_pool(deadpool_sqlite::Runtime::Tokio1)
        .map_err(|e| miette::miette!("Failed to create database pool: {}", e))?;

    let handler = Handler::new(reader, pool);
    let mut server = ServerFuture::new(handler);

    server.register_socket(
        UdpSocket::bind(&*config.dns.addr)
            .await
            .map_err(|e| miette::miette!("Failed to bind UDP socket: {}", e))?,
    );
    server.register_listener(
        TcpListener::bind(&*config.dns.addr)
            .await
            .map_err(|e| miette::miette!("Failed to bind TCP socket: {}", e))?,
        Duration::from_secs(5),
    );

    // TODO: Add TLS/QUIC support when we have certificates
    // This will require integrating with the certificate management system

    let server = Arc::new(Mutex::new(server));
    let server_clone = Arc::clone(&server);

    tokio::spawn(async move {
        tripwire.await;
        info!("Shutting down DNS server");
        let mut server = server_clone.lock().await;
        let _ = server.shutdown_gracefully().await;
        info!("DNS server stopped");
    });

    let mut server = server.lock().await;
    server
        .block_until_done()
        .await
        .map_err(|e| miette::miette!("DNS server error: {}", e))?;

    Ok(())
}
