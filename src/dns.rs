use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};

use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::tcp::TcpClientStream;
use hickory_resolver::net::udp::UdpClientStream;
use hickory_resolver::net::xfer::{DnsHandle, FirstAnswer};
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::dnssec::{DnssecSummary, PublicKey, rdata::DNSSECRData};
use hickory_resolver::proto::op::{
    DnsRequest, DnsRequestOptions, DnsResponse, Edns, OpCode, Query, ResponseCode,
};
use hickory_resolver::proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::{Resolver, ResolverBuilder};
use ipnet::IpNet;
use mlua::{Error, Lua, Table, Value};

/// Per exchange. A silent server fails the query instead of being retried.
const DIRECT_TIMEOUT: Duration = Duration::from_secs(5);

pub fn install(lua: &Lua) -> mlua::Result<()> {
    let dns = lua.create_table()?;
    dns.set("query", lua.create_async_function(query)?)?;
    dns.set(
        "normalize_name",
        lua.create_function(|_, value: String| {
            let mut name = Name::from_str(&value)
                .map_err(Error::external)?
                .to_lowercase();
            name.set_fqdn(true);
            Ok(name.to_utf8())
        })?,
    )?;
    dns.set(
        "reverse_name",
        lua.create_function(|_, value: String| {
            let address = value.parse::<IpAddr>().map_err(Error::external)?;
            Ok(Name::from(address).to_utf8())
        })?,
    )?;
    for (name, ipv4) in [("is_ipv4", true), ("is_ipv6", false)] {
        dns.set(
            name,
            lua.create_function(move |_, value: Value| {
                let Value::String(value) = value else {
                    return Ok(false);
                };

                Ok(value
                    .to_str()
                    .ok()
                    .and_then(|value| value.parse::<IpAddr>().ok())
                    .is_some_and(|address| address.is_ipv4() == ipv4))
            })?,
        )?;
    }

    lua.globals().set("dns", dns)
}

async fn query(
    lua: Lua,
    (host, kind, validate, server, ecs): (
        String,
        Option<String>,
        bool,
        Option<String>,
        Option<String>,
    ),
) -> mlua::Result<Table> {
    let kind = kind.unwrap_or_else(|| "A".into()).to_ascii_uppercase();
    let record_type = RecordType::from_str(&kind).map_err(Error::external)?;
    let mut name = Name::from_str(&host).map_err(Error::external)?;
    name.set_fqdn(true);
    let server = server.as_deref().map(parse_server).transpose()?;
    let ecs = ecs.as_deref().map(parse_ecs).transpose()?;

    let started;
    let mut direct = None;
    let result = match server {
        Some(address) => {
            started = Instant::now();
            direct_query(address, &name, record_type, ecs)
                .await
                .map(|response| {
                    let result = (response.response_code, response.answers.clone());
                    direct = Some(response);
                    result
                })
        }
        None => {
            let mut builder = system_resolver()?;
            builder.options_mut().validate = validate;
            builder.options_mut().preserve_intermediates = true;
            builder.options_mut().use_hosts_file = ResolveHosts::Never;
            let resolver = builder.build().map_err(Error::external)?;
            started = Instant::now();
            resolver
                .lookup(name.clone(), record_type)
                .await
                .map(|lookup| (lookup.message().response_code, lookup.answers().to_vec()))
        }
    };
    let (code, answers) = match result {
        Ok(result) => result,
        Err(NetError::Dns(DnsError::NoRecordsFound(info))) => (info.response_code, vec![]),
        Err(NetError::Dns(DnsError::ResponseCode(code))) => (code, vec![]),
        Err(error) => {
            let via = server
                .map(|address| format!(" via {address}"))
                .unwrap_or_default();
            return Err(Error::runtime(format!(
                "{kind} query for {host}{via}: {error}"
            )));
        }
    };
    let code = rcode_name(code);
    let response = lua.create_table()?;
    response.set("name", name.to_utf8())?;
    response.set("type", kind)?;
    response.set("rcode", code)?;
    response.set("server", server.map(|address| address.to_string()))?;
    response.set("validation_enabled", validate)?;
    response.set(
        "answers_secure",
        validate
            && matches!(
                DnssecSummary::from_records(answers.iter()),
                DnssecSummary::Secure
            ),
    )?;
    response.set("duration_ms", started.elapsed().as_secs_f64() * 1000.0)?;
    response.set("answers", records(&lua, &answers)?)?;
    if let Some(message) = &direct {
        direct_fields(&lua, &response, message)?;
    }

    Ok(response)
}

fn rcode_name(code: ResponseCode) -> String {
    let name = match code {
        ResponseCode::NoError => "NOERROR",
        ResponseCode::FormErr => "FORMERR",
        ResponseCode::ServFail => "SERVFAIL",
        ResponseCode::NXDomain => "NXDOMAIN",
        ResponseCode::NotImp => "NOTIMP",
        ResponseCode::Refused => "REFUSED",
        ResponseCode::YXDomain => "YXDOMAIN",
        ResponseCode::YXRRSet => "YXRRSET",
        ResponseCode::NXRRSet => "NXRRSET",
        ResponseCode::NotAuth => "NOTAUTH",
        ResponseCode::NotZone => "NOTZONE",
        ResponseCode::BADVERS => "BADVERS",
        ResponseCode::BADSIG => "BADSIG",
        ResponseCode::BADKEY => "BADKEY",
        ResponseCode::BADTIME => "BADTIME",
        ResponseCode::BADMODE => "BADMODE",
        ResponseCode::BADNAME => "BADNAME",
        ResponseCode::BADALG => "BADALG",
        ResponseCode::BADTRUNC => "BADTRUNC",
        ResponseCode::BADCOOKIE => "BADCOOKIE",
        code => return format!("RCODE{}", u16::from(code)),
    };

    name.to_owned()
}

fn record_table(lua: &Lua, record: &Record) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    table.set("name", record.name.to_utf8())?;
    table.set("type", record.record_type().to_string())?;
    table.set("ttl", record.ttl)?;
    table.set("data", record.data.to_string())?;
    table.set("proof", record.proof.to_string().to_ascii_lowercase())?;

    match &record.data {
        RData::A(value) => table.set("address", value.to_string())?,
        RData::AAAA(value) => table.set("address", value.to_string())?,
        RData::CNAME(value) => table.set("target", value.0.to_utf8())?,
        RData::NS(value) => table.set("target", value.0.to_utf8())?,
        RData::PTR(value) => table.set("target", value.0.to_utf8())?,
        RData::MX(value) => {
            table.set("preference", value.preference)?;
            table.set("exchange", value.exchange.to_utf8())?;
        }
        RData::TXT(value) => {
            let chunks = value
                .txt_data
                .iter()
                .map(|chunk| lua.create_string(chunk))
                .collect::<mlua::Result<Vec<_>>>()?;
            table.set("text", lua.create_string(value.txt_data.concat())?)?;
            table.set("chunks", lua.create_sequence_from(chunks)?)?;
        }
        RData::SRV(value) => {
            table.set("priority", value.priority)?;
            table.set("weight", value.weight)?;
            table.set("port", value.port)?;
            table.set("target", value.target.to_utf8())?;
        }
        RData::DNSSEC(value) => dnssec_fields(&table, value)?,
        _ => {}
    }

    Ok(table)
}

fn dnssec_fields(table: &Table, data: &DNSSECRData) -> mlua::Result<()> {
    match data {
        DNSSECRData::DS(value) => {
            table.set("key_tag", value.key_tag())?;
            table.set("algorithm", u8::from(value.algorithm()))?;
            table.set("digest_type", u8::from(value.digest_type()))?;
            table.set("digest", data_encoding::HEXUPPER.encode(value.digest()))?;
        }
        DNSSECRData::DNSKEY(value) => {
            table.set("flags", value.flags())?;
            table.set(
                "key_tag",
                value.calculate_key_tag().map_err(Error::external)?,
            )?;
            table.set("algorithm", u8::from(value.public_key().algorithm()))?;
            table.set(
                "public_key",
                data_encoding::BASE64.encode(value.public_key().public_bytes()),
            )?;
        }
        DNSSECRData::RRSIG(value) => {
            let input = value.input();
            table.set("type_covered", input.type_covered.to_string())?;
            table.set("algorithm", u8::from(input.algorithm))?;
            table.set("labels", input.num_labels)?;
            table.set("original_ttl", input.original_ttl)?;
            table.set("expiration", input.sig_expiration.get())?;
            table.set("inception", input.sig_inception.get())?;
            table.set("key_tag", input.key_tag)?;
            table.set("signer_name", input.signer_name.to_utf8())?;
            table.set("signature", data_encoding::BASE64.encode(value.sig()))?;
        }
        _ => {}
    }

    Ok(())
}

/// Accepts `ip`, `ip:port`, or `[ipv6]:port`. Port defaults to 53.
fn parse_server(server: &str) -> mlua::Result<SocketAddr> {
    let address = server
        .parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, 53))
        .or_else(|_| server.parse::<SocketAddr>())
        .ok()
        // Scope IDs are host-specific interface numbers, which shared test files should not hold.
        .filter(|address| {
            let ip = address.ip();
            address.port() != 0
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !matches!(address, SocketAddr::V6(v6) if v6.scope_id() != 0)
        });

    address.ok_or_else(|| {
        Error::external(format!(
            "invalid server {server:?}: expected an IP address with an optional nonzero port"
        ))
    })
}

/// Accepts `address/prefix`. Bits past the prefix are cleared, as RFC 7871 requires.
fn parse_ecs(value: &str) -> mlua::Result<ClientSubnet> {
    let subnet = value.parse::<IpNet>().map_err(|_| {
        Error::external(format!(
            "invalid ecs {value:?}: expected an address and prefix such as 192.0.2.0/24"
        ))
    })?;

    Ok(ClientSubnet::from(subnet.trunc()))
}

/// Sends one query over UDP, then TCP if truncated, and returns the server's reply as is.
/// The resolver would retry error rcodes, answer RFC 6761 names locally, and chase CNAME
/// targets at the same server, which an authoritative server refuses when out of zone.
async fn direct_query(
    address: SocketAddr,
    name: &Name,
    record_type: RecordType,
    ecs: Option<ClientSubnet>,
) -> Result<DnsResponse, NetError> {
    let response = exchange(address, name, record_type, ecs, false).await?;
    if !response.metadata.truncation {
        return Ok(response);
    }

    let response = exchange(address, name, record_type, ecs, true)
        .await
        .map_err(|error| {
            NetError::from(format!("TCP fallback after a truncated reply: {error}"))
        })?;
    if response.metadata.truncation {
        return Err("truncated response over TCP".into());
    }

    Ok(response)
}

async fn exchange(
    address: SocketAddr,
    name: &Name,
    record_type: RecordType,
    ecs: Option<ClientSubnet>,
    tcp: bool,
) -> Result<DnsResponse, NetError> {
    // Keep the provider alive while its TCP background task handles the response.
    let provider = TokioRuntimeProvider::default();
    let exchange = if tcp {
        TcpClientStream::exchange(address, None, DIRECT_TIMEOUT, None, provider.clone()).await?
    } else {
        UdpClientStream::builder(address, provider)
            .with_timeout(Some(DIRECT_TIMEOUT))
            .with_max_retries(0)
            .exchange()
    };

    let question = Query::query(name.clone(), record_type);
    let mut request = DnsRequest::from_query(question.clone(), DnsRequestOptions::default());
    if let Some(subnet) = ecs {
        request
            .edns
            .get_or_insert_with(Edns::new)
            .options_mut()
            .insert(EdnsOption::Subnet(subnet));
    }

    let response = exchange.send(request).first_answer().await?;
    if response.metadata.op_code != OpCode::Query {
        return Err("response opcode does not match the query".into());
    }

    // The TCP multiplexer matches replies by ID alone.
    if response.queries.as_slice() != std::slice::from_ref(&question) {
        return Err("response question does not match the query".into());
    }

    Ok(response)
}

fn records(lua: &Lua, records: &[Record]) -> mlua::Result<Table> {
    lua.create_sequence_from(
        records
            .iter()
            .map(|record| record_table(lua, record))
            .collect::<mlua::Result<Vec<_>>>()?,
    )
}

/// Adds the header flag, authority section, and echoed ECS that only a direct query keeps.
fn direct_fields(lua: &Lua, table: &Table, response: &DnsResponse) -> mlua::Result<()> {
    table.set("authoritative", response.metadata.authoritative)?;
    table.set("authorities", records(lua, &response.authorities)?)?;

    let subnet = response
        .edns
        .as_ref()
        .and_then(|edns| edns.option(EdnsCode::Subnet));
    if let Some(EdnsOption::Subnet(subnet)) = subnet {
        let ecs = lua.create_table()?;
        ecs.set("address", subnet.addr().to_string())?;
        ecs.set("source_prefix", subnet.source_prefix())?;
        ecs.set("scope_prefix", subnet.scope_prefix())?;
        table.set("ecs", ecs)?;
    }

    Ok(())
}

/// System nameservers and retry options, read once so every query sees the same configuration.
#[cfg(all(unix, not(target_os = "android")))]
struct SystemConfig {
    servers: Vec<IpAddr>,
    timeout: std::time::Duration,
    attempts: usize,
}

/// Reads resolv.conf directly because hickory's macOS reader rejects scoped IPv6
/// servers such as `fe80::1%en0`, and its unix reader drops their zone.
#[cfg(all(unix, not(target_os = "android")))]
fn system_resolver() -> mlua::Result<ResolverBuilder<TokioRuntimeProvider>> {
    use std::sync::OnceLock;

    static CONFIG: OnceLock<Result<SystemConfig, String>> = OnceLock::new();
    let config = CONFIG
        .get_or_init(read_system_config)
        .as_ref()
        .map_err(Error::runtime)?;

    let servers = config
        .servers
        .iter()
        .map(|&ip| NameServerConfig::udp_and_tcp(ip))
        .collect();
    let mut builder = Resolver::builder_with_config(
        ResolverConfig::from_parts(None, vec![], servers),
        TokioRuntimeProvider::default(),
    );
    builder.options_mut().timeout = config.timeout;
    builder.options_mut().attempts = config.attempts;

    Ok(builder)
}

#[cfg(all(unix, not(target_os = "android")))]
fn read_system_config() -> Result<SystemConfig, String> {
    use resolv_conf::ScopedIp;

    const PATH: &str = "/etc/resolv.conf";
    let data = std::fs::read(PATH).map_err(|error| format!("reading {PATH}: {error}"))?;
    let (config, _) = resolv_conf::Config::parse_with_errors(&data);

    // Hickory cannot address a server on a specific interface, so skip zoned servers
    // instead of failing the whole configuration.
    let configured = config.nameservers.len();
    let servers: Vec<_> = config
        .nameservers
        .into_iter()
        .filter_map(|server| match server {
            ScopedIp::V6(_, Some(_)) => None,
            ip => Some(IpAddr::from(ip)),
        })
        .collect();

    if servers.is_empty() {
        let reason = if configured == 0 {
            ""
        } else {
            ". Link-local servers with an interface zone are not supported"
        };
        return Err(format!("no usable nameservers found in {PATH}{reason}"));
    }

    Ok(SystemConfig {
        servers,
        timeout: std::time::Duration::from_secs(config.timeout.into()),
        attempts: config.attempts as usize,
    })
}

#[cfg(not(all(unix, not(target_os = "android"))))]
fn system_resolver() -> mlua::Result<ResolverBuilder<TokioRuntimeProvider>> {
    Resolver::builder_tokio().map_err(Error::external)
}
