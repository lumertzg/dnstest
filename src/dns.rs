use std::net::IpAddr;
use std::str::FromStr;
use std::time::Instant;

use hickory_resolver::Resolver;
use hickory_resolver::config::ResolveHosts;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::dnssec::{DnssecSummary, PublicKey, rdata::DNSSECRData};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use mlua::{Error, Lua, Table, Value};

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
    (host, kind, validate): (String, Option<String>, bool),
) -> mlua::Result<Table> {
    let kind = kind.unwrap_or_else(|| "A".into()).to_ascii_uppercase();
    let record_type = RecordType::from_str(&kind).map_err(Error::external)?;
    let mut name = Name::from_str(&host).map_err(Error::external)?;
    name.set_fqdn(true);

    let mut builder = Resolver::builder_tokio().map_err(Error::external)?;
    builder.options_mut().validate = validate;
    builder.options_mut().preserve_intermediates = false;
    builder.options_mut().use_hosts_file = ResolveHosts::Never;
    let resolver = builder.build().map_err(Error::external)?;
    let started = Instant::now();
    let (code, answers) = match resolver.lookup(name.clone(), record_type).await {
        Ok(lookup) => (lookup.message().response_code, lookup.answers().to_vec()),
        Err(NetError::Dns(DnsError::NoRecordsFound(info))) => (info.response_code, vec![]),
        Err(NetError::Dns(DnsError::ResponseCode(code))) => (code, vec![]),
        Err(error) => return Err(Error::runtime(format!("{kind} query for {host}: {error}"))),
    };
    let code = match code {
        ResponseCode::Unknown(value) => format!("RCODE{value}"),
        code => format!("{code:?}").to_ascii_uppercase(),
    };
    let response = lua.create_table()?;
    response.set("name", name.to_utf8())?;
    response.set("type", kind)?;
    response.set("rcode", code)?;
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
    response.set(
        "answers",
        lua.create_sequence_from(
            answers
                .iter()
                .map(|record| record_table(&lua, record))
                .collect::<mlua::Result<Vec<_>>>()?,
        )?,
    )?;

    Ok(response)
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
