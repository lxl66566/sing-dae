use std::{collections::HashMap, fmt};

use crate::{
    error::{AppError, Result},
    singbox::config::{Outbound, TlsConfig},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Shadowsocks,
    Vmess,
    Vless,
    Trojan,
    Hysteria2,
    Tuic,
    AnyTLS,
}

impl Protocol {
    pub fn from_scheme(scheme: &str) -> Option<Self> {
        match scheme {
            "ss" | "shadowsocks" => Some(Self::Shadowsocks),
            "vmess" => Some(Self::Vmess),
            "vless" => Some(Self::Vless),
            "trojan" | "trojan-go" => Some(Self::Trojan),
            "hy2" | "hysteria2" => Some(Self::Hysteria2),
            "tuic" => Some(Self::Tuic),
            "anytls" => Some(Self::AnyTLS),
            _ => None,
        }
    }

    pub fn from_sing_type(t: &str) -> Option<Self> {
        match t {
            "shadowsocks" => Some(Self::Shadowsocks),
            "vmess" => Some(Self::Vmess),
            "vless" => Some(Self::Vless),
            "trojan" => Some(Self::Trojan),
            "hysteria2" => Some(Self::Hysteria2),
            "tuic" => Some(Self::Tuic),
            "anytls" => Some(Self::AnyTLS),
            _ => None,
        }
    }

    pub fn sing_type(self) -> &'static str {
        match self {
            Self::Shadowsocks => "shadowsocks",
            Self::Vmess => "vmess",
            Self::Vless => "vless",
            Self::Trojan => "trojan",
            Self::Hysteria2 => "hysteria2",
            Self::Tuic => "tuic",
            Self::AnyTLS => "anytls",
        }
    }

    pub fn dae_scheme(self) -> &'static str {
        match self {
            Self::Shadowsocks => "ss",
            Self::Vmess => "vmess",
            Self::Vless => "vless",
            Self::Trojan => "trojan",
            Self::Hysteria2 => "hy2",
            Self::Tuic => "tuic",
            Self::AnyTLS => "anytls",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.sing_type())
    }
}

pub fn is_proxy_type(t: &str) -> bool {
    Protocol::from_sing_type(t).is_some()
}

pub fn parse_node_link(tag: &str, link: &str) -> Result<Outbound> {
    let (scheme, rest) = link
        .split_once("://")
        .ok_or_else(|| AppError::Conversion(format!("invalid node link: {link}")))?;

    if rest.contains(" -> ") {
        return Err(AppError::Conversion(format!(
            "chain nodes not supported: {link}"
        )));
    }

    let protocol = Protocol::from_scheme(scheme)
        .ok_or_else(|| AppError::Conversion(format!("unsupported protocol: {scheme}")))?;

    if protocol == Protocol::Vmess {
        return parse_vmess_link(tag, rest);
    }

    let main_part = match rest.rfind('#') {
        Some(idx) => &rest[..idx],
        None => rest,
    };

    let (authority, query) = match main_part.find('?') {
        Some(idx) => (&main_part[..idx], Some(&main_part[idx + 1..])),
        None => (main_part, None),
    };

    let at_pos = authority.rfind('@');
    let (credential, host_port) = match at_pos {
        Some(pos) => (&authority[..pos], &authority[pos + 1..]),
        None => ("", authority),
    };

    let colon_pos = host_port.rfind(':');
    let (host, port) = match colon_pos {
        Some(pos) => (
            host_port[..pos].to_string(),
            host_port[pos + 1..]
                .trim_end_matches('/')
                .parse::<u16>()
                .ok(),
        ),
        None => (host_port.to_string(), None),
    };

    let params = parse_query_params(query.unwrap_or(""));
    let sni = params.get("sni").or(params.get("peer")).cloned();
    let insecure = params
        .get("insecure")
        .or(params.get("allowInsecure"))
        .or(params.get("allow_insecure"))
        .or(params.get("skipVerify"))
        .and_then(|v| matches!(v.as_str(), "1" | "true").then_some(true));

    let tls = build_tls(protocol, sni, insecure, &params);
    let base = OutboundBase {
        tag,
        protocol,
        server: &host,
        port,
    };

    match protocol {
        Protocol::Shadowsocks => build_shadowsocks(base, credential, tls),
        Protocol::Vless => build_vless(base, credential, &params, tls),
        Protocol::Trojan => build_trojan(base, credential, tls),
        Protocol::Hysteria2 => build_hysteria2(base, credential, &params, tls),
        Protocol::Tuic => build_tuic(base, credential, &params, tls),
        Protocol::AnyTLS => build_anytls(base, credential, tls),
        Protocol::Vmess => unreachable!(),
    }
}

struct OutboundBase<'a> {
    tag: &'a str,
    protocol: Protocol,
    server: &'a str,
    port: Option<u16>,
}

impl OutboundBase<'_> {
    fn into_outbound(self, f: impl FnOnce(&mut Outbound)) -> Outbound {
        let mut ob = Outbound {
            outbound_type: self.protocol.sing_type().to_string(),
            tag: Some(self.tag.to_string()),
            server: Some(self.server.to_string()),
            server_port: self.port,
            ..Default::default()
        };
        f(&mut ob);
        ob
    }
}

fn build_tls(
    protocol: Protocol,
    sni: Option<String>,
    insecure: Option<bool>,
    params: &HashMap<String, String>,
) -> Option<TlsConfig> {
    let always_tls = matches!(
        protocol,
        Protocol::Trojan
            | Protocol::Hysteria2
            | Protocol::Tuic
            | Protocol::AnyTLS
            | Protocol::Vless
    );
    if !always_tls && sni.is_none() && insecure.is_none_or(|v| !v) {
        return None;
    }

    let alpn = params
        .get("alpn")
        .map(|v| v.split(',').map(String::from).collect());

    Some(TlsConfig {
        enabled: Some(true),
        server_name: sni,
        insecure,
        alpn,
    })
}

fn build_shadowsocks(
    base: OutboundBase,
    credential: &str,
    tls: Option<TlsConfig>,
) -> Result<Outbound> {
    let (method, password) = decode_ss_credential(credential);
    Ok(base.into_outbound(|ob| {
        ob.password = Some(password);
        ob.method = Some(method);
        ob.tls = tls;
    }))
}

fn build_vless(
    base: OutboundBase,
    credential: &str,
    params: &HashMap<String, String>,
    tls: Option<TlsConfig>,
) -> Result<Outbound> {
    Ok(base.into_outbound(|ob| {
        ob.uuid = Some(credential.to_string());
        ob.flow = params.get("flow").cloned();
        ob.security = params.get("security").cloned();
        ob.tls = tls;
    }))
}

fn build_trojan(base: OutboundBase, credential: &str, tls: Option<TlsConfig>) -> Result<Outbound> {
    Ok(base.into_outbound(|ob| {
        ob.password = Some(credential.to_string());
        ob.tls = tls;
    }))
}

fn build_hysteria2(
    base: OutboundBase,
    credential: &str,
    params: &HashMap<String, String>,
    tls: Option<TlsConfig>,
) -> Result<Outbound> {
    Ok(base.into_outbound(|ob| {
        ob.password = Some(credential.to_string());
        ob.up_mbps = params.get("up").and_then(|v| v.parse().ok());
        ob.down_mbps = params.get("down").and_then(|v| v.parse().ok());
        ob.obfs_type = params.get("obfs").cloned();
        ob.obfs_password = params.get("obfs-password").cloned();
        ob.tls = tls;
    }))
}

fn build_tuic(
    base: OutboundBase,
    credential: &str,
    params: &HashMap<String, String>,
    tls: Option<TlsConfig>,
) -> Result<Outbound> {
    let (uuid, password) = credential
        .split_once(':')
        .map(|(u, p)| (u.to_string(), p.to_string()))
        .unwrap_or((credential.to_string(), String::new()));

    Ok(base.into_outbound(|ob| {
        ob.uuid = Some(uuid);
        ob.password = Some(password);
        ob.congestion_control = params.get("congestion_control").cloned();
        ob.udp_relay_mode = params.get("udp_relay_mode").cloned();
        ob.tls = tls;
    }))
}

fn build_anytls(base: OutboundBase, credential: &str, tls: Option<TlsConfig>) -> Result<Outbound> {
    Ok(base.into_outbound(|ob| {
        ob.password = Some(credential.to_string());
        ob.tls = tls;
    }))
}

fn parse_vmess_link(tag: &str, rest: &str) -> Result<Outbound> {
    let raw = match rest.rfind('#') {
        Some(idx) => &rest[..idx],
        None => rest,
    };
    let json_bytes = base64_decode(raw.trim_end_matches('/'))
        .map_err(|_| AppError::Conversion("invalid vmess base64".into()))?;
    let json_str = String::from_utf8(json_bytes)
        .map_err(|_| AppError::Conversion("invalid vmess base64 encoding".into()))?;
    let vmess: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| AppError::Conversion(format!("invalid vmess json: {e}")))?;

    let server = vmess["add"].as_str().unwrap_or("").to_string();
    let port = vmess["port"]
        .as_str()
        .and_then(|p| p.parse::<u16>().ok())
        .or_else(|| vmess["port"].as_u64().and_then(|p| u16::try_from(p).ok()));
    let uuid = vmess["id"].as_str().unwrap_or("").to_string();
    let security = vmess["scy"].as_str().unwrap_or("auto").to_string();
    let sni = vmess["sni"]
        .as_str()
        .or_else(|| vmess["host"].as_str())
        .map(String::from);
    let tls_enabled = vmess["tls"].as_str().is_some_and(|t| t == "tls");

    let tls = if tls_enabled || sni.is_some() {
        Some(TlsConfig {
            enabled: Some(tls_enabled),
            server_name: sni,
            insecure: None,
            alpn: None,
        })
    } else {
        None
    };

    Ok(Outbound {
        outbound_type: Protocol::Vmess.sing_type().to_string(),
        tag: Some(tag.to_string()),
        server: Some(server),
        server_port: port,
        uuid: Some(uuid),
        security: Some(security),
        tls,
        ..Default::default()
    })
}

pub fn build_node_link(ob: &Outbound) -> Result<String> {
    let protocol = Protocol::from_sing_type(&ob.outbound_type).ok_or_else(|| {
        AppError::Conversion(format!("unsupported outbound type: '{}'", ob.outbound_type))
    })?;

    let tag = ob.tag.as_deref().unwrap_or(&ob.outbound_type);
    let server = ob
        .server
        .as_deref()
        .ok_or_else(|| AppError::Conversion(format!("outbound '{tag}' missing server")))?;
    let port = resolve_port(ob, tag)?;
    let fragment = simple_percent_encode(tag);
    let sni = ob
        .tls
        .as_ref()
        .and_then(|t| t.server_name.clone())
        .unwrap_or_else(|| server.to_string());

    match protocol {
        Protocol::Shadowsocks => {
            let method = ob.method.as_deref().unwrap_or("aes-256-gcm");
            let password = ob.password.as_deref().unwrap_or("");
            let userinfo = base64_encode(format!("{method}:{password}").as_bytes());
            Ok(format!("ss://{userinfo}@{server}:{port}#{fragment}"))
        }
        Protocol::Vmess => {
            let uuid = ob.uuid.as_deref().unwrap_or("");
            let scy = ob.security.as_deref().unwrap_or("auto");
            let tls_enabled = ob.tls.as_ref().is_some_and(|t| t.enabled.unwrap_or(false));
            let tls_str = if tls_enabled { "tls" } else { "" };
            let json = format!(
                r#"{{"v":"2","ps":"{tag}","add":"{server}","port":"{port}",\
                "id":"{uuid}","aid":"0","net":"tcp","type":"none",\
                "host":"","path":"","scy":"{scy}","tls":"{tls_str}","sni":"{sni}"}}"#
            );
            Ok(format!("vmess://{}", base64_encode(json.as_bytes())))
        }
        Protocol::Vless => {
            let uuid = ob.uuid.as_deref().unwrap_or("");
            let security = ob.security.as_deref().unwrap_or("tls");
            let mut query = format!("type=tcp&security={security}&sni={sni}");
            if let Some(flow) = &ob.flow {
                query.push_str(&format!("&flow={flow}"));
            }
            Ok(format!(
                "vless://{uuid}@{server}:{port}/?{query}#{fragment}"
            ))
        }
        Protocol::Trojan => {
            let password = ob.password.as_deref().unwrap_or("");
            Ok(format!(
                "trojan://{password}@{server}:{port}/?type=tcp&security=tls&sni={sni}#{fragment}"
            ))
        }
        Protocol::Hysteria2 => {
            let password = ob.password.as_deref().unwrap_or("");
            let mut query = format!("sni={sni}");
            append_tls_insecure(&mut query, ob);
            if let Some(up) = &ob.up_mbps {
                query.push_str(&format!("&up={up}"));
            }
            if let Some(down) = &ob.down_mbps {
                query.push_str(&format!("&down={down}"));
            }
            if let Some(obfs) = &ob.obfs_type {
                query.push_str(&format!("&obfs={obfs}"));
            }
            if let Some(obfs_pwd) = &ob.obfs_password {
                query.push_str(&format!("&obfs-password={obfs_pwd}"));
            }
            Ok(format!(
                "hy2://{password}@{server}:{port}/?{query}#{fragment}"
            ))
        }
        Protocol::Tuic => {
            let uuid = ob.uuid.as_deref().unwrap_or("");
            let password = ob.password.as_deref().unwrap_or("");
            let mut query = format!("sni={sni}");
            if let Some(cc) = &ob.congestion_control {
                query.push_str(&format!("&congestion_control={cc}"));
            }
            if let Some(urm) = &ob.udp_relay_mode {
                query.push_str(&format!("&udp_relay_mode={urm}"));
            }
            if let Some(alpn) = ob.tls.as_ref().and_then(|t| t.alpn.as_ref())
                && !alpn.is_empty()
            {
                query.push_str(&format!("&alpn={}", alpn.join(",")));
            }
            Ok(format!(
                "tuic://{uuid}:{password}@{server}:{port}/?{query}#{fragment}"
            ))
        }
        Protocol::AnyTLS => {
            let password = ob.password.as_deref().unwrap_or("");
            let mut query = format!("sni={sni}");
            append_tls_insecure(&mut query, ob);
            Ok(format!(
                "anytls://{password}@{server}:{port}/?{query}#{fragment}"
            ))
        }
    }
}

fn append_tls_insecure(query: &mut String, ob: &Outbound) {
    if ob.tls.as_ref().is_some_and(|t| t.insecure.unwrap_or(false)) {
        query.push_str("&insecure=1");
    }
}

fn resolve_port(ob: &Outbound, tag: &str) -> Result<u16> {
    if let Some(port) = ob.server_port {
        return Ok(port);
    }
    if let Some(ports) = &ob.server_ports {
        let first_str = ports.first().ok_or_else(|| {
            AppError::Conversion(format!(
                "outbound '{tag}' has no server_port and empty server_ports"
            ))
        })?;
        let digits: String = first_str
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        digits.parse::<u16>().ok().ok_or_else(|| {
            AppError::Conversion(format!(
                "outbound '{tag}' has invalid server_ports '{ports:?}'"
            ))
        })
    } else {
        Err(AppError::Conversion(format!(
            "outbound '{tag}' missing server_port or server_ports"
        )))
    }
}

fn parse_query_params(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((key, value)) = pair.split_once('=') {
            params.insert(key.to_string(), value.to_string());
        }
    }
    params
}

fn decode_ss_credential(cred: &str) -> (String, String) {
    base64_decode(cred)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| {
            s.split_once(':')
                .map(|(m, p)| (m.to_string(), p.to_string()))
        })
        .unwrap_or_else(|| ("aes-256-gcm".to_string(), cred.to_string()))
}

const HEX_TABLE: &[u8; 16] = b"0123456789ABCDEF";

fn simple_percent_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push('%');
                result.push(HEX_TABLE[(byte >> 4) as usize] as char);
                result.push(HEX_TABLE[(byte & 0x0F) as usize] as char);
            }
        }
    }
    result
}

const BASE64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let triplet = (b0 << 16) | (b1 << 8) | b2;

        result.push(BASE64_TABLE[((triplet >> 18) & 0x3F) as usize] as char);
        result.push(BASE64_TABLE[((triplet >> 12) & 0x3F) as usize] as char);
        result.push(if chunk.len() > 1 {
            BASE64_TABLE[((triplet >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            BASE64_TABLE[(triplet & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    result
}

fn base64_decode(input: &str) -> std::result::Result<Vec<u8>, ()> {
    let input = input.trim_end_matches('=');
    if input.is_empty() {
        return Ok(vec![]);
    }

    let decode_table: [u8; 256] = {
        let mut table = [0xFFu8; 256];
        for (i, &b) in BASE64_TABLE.iter().enumerate() {
            table[b as usize] = i as u8;
        }
        table[b'-' as usize] = 62;
        table[b'_' as usize] = 63;
        table
    };

    let mut result = Vec::with_capacity(input.len() * 3 / 4);
    let bytes = input.as_bytes();
    let chunks = bytes.chunks(4);

    for chunk in chunks {
        let b0 = decode_table[*chunk.first().unwrap_or(&b'A') as usize] as u32;
        let b1 = decode_table[*chunk.get(1).unwrap_or(&b'A') as usize] as u32;
        let b2_val = *chunk.get(2).unwrap_or(&b'A');
        let b3_val = *chunk.get(3).unwrap_or(&b'A');
        let b2 = decode_table[b2_val as usize] as u32;
        let b3 = decode_table[b3_val as usize] as u32;

        let triplet = (b0 << 18) | (b1 << 12) | (b2 << 6) | b3;

        result.push(((triplet >> 16) & 0xFF) as u8);
        if chunk.len() > 2 && b2_val != b'=' {
            result.push(((triplet >> 8) & 0xFF) as u8);
        }
        if chunk.len() > 3 && b3_val != b'=' {
            result.push((triplet & 0xFF) as u8);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_base64() {
        let data = b"Hello, World!";
        assert_eq!(base64_decode(&base64_encode(data)).unwrap(), data);
    }

    #[test]
    fn roundtrip_base64_empty() {
        assert_eq!(base64_decode(&base64_encode(b"")).unwrap(), b"");
    }

    #[test]
    fn base64_decode_url_safe() {
        // Standard and URL-safe base64 should both work
        let standard = "aGVsbG8=";
        let url_safe = "aGVsbG8";
        assert_eq!(
            base64_decode(standard).unwrap(),
            base64_decode(url_safe).unwrap()
        );
    }

    #[test]
    fn protocol_roundtrip_schemes() {
        assert_eq!(
            Protocol::from_scheme("ss").unwrap().sing_type(),
            "shadowsocks"
        );
        assert_eq!(
            Protocol::from_scheme("hy2").unwrap().sing_type(),
            "hysteria2"
        );
        assert_eq!(Protocol::from_scheme("tuic").unwrap().sing_type(), "tuic");
        assert_eq!(
            Protocol::from_scheme("anytls").unwrap().sing_type(),
            "anytls"
        );
        assert!(Protocol::from_scheme("unknown").is_none());
    }

    #[test]
    fn parse_hy2_link() {
        let ob = parse_node_link(
            "my-hy",
            "hy2://pass123@1.2.3.4:443/?sni=example.com#display",
        )
        .unwrap();
        assert_eq!(ob.outbound_type, "hysteria2");
        assert_eq!(ob.tag.as_deref(), Some("my-hy"));
        assert_eq!(ob.server.as_deref(), Some("1.2.3.4"));
        assert_eq!(ob.server_port, Some(443));
        assert_eq!(ob.password.as_deref(), Some("pass123"));
        assert_eq!(
            ob.tls.as_ref().unwrap().server_name.as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn parse_trojan_link() {
        let ob = parse_node_link(
            "tr",
            "trojan://pw@host:8080/?type=tcp&security=tls&sni=host#name",
        )
        .unwrap();
        assert_eq!(ob.outbound_type, "trojan");
        assert_eq!(ob.password.as_deref(), Some("pw"));
        assert_eq!(ob.server_port, Some(8080));
    }

    #[test]
    fn parse_vless_link() {
        let ob = parse_node_link(
            "vl",
            "vless://uuid123@1.2.3.4:443/?type=tcp&security=tls&sni=example.com&flow=xtls-rprx-vision",
        )
        .unwrap();
        assert_eq!(ob.outbound_type, "vless");
        assert_eq!(ob.uuid.as_deref(), Some("uuid123"));
        assert_eq!(ob.flow.as_deref(), Some("xtls-rprx-vision"));
    }

    #[test]
    fn parse_ss_link() {
        let ob = parse_node_link(
            "ss-node",
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#ss-node",
        )
        .unwrap();
        assert_eq!(ob.outbound_type, "shadowsocks");
        assert_eq!(ob.method.as_deref(), Some("aes-256-gcm"));
        assert_eq!(ob.password.as_deref(), Some("password"));
    }

    #[test]
    fn parse_vmess_link() {
        let json = r#"{"v":"2","ps":"test","add":"1.2.3.4","port":"443","id":"uuid-1234","aid":"0","net":"tcp","type":"none","host":"","path":"","scy":"auto","tls":"tls","sni":"example.com"}"#;
        let encoded = base64_encode(json.as_bytes());
        let link = format!("vmess://{encoded}");
        let ob = parse_node_link("vm", &link).unwrap();
        assert_eq!(ob.outbound_type, "vmess");
        assert_eq!(ob.server.as_deref(), Some("1.2.3.4"));
        assert_eq!(ob.server_port, Some(443));
        assert_eq!(ob.uuid.as_deref(), Some("uuid-1234"));
        assert_eq!(ob.security.as_deref(), Some("auto"));
        assert!(ob.tls.as_ref().is_some());
    }

    #[test]
    fn parse_tuic_link() {
        let ob = parse_node_link(
            "tuic-node",
            "tuic://uuid-abc:password123@1.2.3.4:443/?congestion_control=bbr&udp_relay_mode=quic&sni=example.com&alpn=h3",
        )
        .unwrap();
        assert_eq!(ob.outbound_type, "tuic");
        assert_eq!(ob.uuid.as_deref(), Some("uuid-abc"));
        assert_eq!(ob.password.as_deref(), Some("password123"));
        assert_eq!(ob.congestion_control.as_deref(), Some("bbr"));
        assert_eq!(ob.udp_relay_mode.as_deref(), Some("quic"));
        assert_eq!(
            ob.tls.as_ref().unwrap().alpn.as_deref(),
            Some(["h3".to_string()].as_slice())
        );
    }

    #[test]
    fn parse_anytls_link() {
        let ob = parse_node_link(
            "at",
            "anytls://authcode@1.2.3.4:443/?sni=example.com&insecure=1",
        )
        .unwrap();
        assert_eq!(ob.outbound_type, "anytls");
        assert_eq!(ob.password.as_deref(), Some("authcode"));
        assert!(ob.tls.as_ref().unwrap().insecure.unwrap_or(false));
    }

    #[test]
    fn build_tuic_link() {
        let ob = Outbound {
            outbound_type: "tuic".into(),
            tag: Some("tuic-node".into()),
            server: Some("1.2.3.4".into()),
            server_port: Some(443),
            uuid: Some("uuid-abc".into()),
            password: Some("password123".into()),
            congestion_control: Some("bbr".into()),
            udp_relay_mode: Some("quic".into()),
            tls: Some(TlsConfig {
                enabled: Some(true),
                server_name: Some("example.com".into()),
                insecure: None,
                alpn: Some(vec!["h3".into()]),
            }),
            ..Default::default()
        };
        let link = build_node_link(&ob).unwrap();
        assert!(link.starts_with("tuic://uuid-abc:password123@1.2.3.4:443/"));
        assert!(link.contains("sni=example.com"));
        assert!(link.contains("congestion_control=bbr"));
        assert!(link.contains("udp_relay_mode=quic"));
        assert!(link.contains("alpn=h3"));
        assert!(link.ends_with("#tuic-node"));
    }

    #[test]
    fn build_anytls_link() {
        let ob = Outbound {
            outbound_type: "anytls".into(),
            tag: Some("at".into()),
            server: Some("1.2.3.4".into()),
            server_port: Some(443),
            password: Some("mypassword".into()),
            tls: Some(TlsConfig {
                enabled: Some(true),
                server_name: Some("example.com".into()),
                insecure: None,
                alpn: None,
            }),
            ..Default::default()
        };
        let link = build_node_link(&ob).unwrap();
        assert!(link.starts_with("anytls://mypassword@1.2.3.4:443/"));
        assert!(link.contains("sni=example.com"));
        assert!(link.ends_with("#at"));
    }

    #[test]
    fn hy2_link_with_obfs() {
        let ob = parse_node_link(
            "hy2-obfs",
            "hy2://pass@1.2.3.4:443/?sni=example.com&obfs=salamander&obfs-password=secret&up=100&down=200",
        )
        .unwrap();
        assert_eq!(ob.obfs_type.as_deref(), Some("salamander"));
        assert_eq!(ob.obfs_password.as_deref(), Some("secret"));
        assert_eq!(ob.up_mbps, Some(100));
        assert_eq!(ob.down_mbps, Some(200));

        let link = build_node_link(&ob).unwrap();
        assert!(link.contains("obfs=salamander"));
        assert!(link.contains("obfs-password=secret"));
        assert!(link.contains("up=100"));
        assert!(link.contains("down=200"));
    }
}
