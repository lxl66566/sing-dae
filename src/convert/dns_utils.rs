use crate::singbox::config::DnsServer;

pub const DNS_TYPES_WITH_PATH: &[&str] = &["https", "h3", "http3"];

pub const DNS_TYPES_VIRTUAL: &[&str] = &["local", "hosts", "fakeip"];

pub fn default_port(dns_type: &str) -> u16 {
    match dns_type {
        "https" | "h3" | "http3" => 443,
        "tls" | "quic" => 853,
        _ => 53,
    }
}

pub fn is_virtual_dns_type(dns_type: &str) -> bool {
    DNS_TYPES_VIRTUAL.contains(&dns_type)
}

pub fn split_host_port(input: &str) -> (&str, Option<&str>) {
    if let Some(bracket_end) = input.find(']') {
        let host = &input[..=bracket_end];
        let rest = &input[bracket_end + 1..];
        if let Some(port) = rest.strip_prefix(':') {
            (host, Some(port))
        } else {
            (host, None)
        }
    } else if let Some(colon) = input.rfind(':') {
        (&input[..colon], Some(&input[colon + 1..]))
    } else {
        (input, None)
    }
}

pub fn has_explicit_port(host: &str) -> bool {
    if host.starts_with('[') {
        return host
            .find(']')
            .is_some_and(|i| host[i + 1..].starts_with(':'));
    }
    let Some(i) = host.rfind(':') else {
        return false;
    };
    host[i + 1..].parse::<u16>().is_ok()
}

/// Map dae upstream URL schemes to sing-box DNS server types.
fn normalize_dns_type(scheme: &str) -> &str {
    match scheme {
        "tcp+udp" => "udp",
        other => other,
    }
}

pub fn parse_dns_upstream(tag: &str, url: &str) -> DnsServer {
    let Some((scheme, rest)) = url.split_once("://") else {
        return DnsServer {
            tag: Some(tag.to_string()),
            dns_type: Some("udp".to_string()),
            server: Some(url.to_string()),
            ..DnsServer::default()
        };
    };

    let dns_type = normalize_dns_type(scheme);

    let (host_part, path) = match (dns_type, rest.find('/')) {
        (s, Some(pos)) if DNS_TYPES_WITH_PATH.contains(&s) => {
            let (h, p) = rest.split_at(pos);
            (h, Some(p.to_string()))
        }
        _ => (rest, None),
    };

    let (server, _port) = split_host_port(host_part);

    DnsServer {
        server: Some(server.to_string()),
        tag: Some(tag.to_string()),
        dns_type: Some(dns_type.to_string()),
        path,
        ..DnsServer::default()
    }
}

pub fn build_dae_upstream_url(srv: &DnsServer) -> Option<String> {
    let dns_type = srv.dns_type.as_deref()?;
    if is_virtual_dns_type(dns_type) {
        return None;
    }
    let host = srv.server.as_deref()?;

    let has_port = has_explicit_port(host);
    let default = default_port(dns_type);

    let url = if DNS_TYPES_WITH_PATH.contains(&dns_type) {
        let path = srv.path.as_deref().unwrap_or("/dns-query");
        if has_port {
            format!("{dns_type}://{host}{path}")
        } else {
            format!("{dns_type}://{host}:{default}{path}")
        }
    } else if has_port {
        format!("{dns_type}://{host}")
    } else {
        format!("{dns_type}://{host}:{default}")
    };

    Some(url)
}

pub fn extract_paren_args<'a>(s: &'a str, func: &str) -> Option<&'a str> {
    let s = s.trim();
    if !s.starts_with(func) || !s.contains('(') {
        return None;
    }
    let start = s.find('(')?;
    let end = s.rfind(')')?;
    if end <= start {
        return None;
    }
    Some(s[start + 1..end].trim())
}

pub fn parse_comma_args(s: &str) -> Vec<String> {
    s.split(',')
        .map(|arg| clean_quoted(arg.trim()))
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn clean_quoted(s: &str) -> String {
    let trimmed = s.trim();
    if (trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2)
        || (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2)
    {
        trimmed[1..trimmed.len() - 1].to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_host_port_ipv4() {
        assert_eq!(split_host_port("8.8.8.8:53"), ("8.8.8.8", Some("53")));
        assert_eq!(split_host_port("8.8.8.8"), ("8.8.8.8", None));
    }

    #[test]
    fn split_host_port_ipv6_bracketed() {
        assert_eq!(
            split_host_port("[2001:db8::1]:53"),
            ("[2001:db8::1]", Some("53"))
        );
        assert_eq!(split_host_port("[2001:db8::1]"), ("[2001:db8::1]", None));
    }

    #[test]
    fn has_explicit_port_cases() {
        assert!(has_explicit_port("8.8.8.8:53"));
        assert!(!has_explicit_port("8.8.8.8"));
        assert!(has_explicit_port("[::1]:5353"));
        assert!(!has_explicit_port("[::1]"));
    }

    #[test]
    fn default_port_mapping() {
        assert_eq!(default_port("udp"), 53);
        assert_eq!(default_port("tcp"), 53);
        assert_eq!(default_port("tcp+udp"), 53);
        assert_eq!(default_port("https"), 443);
        assert_eq!(default_port("tls"), 853);
        assert_eq!(default_port("quic"), 853);
        assert_eq!(default_port("h3"), 443);
    }

    #[test]
    fn roundtrip_dns_upstream_udp() {
        let srv = parse_dns_upstream("my", "udp://8.8.8.8:53");
        assert_eq!(srv.tag.as_deref(), Some("my"));
        assert_eq!(srv.dns_type.as_deref(), Some("udp"));
        assert_eq!(srv.server.as_deref(), Some("8.8.8.8"));

        let url = build_dae_upstream_url(&srv).unwrap();
        assert_eq!(url, "udp://8.8.8.8:53");
    }

    #[test]
    fn roundtrip_dns_upstream_https() {
        let srv = parse_dns_upstream("doh", "https://dns.cloudflare.com:443/dns-query");
        assert_eq!(srv.server.as_deref(), Some("dns.cloudflare.com"));
        assert_eq!(srv.path.as_deref(), Some("/dns-query"));

        let url = build_dae_upstream_url(&srv).unwrap();
        assert_eq!(url, "https://dns.cloudflare.com:443/dns-query");
    }
}
