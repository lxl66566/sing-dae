use std::collections::HashSet;

use crate::{
    convert::dns_utils::{build_dae_upstream_url, is_virtual_dns_type},
    dae::ast::{
        DaeConfig, DnsSection, Entry, FilterDef, GroupDef, KeyValue, PolicyDef, RoutingRule,
        RoutingSection,
    },
    error::{AppError, Result},
    singbox::config::SingBoxConfig,
};

#[allow(clippy::missing_errors_doc)]
pub fn convert(sing: &SingBoxConfig) -> Result<DaeConfig> {
    let global = build_global(sing);
    let nodes = build_nodes(sing)?;
    let groups = build_groups(sing);
    let dns = build_dns(sing);
    let routing = build_routing(sing);

    Ok(DaeConfig {
        global,
        subscriptions: vec![],
        nodes,
        dns,
        groups,
        routing,
    })
}

// ---- Log -> Global ----

fn build_global(sing: &SingBoxConfig) -> Vec<KeyValue> {
    let mut kvs = Vec::new();

    if let Some(level) = sing.log.as_ref().and_then(|log| log.level.as_ref()) {
        kvs.push(KeyValue {
            key: "log_level".into(),
            value: level.clone(),
        });
    }

    let defaults = [
        ("tproxy_port", "12345"),
        ("wan_interface", "auto"),
        ("dial_mode", "domain"),
        ("allow_insecure", "false"),
        (
            "tcp_check_url",
            "http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111",
        ),
        (
            "udp_check_dns",
            "dns.google.com:53,8.8.8.8,2001:4860:4860::8888",
        ),
        ("check_interval", "30s"),
    ];

    for (key, value) in defaults {
        if !kvs.iter().any(|kv| kv.key == key) {
            kvs.push(KeyValue {
                key: key.to_string(),
                value: value.to_string(),
            });
        }
    }

    kvs
}

// ---- Proxy Outbounds -> Nodes ----

fn build_nodes(sing: &SingBoxConfig) -> Result<Vec<Entry>> {
    sing.outbounds
        .iter()
        .filter(|ob| is_proxy_type(&ob.outbound_type))
        .map(|ob| {
            let tag = ob.tag.as_deref().unwrap_or(&ob.outbound_type);
            let link = build_node_link(ob)?;
            Ok(Entry::Tagged {
                key: tag.to_string(),
                value: link,
            })
        })
        .collect()
}

fn is_proxy_type(t: &str) -> bool {
    matches!(
        t,
        "hysteria2" | "trojan" | "vmess" | "vless" | "shadowsocks"
    )
}

fn build_node_link(ob: &crate::singbox::config::Outbound) -> Result<String> {
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

    match ob.outbound_type.as_str() {
        "hysteria2" => {
            let password = ob.password.as_deref().unwrap_or("");
            Ok(format!(
                "hy2://{password}@{server}:{port}/?sni={sni}#{fragment}"
            ))
        }
        "trojan" => {
            let password = ob.password.as_deref().unwrap_or("");
            Ok(format!(
                "trojan://{password}@{server}:{port}/?type=tcp&security=tls&sni={sni}#{fragment}"
            ))
        }
        "vless" => {
            let uuid = ob.uuid.as_deref().unwrap_or("");
            let security = ob.security.as_deref().unwrap_or("tls");
            Ok(format!(
                "vless://{uuid}@{server}:{port}/?type=tcp&security={security}&sni={sni}#{fragment}"
            ))
        }
        "vmess" => {
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
        "shadowsocks" => {
            let method = ob.method.as_deref().unwrap_or("aes-256-gcm");
            let password = ob.password.as_deref().unwrap_or("");
            let userinfo = base64_encode(format!("{method}:{password}").as_bytes());
            Ok(format!("ss://{userinfo}@{server}:{port}#{fragment}"))
        }
        _ => Err(AppError::Conversion(format!(
            "unsupported outbound type: '{}'",
            ob.outbound_type
        ))),
    }
}

// ---- Selector/URLTest Outbounds -> Groups ----

fn build_groups(sing: &SingBoxConfig) -> Vec<GroupDef> {
    sing.outbounds
        .iter()
        .filter(|ob| matches!(ob.outbound_type.as_str(), "selector" | "urltest"))
        .map(|ob| {
            let policy = if ob.outbound_type == "urltest" {
                PolicyDef::MinMovingAvg
            } else {
                PolicyDef::Random
            };

            let group_outbounds = ob.outbounds.as_deref().unwrap_or(&[]);
            let filters = if group_outbounds.is_empty() {
                vec![]
            } else {
                vec![FilterDef {
                    expression: format!("name({})", group_outbounds.join(", ")),
                    latency_offset: None,
                }]
            };

            GroupDef {
                name: ob.tag.clone().unwrap_or_default(),
                filters,
                policy,
                extra: vec![],
            }
        })
        .collect()
}

// ---- DNS ----

fn build_dns(sing: &SingBoxConfig) -> DnsSection {
    let mut dns = DnsSection::default();

    if let Some(sing_dns) = &sing.dns {
        let valid_upstreams: HashSet<&str> = sing_dns
            .servers
            .iter()
            .filter(|s| !is_virtual_dns_type(s.dns_type.as_deref().unwrap_or("")))
            .filter_map(|s| s.tag.as_deref())
            .collect();

        for srv in &sing_dns.servers {
            if let Some(tag) = srv.tag.as_deref()
                && let Some(url) = build_dae_upstream_url(srv)
            {
                dns.upstream.push(KeyValue {
                    key: tag.to_string(),
                    value: url,
                });
            }
        }

        for rule in &sing_dns.rules {
            if let Some(dae_rule) = convert_dns_rule(rule, &valid_upstreams) {
                dns.request_rules.push(dae_rule);
            }
        }

        if let Some(final_dns) = &sing_dns.final_dns
            && valid_upstreams.contains(final_dns.as_str())
        {
            dns.fallback = Some(final_dns.clone());
        }
    }

    dns
}

fn convert_dns_rule(
    rule: &crate::singbox::config::DnsRule,
    valid_upstreams: &HashSet<&str>,
) -> Option<RoutingRule> {
    if rule.rule_type.as_deref() == Some("logical") {
        return None;
    }

    let has_domain = !rule.domain.is_empty()
        || !rule.domain_suffix.is_empty()
        || !rule.domain_keyword.is_empty()
        || !rule.domain_regex.is_empty()
        || !rule.rule_set.is_empty();

    let target = if rule.action.as_deref() == Some("predefined") {
        if !has_domain {
            return None;
        }
        "reject".to_string()
    } else {
        let server = rule.server.as_deref()?;
        if !valid_upstreams.contains(server) {
            return None;
        }
        server.to_string()
    };

    let mut qname_args: Vec<String> = Vec::new();
    for s in &rule.domain {
        qname_args.push(format!("full:{s}"));
    }
    for s in &rule.domain_suffix {
        qname_args.push(s.clone());
    }
    for s in &rule.domain_keyword {
        qname_args.push(format!("keyword:{s}"));
    }
    for s in &rule.domain_regex {
        qname_args.push(format!("regex:{s}"));
    }
    for rs in &rule.rule_set {
        if let Some(name) = rs.strip_prefix("geosite-") {
            qname_args.push(format!("geosite:{name}"));
        }
    }

    if qname_args.is_empty() {
        return None;
    }

    Some(RoutingRule {
        condition: format!("qname({})", qname_args.join(", ")),
        target,
    })
}

// ---- Route -> Routing ----

fn build_routing(sing: &SingBoxConfig) -> RoutingSection {
    let mut routing = RoutingSection::default();

    if let Some(route) = &sing.route {
        for rule in &route.rules {
            routing.rules.extend(convert_route_rule(rule));
        }

        if let Some(final_ob) = &route.final_outbound {
            routing.fallback = Some(map_routing_target(final_ob));
        }
    }

    routing
}

fn convert_route_rule(rule: &crate::singbox::config::RouteRule) -> Vec<RoutingRule> {
    if matches!(
        rule.action.as_deref(),
        Some("sniff" | "hijack-dns" | "resolve")
    ) {
        return vec![];
    }

    if rule.rule_type.as_deref() == Some("logical") {
        if rule.mode.as_deref() == Some("or") {
            return rule.rules.iter().flat_map(convert_route_rule).collect();
        }
        return vec![];
    }

    if rule.clash_mode.is_some() {
        return vec![];
    }

    let target = resolve_rule_target(rule);
    let mut results = Vec::new();

    let domain_args = collect_domain_args(rule);
    if !domain_args.is_empty() {
        results.push(RoutingRule {
            condition: format!("domain({})", domain_args.join(", ")),
            target: target.clone(),
        });
    }

    let dip_args = collect_dip_args(rule);
    if !dip_args.is_empty() {
        results.push(RoutingRule {
            condition: format!("dip({})", dip_args.join(", ")),
            target: target.clone(),
        });
    }

    if !rule.process_name.is_empty() {
        results.push(RoutingRule {
            condition: format!("pname({})", rule.process_name.join(", ")),
            target,
        });
    }

    results
}

fn resolve_rule_target(rule: &crate::singbox::config::RouteRule) -> String {
    if rule.action.as_deref() == Some("reject") {
        return "block".to_string();
    }
    if let Some(ob) = &rule.outbound {
        return map_routing_target(ob);
    }
    "direct".to_string()
}

fn map_routing_target(outbound: &str) -> String {
    outbound.to_string()
}

fn collect_domain_args(rule: &crate::singbox::config::RouteRule) -> Vec<String> {
    let mut args = Vec::new();
    args.extend_from_slice(&rule.domain_suffix);
    args.extend_from_slice(&rule.domain);
    for rs in &rule.rule_set {
        if let Some(name) = rs.strip_prefix("geosite-") {
            args.push(format!("geosite:{name}"));
        }
    }
    args
}

fn collect_dip_args(rule: &crate::singbox::config::RouteRule) -> Vec<String> {
    let mut args = Vec::new();
    if rule.ip_is_private == Some(true) {
        args.push("geoip:private".to_string());
    }
    args.extend_from_slice(&rule.ip_cidr);
    for rs in &rule.rule_set {
        if let Some(name) = rs.strip_prefix("geoip-") {
            args.push(format!("geoip:{name}"));
        }
    }
    args
}

fn resolve_port(ob: &crate::singbox::config::Outbound, tag: &str) -> Result<u16> {
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
        let first = digits.parse::<u16>().ok().ok_or_else(|| {
            AppError::Conversion(format!(
                "outbound '{tag}' has invalid server_ports '{ports:?}'"
            ))
        })?;
        return Ok(first);
    }
    Err(AppError::Conversion(format!(
        "outbound '{tag}' missing server_port or server_ports"
    )))
}

// ---- Encoding helpers ----

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
                let hi = (byte >> 4) & 0x0F;
                let lo = byte & 0x0F;
                result.push(HEX_TABLE[hi as usize] as char);
                result.push(HEX_TABLE[lo as usize] as char);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::singbox::config::*;

    fn make_hy2_outbound() -> Outbound {
        Outbound {
            outbound_type: "hysteria2".into(),
            tag: Some("my-hy2".into()),
            server: Some("1.2.3.4".into()),
            server_port: Some(443),
            password: Some("pass123".into()),
            tls: Some(TlsConfig {
                enabled: Some(true),
                server_name: Some("example.com".into()),
                insecure: None,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn log_level_to_global() {
        let sing = SingBoxConfig {
            log: Some(Log {
                level: Some("debug".into()),
                timestamp: None,
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert!(dae.global.len() > 1);
        assert_eq!(dae.global[0].key, "log_level");
        assert_eq!(dae.global[0].value, "debug");
        assert!(dae.global.iter().any(|kv| kv.key == "tproxy_port"));
    }

    #[test]
    fn hysteria2_outbound_to_node() {
        let sing = SingBoxConfig {
            outbounds: vec![make_hy2_outbound()],
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.nodes.len(), 1);
        match &dae.nodes[0] {
            Entry::Tagged { key, value } => {
                assert_eq!(key, "my-hy2");
                assert!(value.starts_with("hy2://pass123@1.2.3.4:443/"));
                assert!(value.contains("sni=example.com"));
                assert!(value.ends_with("#my-hy2"));
            }
            Entry::Untagged(_) => panic!("expected tagged entry"),
        }
    }

    #[test]
    fn hysteria2_server_ports_fallback() {
        let sing = SingBoxConfig {
            outbounds: vec![Outbound {
                outbound_type: "hysteria2".into(),
                tag: Some("hy2-hop".into()),
                server: Some("rfc.852456.xyz".into()),
                server_port: None,
                server_ports: Some(vec!["65501:65533".into()]),
                password: Some("passwd".into()),
                tls: Some(TlsConfig {
                    enabled: Some(true),
                    server_name: Some("rfc.852456.xyz".into()),
                    insecure: None,
                }),
                ..Default::default()
            }],
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.nodes.len(), 1);
        match &dae.nodes[0] {
            Entry::Tagged { key: _, value } => {
                assert!(value.starts_with("hy2://passwd@rfc.852456.xyz:65501/"));
                assert!(value.contains("sni=rfc.852456.xyz"));
            }
            Entry::Untagged(_) => panic!("expected tagged entry"),
        }
    }

    #[test]
    fn trojan_outbound_to_node() {
        let sing = SingBoxConfig {
            outbounds: vec![Outbound {
                outbound_type: "trojan".into(),
                tag: Some("tr-node".into()),
                server: Some("5.6.7.8".into()),
                server_port: Some(8443),
                password: Some("trojanpw".into()),
                tls: Some(TlsConfig {
                    enabled: Some(true),
                    server_name: Some("trojan.example.com".into()),
                    insecure: None,
                }),
                ..Default::default()
            }],
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        match &dae.nodes[0] {
            Entry::Tagged { key, value } => {
                assert_eq!(key, "tr-node");
                assert!(value.starts_with("trojan://trojanpw@5.6.7.8:8443/"));
                assert!(value.contains("type=tcp"));
                assert!(value.contains("security=tls"));
                assert!(value.contains("sni=trojan.example.com"));
            }
            Entry::Untagged(_) => panic!("expected tagged entry"),
        }
    }

    #[test]
    fn direct_outbound_skipped() {
        let sing = SingBoxConfig {
            outbounds: vec![
                make_hy2_outbound(),
                Outbound {
                    outbound_type: "direct".into(),
                    tag: Some("direct".into()),
                    ..Default::default()
                },
            ],
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.nodes.len(), 1);
        match &dae.nodes[0] {
            Entry::Tagged { key, .. } => assert_eq!(key, "my-hy2"),
            Entry::Untagged(_) => panic!("expected tagged entry"),
        }
    }

    #[test]
    fn selector_becomes_group() {
        let sing = SingBoxConfig {
            outbounds: vec![
                make_hy2_outbound(),
                Outbound {
                    outbound_type: "selector".into(),
                    tag: Some("my-group".into()),
                    outbounds: Some(vec!["my-hy2".into()]),
                    ..Default::default()
                },
            ],
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.groups.len(), 1);
        assert_eq!(dae.groups[0].name, "my-group");
        assert_eq!(dae.groups[0].policy, PolicyDef::Random);
        assert_eq!(dae.groups[0].filters.len(), 1);
        assert_eq!(dae.groups[0].filters[0].expression, "name(my-hy2)");
    }

    #[test]
    fn urltest_becomes_min_moving_avg() {
        let sing = SingBoxConfig {
            outbounds: vec![Outbound {
                outbound_type: "urltest".into(),
                tag: Some("auto-group".into()),
                outbounds: Some(vec!["a".into(), "b".into()]),
                ..Default::default()
            }],
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.groups[0].policy, PolicyDef::MinMovingAvg);
        assert_eq!(dae.groups[0].filters[0].expression, "name(a, b)");
    }

    #[test]
    fn dns_servers_to_upstream() {
        let sing = SingBoxConfig {
            dns: Some(Dns {
                servers: vec![
                    DnsServer {
                        tag: Some("local".into()),
                        dns_type: Some("udp".into()),
                        server: Some("223.5.5.5".into()),
                        ..Default::default()
                    },
                    DnsServer {
                        tag: Some("remote".into()),
                        dns_type: Some("tcp+udp".into()),
                        server: Some("dns.google.com".into()),
                        ..Default::default()
                    },
                ],
                final_dns: Some("remote".into()),
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.dns.upstream.len(), 2);
        assert_eq!(dae.dns.upstream[0].key, "local");
        assert_eq!(dae.dns.upstream[0].value, "udp://223.5.5.5:53");
        assert_eq!(dae.dns.upstream[1].value, "tcp+udp://dns.google.com:53");

        assert_eq!(dae.dns.fallback.as_deref(), Some("remote"));
    }

    #[test]
    fn dns_rule_domain_suffix_to_qname() {
        let sing = SingBoxConfig {
            dns: Some(Dns {
                servers: vec![DnsServer {
                    tag: Some("mydns".into()),
                    dns_type: Some("udp".into()),
                    server: Some("1.1.1.1".into()),
                    ..Default::default()
                }],
                rules: vec![DnsRule {
                    server: Some("mydns".into()),
                    domain_suffix: vec!["example.com".into(), "test.org".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        let rule = &dae.dns.request_rules[0];
        assert_eq!(rule.condition, "qname(example.com, test.org)");
        assert_eq!(rule.target, "mydns");
    }

    #[test]
    fn dns_rule_predefined_to_reject() {
        let sing = SingBoxConfig {
            dns: Some(Dns {
                servers: vec![],
                rules: vec![DnsRule {
                    action: Some("predefined".into()),
                    rcode: Some("NXDOMAIN".into()),
                    rule_set: vec!["geosite-category-ads-all".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        let rule = &dae.dns.request_rules[0];
        assert_eq!(rule.target, "reject");
        assert!(rule.condition.contains("geosite:category-ads-all"));
    }

    #[test]
    fn route_domain_suffix_to_domain() {
        let sing = SingBoxConfig {
            route: Some(Route {
                rules: vec![RouteRule {
                    outbound: Some("direct".into()),
                    domain_suffix: vec!["example.com".into(), "test.org".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.routing.rules.len(), 1);
        assert_eq!(
            dae.routing.rules[0].condition,
            "domain(example.com, test.org)"
        );
        assert_eq!(dae.routing.rules[0].target, "direct");
    }

    #[test]
    fn route_rule_set_geosite_to_domain() {
        let sing = SingBoxConfig {
            route: Some(Route {
                rules: vec![RouteRule {
                    outbound: Some("direct".into()),
                    rule_set: vec!["geosite-cn".into(), "geosite-bilibili".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(
            dae.routing.rules[0].condition,
            "domain(geosite:cn, geosite:bilibili)"
        );
    }

    #[test]
    fn route_ip_is_private_to_dip() {
        let sing = SingBoxConfig {
            route: Some(Route {
                rules: vec![RouteRule {
                    outbound: Some("direct".into()),
                    ip_is_private: Some(true),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.routing.rules[0].condition, "dip(geoip:private)");
        assert_eq!(dae.routing.rules[0].target, "direct");
    }

    #[test]
    fn route_ip_cidr_to_dip() {
        let sing = SingBoxConfig {
            route: Some(Route {
                rules: vec![RouteRule {
                    outbound: Some("proxy".into()),
                    ip_cidr: vec!["10.0.0.0/8".into(), "172.16.0.0/12".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(
            dae.routing.rules[0].condition,
            "dip(10.0.0.0/8, 172.16.0.0/12)"
        );
    }

    #[test]
    fn route_geoip_rule_set_to_dip() {
        let sing = SingBoxConfig {
            route: Some(Route {
                rules: vec![RouteRule {
                    outbound: Some("direct".into()),
                    rule_set: vec!["geoip-cn".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.routing.rules[0].condition, "dip(geoip:cn)");
    }

    #[test]
    fn route_action_reject_to_block() {
        let sing = SingBoxConfig {
            route: Some(Route {
                rules: vec![RouteRule {
                    action: Some("reject".into()),
                    domain_suffix: vec!["ads.example.com".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.routing.rules[0].target, "block");
    }

    #[test]
    fn route_process_name_to_pname() {
        let sing = SingBoxConfig {
            route: Some(Route {
                rules: vec![RouteRule {
                    outbound: Some("direct".into()),
                    process_name: vec!["sshd".into(), "systemd-resolved".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(
            dae.routing.rules[0].condition,
            "pname(sshd, systemd-resolved)"
        );
    }

    #[test]
    fn route_final_to_fallback() {
        let sing = SingBoxConfig {
            route: Some(Route {
                final_outbound: Some("proxy".into()),
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.routing.fallback.as_deref(), Some("proxy"));
    }

    #[test]
    fn sniff_and_hijack_rules_skipped() {
        let sing = SingBoxConfig {
            route: Some(Route {
                rules: vec![
                    RouteRule {
                        action: Some("sniff".into()),
                        ..Default::default()
                    },
                    RouteRule {
                        action: Some("hijack-dns".into()),
                        ..Default::default()
                    },
                    RouteRule {
                        outbound: Some("proxy".into()),
                        domain_suffix: vec!["example.com".into()],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.routing.rules.len(), 1);
        assert_eq!(dae.routing.rules[0].condition, "domain(example.com)");
    }

    #[test]
    fn logical_or_rules_flattened() {
        let sing = SingBoxConfig {
            route: Some(Route {
                rules: vec![RouteRule {
                    rule_type: Some("logical".into()),
                    mode: Some("or".into()),
                    action: Some("hijack-dns".into()),
                    rules: vec![
                        RouteRule {
                            port: vec![53],
                            ..Default::default()
                        },
                        RouteRule {
                            protocol: vec!["dns".into()],
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        // hijack-dns sub-rules produce no dae rules
        assert!(dae.routing.rules.is_empty());
    }

    #[test]
    fn mixed_domain_and_ip_conditions_split() {
        let sing = SingBoxConfig {
            route: Some(Route {
                rules: vec![RouteRule {
                    outbound: Some("direct".into()),
                    domain_suffix: vec!["example.com".into()],
                    ip_cidr: vec!["10.0.0.0/8".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.routing.rules.len(), 2);
        assert_eq!(dae.routing.rules[0].condition, "domain(example.com)");
        assert_eq!(dae.routing.rules[1].condition, "dip(10.0.0.0/8)");
        assert_eq!(dae.routing.rules[0].target, "direct");
        assert_eq!(dae.routing.rules[1].target, "direct");
    }

    #[test]
    fn logical_or_rule_flattened() {
        let sing = SingBoxConfig {
            route: Some(Route {
                rules: vec![RouteRule {
                    rule_type: Some("logical".into()),
                    mode: Some("or".into()),
                    rules: vec![
                        RouteRule {
                            outbound: Some("direct".into()),
                            domain_suffix: vec!["a.com".into()],
                            ..Default::default()
                        },
                        RouteRule {
                            outbound: Some("direct".into()),
                            ip_cidr: vec!["10.0.0.0/8".into()],
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.routing.rules.len(), 2);
        assert_eq!(dae.routing.rules[0].condition, "domain(a.com)");
        assert_eq!(dae.routing.rules[1].condition, "dip(10.0.0.0/8)");
    }

    #[test]
    fn geosite_and_geoip_in_same_rule() {
        let sing = SingBoxConfig {
            route: Some(Route {
                rules: vec![RouteRule {
                    outbound: Some("direct".into()),
                    rule_set: vec!["geosite-cn".into(), "geoip-cn".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.routing.rules.len(), 2);
        assert_eq!(dae.routing.rules[0].condition, "domain(geosite:cn)");
        assert_eq!(dae.routing.rules[1].condition, "dip(geoip:cn)");
    }

    #[test]
    fn dns_https_upstream_with_path() {
        let sing = SingBoxConfig {
            dns: Some(Dns {
                servers: vec![DnsServer {
                    tag: Some("mydoh".into()),
                    dns_type: Some("https".into()),
                    server: Some("dns.cloudflare.com".into()),
                    path: Some("/dns-query".into()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.dns.upstream.len(), 1);
        assert_eq!(
            dae.dns.upstream[0].value,
            "https://dns.cloudflare.com:443/dns-query"
        );
    }

    #[test]
    fn dns_upstream_skips_local_hosts_fakeip() {
        let sing = SingBoxConfig {
            dns: Some(Dns {
                servers: vec![
                    DnsServer {
                        tag: Some("real_upstream".into()),
                        dns_type: Some("udp".into()),
                        server: Some("8.8.8.8".into()),
                        ..Default::default()
                    },
                    DnsServer {
                        tag: Some("local_dns".into()),
                        dns_type: Some("local".into()),
                        ..Default::default()
                    },
                    DnsServer {
                        tag: Some("hosts_table".into()),
                        dns_type: Some("hosts".into()),
                        ..Default::default()
                    },
                    DnsServer {
                        tag: Some("fake_dns".into()),
                        dns_type: Some("fakeip".into()),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.dns.upstream.len(), 1);
        assert_eq!(dae.dns.upstream[0].key, "real_upstream");
    }

    #[test]
    fn dns_rule_domain_exact_to_full() {
        let sing = SingBoxConfig {
            dns: Some(Dns {
                servers: vec![DnsServer {
                    tag: Some("mydns".into()),
                    dns_type: Some("udp".into()),
                    server: Some("1.1.1.1".into()),
                    ..Default::default()
                }],
                rules: vec![DnsRule {
                    server: Some("mydns".into()),
                    domain: vec!["exact.com".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        let rule = &dae.dns.request_rules[0];
        assert_eq!(rule.condition, "qname(full:exact.com)");
        assert_eq!(rule.target, "mydns");
    }

    #[test]
    fn dns_rule_domain_keyword_and_regex() {
        let sing = SingBoxConfig {
            dns: Some(Dns {
                servers: vec![DnsServer {
                    tag: Some("mydns".into()),
                    dns_type: Some("udp".into()),
                    server: Some("1.1.1.1".into()),
                    ..Default::default()
                }],
                rules: vec![DnsRule {
                    server: Some("mydns".into()),
                    domain_keyword: vec!["ad".into(), "track".into()],
                    domain_regex: vec!["\\.cn$".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        let rule = &dae.dns.request_rules[0];
        assert!(rule.condition.contains("keyword:ad"));
        assert!(rule.condition.contains("keyword:track"));
        assert!(rule.condition.contains("regex:\\.cn$"));
        assert_eq!(rule.target, "mydns");
    }

    #[test]
    fn dns_rule_skips_non_upstream_server() {
        let sing = SingBoxConfig {
            dns: Some(Dns {
                servers: vec![
                    DnsServer {
                        tag: Some("real_upstream".into()),
                        dns_type: Some("udp".into()),
                        server: Some("8.8.8.8".into()),
                        ..Default::default()
                    },
                    DnsServer {
                        tag: Some("local_dns".into()),
                        dns_type: Some("local".into()),
                        ..Default::default()
                    },
                ],
                rules: vec![
                    DnsRule {
                        server: Some("real_upstream".into()),
                        domain_suffix: vec!["valid.com".into()],
                        ..Default::default()
                    },
                    DnsRule {
                        server: Some("local_dns".into()),
                        domain_suffix: vec!["skipped.com".into()],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.dns.request_rules.len(), 1);
        assert_eq!(dae.dns.request_rules[0].condition, "qname(valid.com)");
        assert_eq!(dae.dns.request_rules[0].target, "real_upstream");
    }

    #[test]
    fn domain_keyword_and_suffix_combined() {
        let sing = SingBoxConfig {
            route: Some(Route {
                rules: vec![RouteRule {
                    outbound: Some("proxy".into()),
                    domain_suffix: vec!["google.com".into()],
                    domain_keyword: vec!["google".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.routing.rules.len(), 1);
        assert_eq!(dae.routing.rules[0].condition, "domain(google.com)");
    }

    #[test]
    fn sniff_and_hijack_dns_skipped() {
        let sing = SingBoxConfig {
            route: Some(Route {
                rules: vec![
                    RouteRule {
                        action: Some("sniff".into()),
                        ..Default::default()
                    },
                    RouteRule {
                        action: Some("hijack-dns".into()),
                        ..Default::default()
                    },
                    RouteRule {
                        outbound: Some("direct".into()),
                        domain_suffix: vec!["example.com".into()],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.routing.rules.len(), 1);
        assert_eq!(dae.routing.rules[0].condition, "domain(example.com)");
    }

    #[test]
    fn clash_mode_skipped() {
        let sing = SingBoxConfig {
            route: Some(Route {
                rules: vec![RouteRule {
                    outbound: Some("direct".into()),
                    clash_mode: Some("Direct".into()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert!(dae.routing.rules.is_empty());
    }

    #[test]
    fn dns_upstream_ipv6_no_port() {
        let sing = SingBoxConfig {
            dns: Some(Dns {
                servers: vec![DnsServer {
                    tag: Some("v6dns".into()),
                    dns_type: Some("udp".into()),
                    server: Some("2001:db8::1".into()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.dns.upstream.len(), 1);
        assert_eq!(dae.dns.upstream[0].value, "udp://2001:db8::1");
    }

    #[test]
    fn dns_upstream_ipv4_with_port() {
        let sing = SingBoxConfig {
            dns: Some(Dns {
                servers: vec![DnsServer {
                    tag: Some("mydns".into()),
                    dns_type: Some("udp".into()),
                    server: Some("8.8.8.8:5353".into()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.dns.upstream[0].value, "udp://8.8.8.8:5353");
    }
}
