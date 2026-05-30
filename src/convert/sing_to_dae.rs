use crate::{
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
    sing.log
        .as_ref()
        .and_then(|log| log.level.as_ref())
        .map(|level| {
            vec![KeyValue {
                key: "log_level".into(),
                value: level.clone(),
            }]
        })
        .unwrap_or_default()
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
    let port = ob
        .server_port
        .ok_or_else(|| AppError::Conversion(format!("outbound '{tag}' missing server_port")))?;
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

            let filters = if ob.outbounds.is_empty() {
                vec![]
            } else {
                vec![FilterDef {
                    expression: format!("name({})", ob.outbounds.join(", ")),
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
        for srv in &sing_dns.servers {
            let tag = srv.tag.as_deref().unwrap_or("unnamed");
            let dns_type = srv.dns_type.as_deref().unwrap_or("udp");
            let server = srv.server.as_deref().unwrap_or("0.0.0.0");

            if matches!(dns_type, "local" | "hosts" | "fakeip") {
                continue;
            }

            dns.upstream.push(KeyValue {
                key: tag.to_string(),
                value: format!("{dns_type}://{server}:53"),
            });
        }

        for rule in &sing_dns.rules {
            if let Some(dae_rule) = convert_dns_rule(rule) {
                dns.request_rules.push(dae_rule);
            }
        }

        if let Some(final_dns) = &sing_dns.final_dns {
            dns.request_rules.push(RoutingRule {
                condition: "fallback".to_string(),
                target: final_dns.clone(),
            });
        }
    }

    dns
}

fn convert_dns_rule(rule: &crate::singbox::config::DnsRule) -> Option<RoutingRule> {
    if !rule.query_type.is_empty() {
        return None;
    }
    if rule.rule_type.as_deref() == Some("logical") {
        return None;
    }

    let target = if rule.action.as_deref() == Some("predefined") {
        "reject".to_string()
    } else {
        rule.server.clone()?
    };

    let mut qname_args: Vec<String> = Vec::new();
    for s in &rule.domain_suffix {
        qname_args.push(s.clone());
    }
    for s in &rule.domain {
        qname_args.push(s.clone());
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
            ..empty_outbound()
        }
    }

    fn empty_outbound() -> Outbound {
        Outbound {
            outbound_type: String::new(),
            tag: None,
            server: None,
            server_port: None,
            password: None,
            up_mbps: None,
            down_mbps: None,
            tls: None,
            method: None,
            uuid: None,
            security: None,
            outbounds: vec![],
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
        assert_eq!(dae.global.len(), 1);
        assert_eq!(dae.global[0].key, "log_level");
        assert_eq!(dae.global[0].value, "debug");
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
                ..empty_outbound()
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
                    ..empty_outbound()
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
                    outbounds: vec!["my-hy2".into()],
                    ..empty_outbound()
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
                outbounds: vec!["a".into(), "b".into()],
                ..empty_outbound()
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
                        ..empty_dns_server()
                    },
                    DnsServer {
                        tag: Some("remote".into()),
                        dns_type: Some("tcp+udp".into()),
                        server: Some("dns.google.com".into()),
                        ..empty_dns_server()
                    },
                ],
                final_dns: Some("remote".into()),
                ..empty_dns()
            }),
            ..SingBoxConfig::default()
        };
        let dae = convert(&sing).unwrap();
        assert_eq!(dae.dns.upstream.len(), 2);
        assert_eq!(dae.dns.upstream[0].key, "local");
        assert_eq!(dae.dns.upstream[0].value, "udp://223.5.5.5:53");
        assert_eq!(dae.dns.upstream[1].value, "tcp+udp://dns.google.com:53");

        let fallback = dae.dns.request_rules.last().unwrap();
        assert_eq!(fallback.condition, "fallback");
        assert_eq!(fallback.target, "remote");
    }

    #[test]
    fn dns_rule_domain_suffix_to_qname() {
        let sing = SingBoxConfig {
            dns: Some(Dns {
                servers: vec![DnsServer {
                    tag: Some("mydns".into()),
                    dns_type: Some("udp".into()),
                    server: Some("1.1.1.1".into()),
                    ..empty_dns_server()
                }],
                rules: vec![DnsRule {
                    server: Some("mydns".into()),
                    domain_suffix: vec!["example.com".into(), "test.org".into()],
                    ..empty_dns_rule()
                }],
                ..empty_dns()
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
                    ..empty_dns_rule()
                }],
                ..empty_dns()
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
                    ..empty_route_rule()
                }],
                ..empty_route()
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
                    ..empty_route_rule()
                }],
                ..empty_route()
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
                    ..empty_route_rule()
                }],
                ..empty_route()
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
                    ..empty_route_rule()
                }],
                ..empty_route()
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
                    ..empty_route_rule()
                }],
                ..empty_route()
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
                    ..empty_route_rule()
                }],
                ..empty_route()
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
                    ..empty_route_rule()
                }],
                ..empty_route()
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
                ..empty_route()
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
                        ..empty_route_rule()
                    },
                    RouteRule {
                        action: Some("hijack-dns".into()),
                        ..empty_route_rule()
                    },
                    RouteRule {
                        outbound: Some("proxy".into()),
                        domain_suffix: vec!["example.com".into()],
                        ..empty_route_rule()
                    },
                ],
                ..empty_route()
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
                            ..empty_route_rule()
                        },
                        RouteRule {
                            protocol: vec!["dns".into()],
                            ..empty_route_rule()
                        },
                    ],
                    ..empty_route_rule()
                }],
                ..empty_route()
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
                    ..empty_route_rule()
                }],
                ..empty_route()
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

    fn empty_dns_server() -> DnsServer {
        DnsServer {
            server: None,
            tag: None,
            dns_type: None,
            detour: None,
            domain_resolver: None,
            path: None,
            inet4_range: None,
            inet6_range: None,
            predefined: None,
        }
    }

    fn empty_dns() -> Dns {
        Dns {
            servers: vec![],
            rules: vec![],
            final_dns: None,
            independent_cache: None,
        }
    }

    fn empty_dns_rule() -> DnsRule {
        DnsRule {
            server: None,
            rule_type: None,
            mode: None,
            action: None,
            rcode: None,
            invert: None,
            rewrite_ttl: None,
            clash_mode: None,
            ip_accept_any: None,
            query_type: vec![],
            domain: vec![],
            domain_suffix: vec![],
            domain_keyword: vec![],
            domain_regex: vec![],
            rule_set: vec![],
            rules: vec![],
        }
    }

    fn empty_route() -> Route {
        Route {
            rules: vec![],
            rule_set: vec![],
            final_outbound: None,
            default_domain_resolver: None,
        }
    }

    fn empty_route_rule() -> RouteRule {
        RouteRule {
            outbound: None,
            rule_type: None,
            mode: None,
            action: None,
            invert: None,
            clash_mode: None,
            ip_is_private: None,
            network: vec![],
            port: vec![],
            port_range: vec![],
            domain: vec![],
            domain_suffix: vec![],
            domain_keyword: vec![],
            domain_regex: vec![],
            ip_cidr: vec![],
            process_name: vec![],
            protocol: vec![],
            rule_set: vec![],
            rules: vec![],
        }
    }
}
