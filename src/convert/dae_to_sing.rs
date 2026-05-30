use std::collections::HashMap;

use crate::{
    dae::ast::{DaeConfig, Entry, FilterDef, PolicyDef, RoutingRule},
    error::{AppError, Result},
    singbox::config::{
        Dns, DnsRule, DnsServer, Log, Outbound, Route, RouteRule, SingBoxConfig, TlsConfig,
    },
};

#[allow(clippy::missing_errors_doc)]
pub fn convert(dae: &DaeConfig) -> Result<SingBoxConfig> {
    let log = build_log(dae);

    let node_tags: Vec<String> = dae
        .nodes
        .iter()
        .filter_map(|n| match n {
            Entry::Tagged { key, .. } => Some(key.clone()),
            Entry::Untagged(_) => None,
        })
        .collect();
    let node_outbounds = build_node_outbounds(dae)?;
    let group_outbounds = build_group_outbounds(dae, &node_tags)?;

    let mut outbounds = Vec::new();
    outbounds.extend(node_outbounds);
    outbounds.push(new_outbound("direct", "direct"));
    outbounds.extend(group_outbounds);

    let dns = build_dns(dae);
    let route = build_route(dae);

    Ok(SingBoxConfig {
        log,
        dns,
        inbounds: vec![],
        outbounds,
        endpoints: vec![],
        route,
        experimental: None,
    })
}

// ---- Log ----

fn build_log(dae: &DaeConfig) -> Option<Log> {
    dae.global
        .iter()
        .find(|kv| kv.key == "log_level")
        .map(|kv| Log {
            level: Some(kv.value.clone()),
            timestamp: Some(true),
        })
}

// ---- Nodes -> Outbounds ----

fn build_node_outbounds(dae: &DaeConfig) -> Result<Vec<Outbound>> {
    let outbounds: Vec<Outbound> = dae
        .nodes
        .iter()
        .filter_map(|entry| match entry {
            Entry::Tagged { key, value } => parse_node_link(key, value).ok(),
            Entry::Untagged(val) => {
                let tag = format!("untagged_{}", &val[..val.len().min(8)]);
                parse_node_link(&tag, val).ok()
            }
        })
        .collect();
    Ok(outbounds)
}

fn parse_node_link(tag: &str, link: &str) -> Result<Outbound> {
    let (scheme, rest) = link
        .split_once("://")
        .ok_or_else(|| AppError::Conversion(format!("invalid node link: {link}")))?;

    if rest.contains(" -> ") {
        return Err(AppError::Conversion(format!(
            "chain nodes not supported: {link}"
        )));
    }

    let _fragment = match rest.rfind('#') {
        Some(idx) => &rest[idx + 1..],
        None => "",
    };

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
    let sni = params.get("sni").cloned();

    let outbound_type = match scheme {
        "hy2" => "hysteria2",
        "ss" => "shadowsocks",
        other => other,
    };

    let (password, uuid) = match scheme {
        "vless" => (None, Some(credential.to_string())),
        _ => (Some(credential.to_string()), None),
    };

    let tls = if sni.is_some() || matches!(scheme, "hy2" | "trojan") {
        Some(TlsConfig {
            enabled: Some(true),
            server_name: sni,
            insecure: None,
        })
    } else {
        None
    };

    Ok(Outbound {
        outbound_type: outbound_type.to_string(),
        tag: Some(tag.to_string()),
        server: Some(host),
        server_port: port,
        password,
        up_mbps: None,
        down_mbps: None,
        tls,
        method: None,
        uuid,
        security: None,
        outbounds: vec![],
    })
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

// ---- Groups -> Selector/UrlTest Outbounds ----

fn build_group_outbounds(dae: &DaeConfig, all_node_tags: &[String]) -> Result<Vec<Outbound>> {
    dae.groups
        .iter()
        .map(|group| {
            let matched = filter_nodes(&group.filters, all_node_tags);
            let outbound_type = match &group.policy {
                PolicyDef::Random | PolicyDef::Fixed(_) => "selector",
                PolicyDef::Min | PolicyDef::MinMovingAvg | PolicyDef::MinAvg10 => "urltest",
            };
            Ok(Outbound {
                outbound_type: outbound_type.to_string(),
                tag: Some(group.name.clone()),
                server: None,
                server_port: None,
                password: None,
                up_mbps: None,
                down_mbps: None,
                tls: None,
                method: None,
                uuid: None,
                security: None,
                outbounds: matched,
            })
        })
        .collect()
}

fn filter_nodes(filters: &[FilterDef], all_tags: &[String]) -> Vec<String> {
    if filters.is_empty() {
        return all_tags.to_vec();
    }

    let mut result = Vec::new();
    for filter in filters {
        let matched = apply_filter(&filter.expression, all_tags);
        result.extend(matched);
    }
    result.sort();
    result.dedup();
    result
}

fn apply_filter(expr: &str, tags: &[String]) -> Vec<String> {
    let expr = expr.trim();

    if let Some(rest) = expr.strip_prefix('!') {
        let included = apply_filter(rest, tags);
        return tags
            .iter()
            .filter(|t| !included.contains(t))
            .cloned()
            .collect();
    }

    if let Some(inner) = extract_paren_args(expr, "name") {
        if let Some(regex_content) = inner.trim().strip_prefix("regex:") {
            let pattern = clean_quoted(regex_content.trim());
            if let Some(prefix) = pattern.strip_prefix('^') {
                return tags
                    .iter()
                    .filter(|t| t.starts_with(prefix))
                    .cloned()
                    .collect();
            }
            return tags.to_vec();
        }
        let names: Vec<String> = inner.split(',').map(|s| clean_quoted(s.trim())).collect();
        return tags
            .iter()
            .filter(|t| names.iter().any(|n| n == *t))
            .cloned()
            .collect();
    }

    tags.to_vec()
}

// ---- DNS ----

fn build_dns(dae: &DaeConfig) -> Option<Dns> {
    if dae.dns.upstream.is_empty()
        && dae.dns.request_rules.is_empty()
        && dae.dns.response_rules.is_empty()
    {
        return None;
    }

    let servers: Vec<DnsServer> = dae
        .dns
        .upstream
        .iter()
        .map(|up| parse_dns_upstream(&up.key, &up.value))
        .collect();

    let mut final_dns = None;
    let mut rules = Vec::new();

    for rule in &dae.dns.request_rules {
        let cond = rule.condition.trim();
        if cond.eq_ignore_ascii_case("fallback") {
            final_dns = Some(rule.target.clone());
            continue;
        }
        rules.push(convert_dns_rule(rule));
    }

    for rule in &dae.dns.response_rules {
        let cond = rule.condition.trim();
        if cond.eq_ignore_ascii_case("fallback") {
            continue;
        }
        rules.push(convert_dns_rule(rule));
    }

    Some(Dns {
        servers,
        rules,
        final_dns,
        independent_cache: Some(true),
    })
}

fn parse_dns_upstream(tag: &str, url: &str) -> DnsServer {
    let (dns_type, server) = if let Some((scheme, rest)) = url.split_once("://") {
        let server = rest.rsplit_once(':').map_or(rest, |(h, _)| h).to_string();
        (scheme.to_string(), server)
    } else {
        ("udp".to_string(), url.to_string())
    };

    DnsServer {
        server: Some(server),
        tag: Some(tag.to_string()),
        dns_type: Some(dns_type),
        detour: None,
        domain_resolver: None,
        path: None,
        inet4_range: None,
        inet6_range: None,
        predefined: None,
    }
}

fn convert_dns_rule(rule: &RoutingRule) -> DnsRule {
    let condition = rule.condition.trim();
    let target = rule.target.trim();

    if let Some(args_str) = extract_paren_args(condition, "qname") {
        let args = parse_comma_args(args_str);
        let mut dns_rule = new_dns_rule();

        if target == "reject" {
            dns_rule.action = Some("predefined".to_string());
            dns_rule.rcode = Some("NOERROR".to_string());
        } else {
            dns_rule.server = Some(target.to_string());
        }

        for arg in &args {
            if let Some(name) = arg.strip_prefix("geosite:") {
                dns_rule.rule_set.push(format!("geosite-{name}"));
            } else if let Some(name) = arg.strip_prefix("geoip:") {
                dns_rule.rule_set.push(format!("geoip-{name}"));
            } else {
                dns_rule.domain_suffix.push(arg.clone());
            }
        }
        return dns_rule;
    }

    if let Some(args_str) = extract_paren_args(condition, "ip") {
        let args = parse_comma_args(args_str);
        let mut dns_rule = new_dns_rule();

        if target != "accept" {
            dns_rule.server = Some(target.to_string());
        }

        for arg in &args {
            if arg == "geoip:private" {
                dns_rule.ip_accept_any = Some(true);
            } else if let Some(name) = arg.strip_prefix("geoip:") {
                dns_rule.rule_set.push(format!("geoip-{name}"));
            }
        }
        return dns_rule;
    }

    if extract_paren_args(condition, "upstream").is_some() {
        let mut dns_rule = new_dns_rule();
        if target != "accept" {
            dns_rule.server = Some(target.to_string());
        }
        return dns_rule;
    }

    let mut dns_rule = new_dns_rule();
    dns_rule.server = Some(target.to_string());
    dns_rule
}

// ---- Route ----

fn build_route(dae: &DaeConfig) -> Option<Route> {
    if dae.routing.rules.is_empty() && dae.routing.fallback.is_none() {
        return None;
    }

    let rules: Vec<RouteRule> = dae.routing.rules.iter().map(convert_routing_rule).collect();

    Some(Route {
        rules,
        rule_set: vec![],
        final_outbound: dae.routing.fallback.clone(),
        default_domain_resolver: None,
    })
}

fn convert_routing_rule(rule: &RoutingRule) -> RouteRule {
    let condition = rule.condition.trim();
    let target = resolve_target(rule.target.trim());

    if let Some(args_str) = extract_paren_args(condition, "domain") {
        let args = parse_comma_args(args_str);
        let (rule_set, domain_suffix) = categorize_domain_args(&args);
        return RouteRule {
            outbound: target.outbound,
            action: target.action,
            rule_set,
            domain_suffix,
            ..new_route_rule()
        };
    }

    if let Some(args_str) = extract_paren_args(condition, "dip") {
        let args = parse_comma_args(args_str);
        let (ip_is_private, rule_set, ip_cidr) = categorize_dip_args(&args);
        return RouteRule {
            outbound: target.outbound,
            action: target.action,
            ip_is_private,
            rule_set,
            ip_cidr,
            ..new_route_rule()
        };
    }

    if let Some(args_str) = extract_paren_args(condition, "pname") {
        let args = parse_comma_args(args_str);
        return RouteRule {
            outbound: target.outbound,
            action: target.action,
            process_name: args,
            ..new_route_rule()
        };
    }

    RouteRule {
        outbound: target.outbound,
        action: target.action,
        ..new_route_rule()
    }
}

struct ResolvedTarget {
    outbound: Option<String>,
    action: Option<String>,
}

fn resolve_target(target: &str) -> ResolvedTarget {
    match target {
        "direct" | "must_direct" => ResolvedTarget {
            outbound: Some("direct".to_string()),
            action: None,
        },
        "block" => ResolvedTarget {
            outbound: None,
            action: Some("reject".to_string()),
        },
        name => ResolvedTarget {
            outbound: Some(name.to_string()),
            action: None,
        },
    }
}

// ---- Argument categorization ----

fn categorize_domain_args(args: &[String]) -> (Vec<String>, Vec<String>) {
    let mut rule_set = Vec::new();
    let mut domain_suffix = Vec::new();

    for arg in args {
        if let Some(name) = arg.strip_prefix("geosite:") {
            rule_set.push(format!("geosite-{name}"));
        } else if let Some(name) = arg.strip_prefix("geoip:") {
            rule_set.push(format!("geoip-{name}"));
        } else {
            domain_suffix.push(arg.clone());
        }
    }

    (rule_set, domain_suffix)
}

fn categorize_dip_args(args: &[String]) -> (Option<bool>, Vec<String>, Vec<String>) {
    let mut ip_is_private = None;
    let mut rule_set = Vec::new();
    let mut ip_cidr = Vec::new();

    for arg in args {
        if arg == "geoip:private" {
            ip_is_private = Some(true);
        } else if let Some(name) = arg.strip_prefix("geoip:") {
            rule_set.push(format!("geoip-{name}"));
        } else {
            ip_cidr.push(arg.clone());
        }
    }

    (ip_is_private, rule_set, ip_cidr)
}

// ---- String helpers ----

fn extract_paren_args<'a>(s: &'a str, func: &str) -> Option<&'a str> {
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

fn parse_comma_args(s: &str) -> Vec<String> {
    s.split(',')
        .map(|arg| clean_quoted(arg.trim()))
        .filter(|s| !s.is_empty())
        .collect()
}

fn clean_quoted(s: &str) -> String {
    let trimmed = s.trim();
    if (trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2)
        || (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2)
    {
        trimmed[1..trimmed.len() - 1].to_owned()
    } else {
        trimmed.to_owned()
    }
}

// ---- Struct constructors ----

fn new_outbound(tag: &str, outbound_type: &str) -> Outbound {
    Outbound {
        outbound_type: outbound_type.to_string(),
        tag: Some(tag.to_string()),
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

fn new_route_rule() -> RouteRule {
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

fn new_dns_rule() -> DnsRule {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dae::ast::*;

    #[test]
    fn roundtrip_log_level() {
        let dae = DaeConfig {
            global: vec![KeyValue {
                key: "log_level".into(),
                value: "debug".into(),
            }],
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        assert_eq!(cfg.log.as_ref().unwrap().level.as_deref(), Some("debug"));
    }

    #[test]
    fn converts_hy2_node() {
        let dae = DaeConfig {
            nodes: vec![Entry::Tagged {
                key: "my-hy".into(),
                value: "hy2://pass123@1.2.3.4:443/?sni=example.com#display".into(),
            }],
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let ob = &cfg.outbounds[0];
        assert_eq!(ob.outbound_type, "hysteria2");
        assert_eq!(ob.tag.as_deref(), Some("my-hy"));
        assert_eq!(ob.server.as_deref(), Some("1.2.3.4"));
        assert_eq!(ob.server_port, Some(443));
        assert_eq!(ob.password.as_deref(), Some("pass123"));
        let tls = ob.tls.as_ref().unwrap();
        assert_eq!(tls.server_name.as_deref(), Some("example.com"));
    }

    #[test]
    fn converts_trojan_node() {
        let dae = DaeConfig {
            nodes: vec![Entry::Tagged {
                key: "my-tr".into(),
                value: "trojan://pw@host:8080/?type=tcp&security=tls&sni=host#name".into(),
            }],
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let ob = &cfg.outbounds[0];
        assert_eq!(ob.outbound_type, "trojan");
        assert_eq!(ob.server_port, Some(8080));
    }

    #[test]
    fn direct_outbound_always_present() {
        let dae = DaeConfig::default();
        let cfg = convert(&dae).unwrap();
        assert!(
            cfg.outbounds
                .iter()
                .any(|ob| ob.tag.as_deref() == Some("direct") && ob.outbound_type == "direct")
        );
    }

    #[test]
    fn group_urltest_with_name_filter() {
        let dae = DaeConfig {
            nodes: vec![
                Entry::Tagged {
                    key: "jp-1".into(),
                    value: "hy2://p@h:1".into(),
                },
                Entry::Tagged {
                    key: "us-1".into(),
                    value: "hy2://p@h:2".into(),
                },
            ],
            groups: vec![GroupDef {
                name: "jp".into(),
                filters: vec![FilterDef {
                    expression: "name(regex: '^jp')".into(),
                    latency_offset: None,
                }],
                policy: PolicyDef::MinMovingAvg,
                extra: vec![],
            }],
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let jp_group = cfg
            .outbounds
            .iter()
            .find(|ob| ob.tag.as_deref() == Some("jp"))
            .unwrap();
        assert_eq!(jp_group.outbound_type, "urltest");
        assert_eq!(jp_group.outbounds, vec!["jp-1"]);
    }

    #[test]
    fn group_selector_with_negated_filter() {
        let dae = DaeConfig {
            nodes: vec![
                Entry::Tagged {
                    key: "jp-1".into(),
                    value: "hy2://p@h:1".into(),
                },
                Entry::Tagged {
                    key: "us-1".into(),
                    value: "hy2://p@h:2".into(),
                },
            ],
            groups: vec![GroupDef {
                name: "no_jp".into(),
                filters: vec![FilterDef {
                    expression: "!name(regex: '^jp')".into(),
                    latency_offset: None,
                }],
                policy: PolicyDef::Random,
                extra: vec![],
            }],
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let g = cfg
            .outbounds
            .iter()
            .find(|ob| ob.tag.as_deref() == Some("no_jp"))
            .unwrap();
        assert_eq!(g.outbound_type, "selector");
        assert_eq!(g.outbounds, vec!["us-1"]);
    }

    #[test]
    fn route_domain_condition() {
        let dae = DaeConfig {
            routing: RoutingSection {
                rules: vec![RoutingRule {
                    condition: "domain(example.com, geosite:cn)".into(),
                    target: "direct".into(),
                }],
                fallback: Some("proxy".into()),
            },
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let route = cfg.route.as_ref().unwrap();
        let r = &route.rules[0];
        assert_eq!(r.outbound.as_deref(), Some("direct"));
        assert_eq!(r.domain_suffix, vec!["example.com"]);
        assert_eq!(r.rule_set, vec!["geosite-cn"]);
        assert_eq!(route.final_outbound.as_deref(), Some("proxy"));
    }

    #[test]
    fn route_dip_condition() {
        let dae = DaeConfig {
            routing: RoutingSection {
                rules: vec![RoutingRule {
                    condition: "dip(geoip:private, 10.0.0.0/8)".into(),
                    target: "direct".into(),
                }],
                fallback: None,
            },
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let r = &cfg.route.unwrap().rules[0];
        assert_eq!(r.ip_is_private, Some(true));
        assert_eq!(r.ip_cidr, vec!["10.0.0.0/8"]);
    }

    #[test]
    fn route_block_target() {
        let dae = DaeConfig {
            routing: RoutingSection {
                rules: vec![RoutingRule {
                    condition: "domain(ads.example.com)".into(),
                    target: "block".into(),
                }],
                fallback: None,
            },
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let r = &cfg.route.unwrap().rules[0];
        assert_eq!(r.action.as_deref(), Some("reject"));
        assert!(r.outbound.is_none());
    }

    #[test]
    fn route_pname_and_must_direct() {
        let dae = DaeConfig {
            routing: RoutingSection {
                rules: vec![RoutingRule {
                    condition: "pname(sshd, systemd-resolved)".into(),
                    target: "must_direct".into(),
                }],
                fallback: None,
            },
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let r = &cfg.route.unwrap().rules[0];
        assert_eq!(r.process_name, vec!["sshd", "systemd-resolved"]);
        assert_eq!(r.outbound.as_deref(), Some("direct"));
    }

    #[test]
    fn dns_upstream_and_request_rules() {
        let dae = DaeConfig {
            dns: DnsSection {
                upstream: vec![
                    KeyValue {
                        key: "alidns".into(),
                        value: "udp://223.5.5.5:53".into(),
                    },
                    KeyValue {
                        key: "googledns".into(),
                        value: "tcp+udp://dns.google.com:53".into(),
                    },
                ],
                request_rules: vec![
                    RoutingRule {
                        condition: "qname(geosite:cn)".into(),
                        target: "alidns".into(),
                    },
                    RoutingRule {
                        condition: "qname(geosite:category-ads)".into(),
                        target: "reject".into(),
                    },
                    RoutingRule {
                        condition: "fallback".into(),
                        target: "googledns".into(),
                    },
                ],
                ..DnsSection::default()
            },
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let dns = cfg.dns.unwrap();

        assert_eq!(dns.servers.len(), 2);
        assert_eq!(dns.servers[0].tag.as_deref(), Some("alidns"));
        assert_eq!(dns.servers[0].dns_type.as_deref(), Some("udp"));
        assert_eq!(dns.servers[0].server.as_deref(), Some("223.5.5.5"));
        assert_eq!(dns.servers[1].dns_type.as_deref(), Some("tcp+udp"));
        assert_eq!(dns.servers[1].server.as_deref(), Some("dns.google.com"));

        assert_eq!(dns.rules.len(), 2);
        assert_eq!(dns.rules[0].server.as_deref(), Some("alidns"));
        assert_eq!(dns.rules[0].rule_set, vec!["geosite-cn"]);

        assert_eq!(dns.rules[1].action.as_deref(), Some("predefined"));
        assert_eq!(dns.rules[1].rule_set, vec!["geosite-category-ads"]);

        assert_eq!(dns.final_dns.as_deref(), Some("googledns"));
    }
}
