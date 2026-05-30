use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SingBoxConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<Log>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Dns>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbounds: Vec<Inbound>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<Outbound>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<serde_json::Value>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<Route>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dns {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<DnsServer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<DnsRule>,
    #[serde(
        rename = "final",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub final_dns: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub independent_cache: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub dns_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_resolver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inet4_range: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inet6_range: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predefined: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub rule_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invert: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite_ttl: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_accept_any: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query_type: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_keyword: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<DnsRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inbound {
    #[serde(rename = "type")]
    pub inbound_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outbound {
    #[serde(rename = "type")]
    pub outbound_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RouteRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<RuleSet>,
    #[serde(
        rename = "final",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub final_outbound: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_domain_resolver: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub rule_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invert: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_is_private: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_range: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_keyword: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_name: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocol: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RouteRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub rule_set_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}
