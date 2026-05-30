use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DaeConfig {
    #[serde(default)]
    pub global: Vec<KeyValue>,
    #[serde(default)]
    pub subscriptions: Vec<KeyValue>,
    #[serde(default)]
    pub nodes: Vec<KeyValue>,
    #[serde(default)]
    pub dns: DnsSection,
    #[serde(default)]
    pub groups: Vec<GroupDef>,
    #[serde(default)]
    pub routing: RoutingSection,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DnsSection {
    #[serde(default)]
    pub entries: Vec<KeyValue>,
    #[serde(default)]
    pub upstream: Vec<KeyValue>,
    #[serde(default)]
    pub request_rules: Vec<RoutingRule>,
    #[serde(default)]
    pub response_rules: Vec<RoutingRule>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutingRule {
    pub condition: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupDef {
    pub name: String,
    #[serde(default)]
    pub filters: Vec<FilterDef>,
    #[serde(default)]
    pub policy: PolicyDef,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FilterDef {
    pub expression: String,
    pub latency_offset: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub enum PolicyDef {
    #[default]
    Random,
    Fixed(usize),
    Min,
    MinMovingAvg,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RoutingSection {
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
    #[serde(default)]
    pub fallback: Option<String>,
}
