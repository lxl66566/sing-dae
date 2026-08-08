# sing-dae

<details>
<summary>前言</summary>

我在 Linux 上使用 dae，在 windows 上使用 sing-box。我不想维护两份配置。

sing-box 的各种前端都很难用，配置又是 DNS 和 routing 解耦，导致分流写两遍。显然这种配置应该让前端来完成，而不是我手写。而 dae 比较适合手写。

</details>

dae (DSL) 与 sing-box (JSONC) 配置格式的双向转换工具。基于 Rust pest 语法解析、编译为 WASM。

在线转换: <https://lxl66566.github.io/sing-dae/>

如果你想直接基于 dae 配置启动 sing-box 代理，请前往 [dae-box](https://github.com/lxl66566/dae-box)。

## 功能

- dae -> sing-box: 解析 dae DSL，转换为 sing-box JSON 配置
  - 支持解析 regex 规则组、must_direct 出站等
  - 支持全局 `tls_implementation: utls` + `utls_imitate` 映射为出站 uTLS 指纹
  - 支持全局 `allow_insecure` 映射为出站 TLS insecure
- sing-box -> dae: 解析 sing-box JSONC，转换为 dae DSL
- 支持节点链接、DNS、路由规则、策略组转换
  - 支持的协议：Shadowsocks | Vmess | Vless | Trojan | Hysteria2 | Tuic | AnyTLS
- DNS request/response fallback 独立保留
- 编译为 WASM，web 端运行，不进行任何配置上传
- 支持使用注释，覆盖产物的字段

## 额外生成配置

项目希望转换后的配置可以直接使用，以下额外值会自动添加：

### dae -> sing-box

<!-- prettier-ignore -->
| 配置项 | 添加 | 说明 |
| ------ | ------ | ---- |
| inbounds | `mixed` 入站，监听 `127.0.0.1:1080` | sing-box 必需的入站配置 |
| experimental.cache_file | `enabled: true, store_fakeip: true` | DNS 缓存，推荐启用 |
| route.rule_set | 根据规则中引用的 geosite/geoip 自动生成 | 使用 [SagerNet 规则集](https://github.com/SagerNet/sing-geosite/tree/rule-set) |
| route.default_http_client + http_clients | `proxy-client`, detour 指向第一个组或第一个节点 | 用于通过代理拉取远程 rule_set srs 文件 |

### sing-box -> dae

<!-- prettier-ignore -->
| 配置项 | 默认值 | 说明 |
| ------ | ------ | ---- |
| global.tproxy_port | `12345` | dae 透明代理端口 |
| global.wan_interface | `auto` | 自动检测 WAN 接口 |
| global.dial_mode | `domain` | 使用域名拨号模式 |
| global.allow_insecure | `false` | 禁止不安全 TLS |
| global.tcp_check_url | Cloudflare 检查地址 | 节点连通性检查 |
| global.udp_check_dns | Google DNS 检查地址 | UDP 连通性检查 |
| global.check_interval | `30s` | 检查间隔 |

## 注释覆盖

你可以在源文件的**第一个注释块**中写入目标格式的配置（在 dae 配置中写 json，在 sing-box 配置中写 dae）。注释中的配置字段会与转换后产物的配置进行合并与覆盖。

如果想关闭注释覆盖功能，可以关闭这个 feature 并重新编译。

### dae 配置覆盖 sing-box

在 dae 文件开头用 `#` 注释写入 sing-box 格式的 JSON：

```dae
#{
#  "inbounds": [
#    {
#      "type": "mixed",
#      "tag": "mixed",
#      "listen": "127.0.0.1",
#      "listen_port": 10450
#    }
#  ]
#}
global {
    log_level: debug
}
```

转换后，`inbounds` 字段将被覆盖，将使用注释中指定的配置（端口 10450），而非默认的 1080。

- 对象类型递归合并；数组或基本类型直接覆盖

### sing-box 配置覆盖 dae

在 sing-box JSON/JSONC 文件开头用 `//` 注释写入 dae DSL：

```json
//global {
//  tproxy_port: 54321
//  wan_interface: eth0
//}
//routing {
//  domain(geosite:cn) -> direct
//  fallback: proxy
//}
{
  "log": {"level": "info"},
  ...
}
```

转换后，注释中的 dae 配置会与生成的配置合并：

- `global` 等键值对 section：按 key 合并，注释值覆盖生成值
- `dns`、`routing` 等 `{}` 结构 section：递归合并，字段级别覆盖
- `rules` 类列表：注释中的规则插入到生成规则之前（优先匹配）
- `nodes`、`groups`：按名称/标签合并，注释值覆盖生成值

## 转换局限性

### 两个方向共同的局限性

| 遗漏项                                   | 原因                                                              |
| ---------------------------------------- | ----------------------------------------------------------------- |
| subscription 订阅源                      | dae 内置订阅拉取，sing-box 无此概念，转换后 subscription 段为空   |
| chain node (链式节点如 `A -> B`)         | 转换时跳过，不受支持                                              |
| `!` 取反条件（如 `!domain(...)`）        | dae 支持逻辑取反，sing-box 默认规则无法表达，转换时取反分支被丢弃 |
| dae `dscp()` / `mac()` / `puid()`        | sing-box 无对应字段，无法转换                                     |
| dae `ext:"file.dat:tag"` 自定义 geo 文件 | sing-box 使用不同机制（remote/local rule_set），不支持直接转换    |

### dae -> sing-box 额外局限

- group 复杂 filter：仅支持 `name()` / `!name()` 的正则和精确匹配，不支持 `subtag()` 等过滤方式
- DNS response 规则：dae 的 response routing（如 `upstream(X) -> accept`）仅部分可映射
- dae global 中大量内核/BPF 参数（`tproxy_port_protect`、`bpf_conn_state_map_size`、`auto_config_kernel_parameter` 等）在 sing-box 中无对应概念
- dae 的 `dial_mode`、`sniffing_timeout`、`mptcp` 等拨号行为参数与 sing-box 模型不同，不参与转换
- dae `bandwidth_max_tx/rx` 为 hysteria2 专用，sing-box hysteria2 已移除 bandwidth 字段

### sing-box -> dae 额外局限

- sing-box inbound 配置（mixed/tun/socks/http 等）不参与转换（dae 使用 eBPF tproxy，无 inbound 概念）
- sing-box `experimental`（cache_file/clash_api/v2ray_api）不参与转换
- sing-box `ntp`、`certificate`、`services`、`endpoints` 段不参与转换
- DNS server type=local/hosts/fakeip/dhcp/tailscale/resolved 不会参与转换（仅 udp/tcp/tls/https/quic/h3 转 dae upstream）
- route 的 sniff / hijack-dns / resolve action 规则被跳过（dae 自身处理 DNS 劫持）
- clash_mode 规则不参与转换
- sing-box TLS 高级字段（reality/ech/certificate/acme/fragment 等）无节点链接对应，无法通过链接格式转换
- sing-box V2Ray transport（ws/grpc/httpupgrade/quic）、multiplex 无节点链接对应，转换后丢失
- 非 `geoip-/geosite-` 前缀的 rule_set 无法表达为 dae 语法
- sing-box `protocol` 嗅探匹配（`protocol: ["bittorrent"]` 等）dae 无对应
- sing-box `source_port_range`、`port_range` 的范围语法（如 `1000-2000`）可转 dae `dport(1000-2000)`，但 dae 对范围支持依赖版本

## 作为 lib 使用

你也可以使用 sing-dae 作为 Rust lib 依赖。

在 Cargo.toml 中加入：

```toml
[dependencies]
sing-dae = { version = "0.1.1" }
```

## 附录

### 已覆盖路由条件函数

<!-- prettier-ignore -->
| dae 函数 | sing-box 字段 | dae→sing | sing→dae |
| -------- | ------------ | -------- | -------- |
| `domain(suffix/plain)` | `domain_suffix` | ✓ | ✓ |
| `domain(full:)` | `domain` | ✓ | ✓ |
| `domain(keyword:)` | `domain_keyword` | ✓ | ✓ |
| `domain(regex:)` | `domain_regex` | ✓ | ✓ |
| `domain(geosite:)` | `rule_set` (geosite-) | ✓ | ✓ |
| `dip()` / `ip()` (CIDR) | `ip_cidr` | ✓ | ✓ |
| `dip(geoip:private)` | `ip_is_private` | ✓ | ✓ |
| `dip(geoip:xxx)` | `rule_set` (geoip-) | ✓ | ✓ |
| `sip()` | `source_ip_cidr` / `source_ip_is_private` | ✓ | ✓ |
| `pname()` | `process_name` | ✓ | ✓ |
| `l4proto()` | `network` | ✓ | ✓ |
| `dport()` / `port()` | `port` / `port_range` | ✓ | ✓ |
| `sport()` | `source_port` / `source_port_range` | ✓ | ✓ |
| `ipversion()` | `ip_version` | ✓ | ✓ |
| `qname(...)` | DNS `domain*` 字段 | ✓ | ✓ |
| `qtype(...)` | DNS `query_type` | ✓ | ✓ |
| `&&` 多条件组合 | 同一规则多字段 (AND) | ✓ | ✓ |
