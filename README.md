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
- sing-box -> dae: 解析 sing-box JSONC，转换为 dae DSL
- 支持节点链接、DNS、路由规则、策略组转换
  - 支持的协议：Shadowsocks | Vmess | Vless | Trojan | Hysteria2 | Tuic | AnyTLS
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

| 遗漏项                                  | 原因                                                            |
| --------------------------------------- | --------------------------------------------------------------- |
| subscription 订阅源                     | dae 内置订阅拉取，sing-box 无此概念，转换后 subscription 段为空 |
| chain node (链式节点如 `A -> B`)        | 转换时跳过，不受支持                                            |
| `&&` 多条件组合规则                     | 仅处理单一条件函数，组合条件被忽略                              |
| `l4proto()` / `dport()` 等端口/协议匹配 | dae 特有语法，sing-box 无直接对应                               |

### dae -> sing-box 额外局限

- group 复杂 filter：仅支持 `name()` / `!name()` 的正则和精确匹配，不支持 `subtag()`、`keyword()` 等过滤方式
- DNS response 规则：dae 的 response routing（如 `upstream(X) -> accept`）无法被正确映射

### sing-box -> dae 额外局限

- DNS server type=local/hosts/fakeip 不会参与转换
- route 的 sniff / hijack-dns / resolve action 规则被跳过
- clash_mode 规则不参与转换
- network / port / port_range 匹配 dae 不支持，转换后丢失
- rule_set 引用：非 `geoip-/geosite-` 前缀的 rule_set 无法表达为 dae 语法

## 作为 lib 使用

你也可以使用 sing-dae 作为 Rust lib 依赖。

在 Cargo.toml 中加入：

```toml
[dependencies]
sing-dae = { version = "0.1.1" }
```
