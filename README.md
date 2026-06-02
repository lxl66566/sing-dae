# sing-dae

sing-box (JSON/JSONC) 与 dae (DSL) 配置格式的双向转换工具。

在线使用: https://lxl66566.github.io/sing-dae/

## 功能

- dae -> sing-box: 解析 dae DSL，转换为 sing-box JSON 配置
- sing-box -> dae: 解析 sing-box JSON/JSONC，转换为 dae DSL
- 支持节点链接（hy2、trojan、vmess、vless、shadowsocks）、DNS、路由规则、策略组转换
- 编译为 WASM，web 端运行，不进行任何配置上传
- 支持解析 JSONC 格式的 sing-box 配置（含注释和尾逗号）

## 自动补充的默认配置

转换后的配置可直接使用，以下默认值会自动添加：

### dae -> sing-box 自动补充

<!-- prettier-ignore -->
| 配置项 | 默认值 | 说明 |
| ------ | ------ | ---- |
| inbounds | `mixed` 入站，监听 `127.0.0.1:1080` | sing-box 必需的入站配置 |
| experimental.cache_file | `enabled: true, store_fakeip: true` | DNS 缓存，推荐启用 |
| route.rule_set | 根据规则中引用的 geosite/geoip 自动生成 | 使用 SagerNet 远程规则集 |

### sing-box -> dae 自动补充

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

## 开发

```sh
# 编译 WASM
cargo build --release --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/release/sing_dae.wasm --out-dir frontend/pkg --target web

# 前端
cd frontend
pnpm run build
```
