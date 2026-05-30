# sing-dae

sing-box (JSON) 与 dae (DSL) 配置格式的双向转换工具。

在线使用: https://lxl66566.github.io/sing-dae/

## 功能

- dae -> sing-box: 解析 dae DSL，转换为 sing-box JSON 配置
- sing-box -> dae: 解析 sing-box JSON，转换为 dae DSL
- 支持节点链接（hy2、trojan、vmess、vless、shadowsocks）、DNS、路由规则、策略组转换
- 编译为 WASM，web 端运行，不进行任何配置上传

## 转换局限性

### 两个方向共同的局限性

| 遗漏项                                  | 原因                                                            |
| --------------------------------------- | --------------------------------------------------------------- |
| 入站配置 (inbounds)                     | dae 使用 eBPF 透明代理，不存在入站概念；转换时不会生成          |
| subscription 订阅源                     | dae 内置订阅拉取，sing-box 无此概念，转换后 subscription 段为空 |
| experimental / clash_api / cache_file   | 无对应字段映射                                                  |
| chain node (链式节点如 `A -> B`)        | 转换时跳过，不受支持                                            |
| `&&` 多条件组合规则                     | 仅处理单一条件函数，组合条件被忽略                              |
| `l4proto()` / `dport()` 等端口/协议匹配 | dae 特有语法，sing-box 无直接对应                               |

### dae -> sing-box 额外局限

- route.rule_set 为空: 规则中引用了 geosite、geoip，但输出的 sing-box JSON 中 `route.rule_set` 为空，需要手动添加 rule_set 定义
- group 复杂 filter：仅支持 `name()` / `!name()` 的正则和精确匹配，不支持 `subtag()`、`keyword()` 等过滤方式
- DNS response 规则：dae 的 response routing（如 `upstream(X) -> accept`）无法被正确映射

### sing-box -> dae 额外局限

- DNS server type=local/hosts/fakeip 不会参与转换
- route 的 sniff / hijack-dns / resolve action 规则被跳过
- clash_mode 规则 不参与转换
- network / port / port_range 匹配 dae 不支持，转换后丢失
- rule_set 引用：非 `geoip-/geosite-` 前缀的 rule_set 无法表达为 dae 语法

## 转换后手动配置指引

### dae -> sing-box 后必须添加的配置

假设转换后得到如下的 JSON，请补充以下部分：

1. inbounds（必需） -- 至少添加一个 mixed 入站：

```json
{
  "inbounds": [
    {
      "type": "mixed",
      "tag": "socks",
      "listen": "127.0.0.1",
      "listen_port": 1080
    }
  ]
}
```

2. experimental（可选但推荐） -- 添加缓存：

```json
{
  "experimental": {
    "cache_file": {
      "enabled": true,
      "store_fakeip": true
    }
  }
}
```

### sing-box -> dae 后必须添加的配置

1. global 段 -- dae 必需的核心配置，如：

```
global {
    tproxy_port: 12345
    wan_interface: auto
    log_level: info
    tcp_check_url: 'http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111'
    udp_check_dns: 'dns.google.com:53,8.8.8.8,2001:4860:4860::8888'
    check_interval: 30s
    dial_mode: domain
    allow_insecure: false
}
```

2. routing fallback -- 检查 fallback 是否正确指向了有效的 group 名

3. DNS upstream -- 确认生成的 dns upstream 配置正确，尤其是端口号（转换时统一添加了 `:53`，可能与实际不符）

## 开发

```sh
# 编译 WASM
wasm-bindgen target/wasm32-unknown-unknown/release/sing_dae.wasm --out-dir frontend/pkg --target web

# 前端
cd frontend
pnpm run build
```
