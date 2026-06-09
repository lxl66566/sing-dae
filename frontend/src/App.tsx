import { createSignal, onMount, type JSX } from "solid-js";
import { FaSolidArrowRight, FaSolidArrowLeft, FaSolidArrowDown, FaSolidArrowUp } from "solid-icons/fa";
import { Editor, type PrismEditor } from "solid-prism-editor";
import { basicSetup } from "solid-prism-editor/setups";
import "./prism";
import "solid-prism-editor/layout.css";
import "solid-prism-editor/themes/github-dark.css";
import "solid-prism-editor/scrollbar.css";
import "solid-prism-editor/search.css";
import init, { dae_to_singbox_with_opts, singbox_to_dae_with_opts } from "../pkg/sing_dae.js";

const EXAMPLE_DAE = `#{
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
    log_level: info
    wan_interface: auto
    tproxy_port: 12345
    dial_mode: domain
    allow_insecure: false
    tcp_check_url: 'http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111'
    udp_check_dns: 'dns.google.com:53,8.8.8.8,2001:4860:4860::8888'
    check_interval: 30s
    check_tolerance: 50ms
}
node {
    node-jp: 'hy2://change-me@jp.example.com:65533/?sni=jp.example.com#jp'
    node-us: 'trojan://change-me@us.example.com:443/?security=tls&sni=us.example.com#us'
    node-sg: 'vless://uuid@sg.example.com:443/?type=tcp&security=tls&sni=sg.example.com#sg'
}
group {
    proxy {
        filter: name(regex: 'node-jp|node-us')
        policy: min_moving_avg
    }
}
dns {
    upstream {
        alidns: 'udp://223.5.5.5:53'
        googledns: 'tcp+udp://dns.google.com:53'
    }
    routing {
        request {
            qname(geosite:cn) -> alidns
            qname(geosite:category-ads) -> reject
            fallback -> googledns
        }
    }
}
routing {
    dip(geoip:private) -> direct
    domain(geosite:cn) -> direct
    domain(geosite:google) -> proxy
    domain(geosite:category-ads) -> block
    pname(YourApp) -> must_direct
    fallback: proxy
}`;

const EXAMPLE_SING = JSON.stringify(
  {
    log: { level: "info", timestamp: true },
    inbounds: [
      {
        type: "mixed",
        tag: "mixed",
        listen: "127.0.0.1",
        listen_port: 1080,
      },
    ],
    outbounds: [
      {
        type: "hysteria2",
        tag: "node-jp",
        server: "jp.example.com",
        server_port: 65533,
        password: "change-me",
        tls: {
          enabled: true,
          server_name: "jp.example.com",
        },
      },
      {
        type: "trojan",
        tag: "node-us",
        server: "us.example.com",
        server_port: 443,
        password: "change-me",
        tls: {
          enabled: true,
          server_name: "us.example.com",
        },
      },
      {
        type: "vless",
        tag: "node-sg",
        server: "sg.example.com",
        server_port: 443,
        uuid: "uuid",
        tls: {
          enabled: true,
          server_name: "sg.example.com",
        },
      },
      {
        type: "direct",
        tag: "direct",
      },
      {
        type: "urltest",
        tag: "proxy",
        outbounds: ["node-jp", "node-us"],
      },
    ],
    dns: {
      servers: [
        {
          tag: "alidns",
          type: "udp",
          server: "223.5.5.5",
          server_port: 53,
        },
        {
          tag: "googledns",
          type: "udp",
          server: "dns.google.com",
          server_port: 53,
        },
      ],
      rules: [
        {
          server: "alidns",
          rule_set: ["geosite-cn"],
        },
        {
          action: "predefined",
          rule_set: ["geosite-category-ads"],
        },
      ],
      final: "googledns",
    },
    route: {
      rules: [
        { outbound: "direct", ip_is_private: true },
        { outbound: "direct", rule_set: ["geosite-cn"] },
        { outbound: "proxy", rule_set: ["geosite-google"] },
        { action: "reject", rule_set: ["geosite-category-ads"] },
        { outbound: "direct", process_name: ["YourApp"] },
      ],
      final: "proxy",
    },
  },
  null,
  2,
);

function setEditorValue(editor: PrismEditor | undefined, value: string) {
  if (!editor) return;
  editor.textarea.value = value;
  editor.update();
}

type StatusType = "info" | "success" | "error";

function App(): JSX.Element {
  const [status, setStatus] = createSignal("Loading WASM...");
  const [statusType, setStatusType] = createSignal<StatusType>("info");
  const [wasmReady, setWasmReady] = createSignal(false);
  const [copiedSide, setCopiedSide] = createSignal<"left" | "right" | null>(null);
  const [prerelease, setPrerelease] = createSignal(false);

  let leftEditor: PrismEditor | undefined;
  let rightEditor: PrismEditor | undefined;
  let copiedTimer: ReturnType<typeof setTimeout> | undefined;

  onMount(async () => {
    try {
      await init();
      setWasmReady(true);
      setStatus("Ready");
      setStatusType("info");
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      setStatus("WASM load failed: " + msg);
      setStatusType("error");
    }
  });

  function convertLeftToRight() {
    if (!leftEditor) return;
    const text = leftEditor.value.trim();
    if (!text) {
      setStatus("No dae content");
      setStatusType("error");
      return;
    }
    try {
      const result = dae_to_singbox_with_opts(text, prerelease());
      setEditorValue(rightEditor, result);
      setStatus("dae -> sing-box OK");
      setStatusType("success");
    } catch (e: unknown) {
      setStatus("Error: " + (e instanceof Error ? e.message : String(e)));
      setStatusType("error");
    }
  }

  function convertRightToLeft() {
    if (!rightEditor) return;
    const text = rightEditor.value.trim();
    if (!text) {
      setStatus("No sing-box content");
      setStatusType("error");
      return;
    }
    try {
      const result = singbox_to_dae_with_opts(text, prerelease());
      setEditorValue(leftEditor, result);
      setStatus("sing-box -> dae OK");
      setStatusType("success");
    } catch (e: unknown) {
      setStatus("Error: " + (e instanceof Error ? e.message : String(e)));
      setStatusType("error");
    }
  }

  async function copyText(side: "left" | "right") {
    const editor = side === "left" ? leftEditor : rightEditor;
    if (!editor || !editor.value) return;
    try {
      await navigator.clipboard.writeText(editor.value);
      setCopiedSide(side);
      clearTimeout(copiedTimer);
      copiedTimer = setTimeout(() => setCopiedSide(null), 1500);
      setStatus("Copied");
      setStatusType("success");
    } catch {
      setStatus("Copy failed");
      setStatusType("error");
    }
  }

  function loadExample() {
    setEditorValue(leftEditor, EXAMPLE_DAE);
    setEditorValue(rightEditor, EXAMPLE_SING);
    setStatus("Example loaded");
    setStatusType("info");
  }

  return (
    <div class="app-root">
      <header class="app-header">
        <h1 class="app-title">sing-dae</h1>
        <span class="app-subtitle">Config Converter</span>
        <label class="toggle-label" title="Enable sing-box 1.14+ pre-release features (e.g. http_clients)">
          <span class="toggle-text">Pre-release sing-box format</span>
          <button class={`toggle-switch${prerelease() ? " active" : ""}`} role="switch" aria-checked={prerelease()} onClick={() => setPrerelease((v) => !v)}>
            <span class="toggle-thumb" />
          </button>
        </label>
        <button class="btn-example" onClick={loadExample} disabled={!wasmReady()}>
          Example
        </button>
      </header>

      <main class="editor-grid">
        <section class="panel">
          <div class="panel-header">
            <span class="tag tag-dae">dae</span>
            <button class="btn-copy" onClick={() => copyText("left")}>
              {copiedSide() === "left" ? "Copied" : "Copy"}
            </button>
          </div>
          <div class="editor-wrap">
            <Editor
              language="dae"
              value={EXAMPLE_DAE}
              lineNumbers
              wordWrap
              tabSize={4}
              extensions={basicSetup}
              onMount={(e) => {
                leftEditor = e;
              }}
            />
          </div>
        </section>

        <div class="convert-col">
          <button class="btn-convert btn-down" onClick={convertLeftToRight} disabled={!wasmReady()} title="dae -> sing-box">
            <span class="arrow-desktop">
              <FaSolidArrowRight size={22} />
            </span>
            <span class="arrow-mobile">
              <FaSolidArrowDown size={22} />
            </span>
          </button>
          <button class="btn-convert btn-up" onClick={convertRightToLeft} disabled={!wasmReady()} title="sing-box -> dae">
            <span class="arrow-desktop">
              <FaSolidArrowLeft size={22} />
            </span>
            <span class="arrow-mobile">
              <FaSolidArrowUp size={22} />
            </span>
          </button>
        </div>

        <section class="panel">
          <div class="panel-header">
            <span class="tag tag-sing">sing-box</span>
            <button class="btn-copy" onClick={() => copyText("right")}>
              {copiedSide() === "right" ? "Copied" : "Copy"}
            </button>
          </div>
          <div class="editor-wrap">
            <Editor
              language="json"
              value=""
              lineNumbers
              wordWrap
              extensions={basicSetup}
              onMount={(e) => {
                rightEditor = e;
              }}
            />
          </div>
        </section>
      </main>

      <footer class="status-bar">
        <span class={`status-text status-${statusType()}`}>{status()}</span>
      </footer>

      <style>{`
        *, *::before, *::after {
          box-sizing: border-box;
        }

        html, body, #root {
          height: 100%;
          margin: 0;
        }

        body {
          background: #09090b;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans SC", sans-serif;
          font-size: 14px;
          color: #e4e4e7;
        }

        * {
          scrollbar-width: thin;
          scrollbar-color: #27272a transparent;
        }
        ::-webkit-scrollbar {
          width: 6px;
          height: 6px;
        }
        ::-webkit-scrollbar-track {
          background: transparent;
        }
        ::-webkit-scrollbar-thumb {
          background: #27272a;
          border-radius: 3px;
        }
        ::-webkit-scrollbar-thumb:hover {
          background: #3f3f46;
        }

        .app-root {
          display: flex;
          flex-direction: column;
          height: 100%;
        }

        .app-header {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 10px 24px;
          background: #111114;
          border-bottom: 1px solid #27272a;
        }

        .app-title {
          font-size: 15px;
          font-weight: 700;
          color: #fafafa;
          letter-spacing: -0.02em;
          margin: 0;
        }

        .app-subtitle {
          font-size: 13px;
          color: gray;
        }

        .btn-example {
          margin-left: auto;
          padding: 4px 14px;
          border-radius: 6px;
          border: 1px solid #27272a;
          background: #18181b;
          color: #a1a1aa;
          font-size: 13px;
          cursor: pointer;
          transition: all 0.15s;
        }
        .btn-example:hover:not(:disabled) {
          background: #27272a;
          color: #e4e4e7;
        }
        .btn-example:disabled {
          opacity: 0.3;
          cursor: not-allowed;
        }

        .toggle-label {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          margin-left: 8px;
          cursor: pointer;
          user-select: none;
        }
        .toggle-text {
          font-size: 12px;
          color: #71717a;
        }
        .toggle-switch {
          position: relative;
          width: 32px;
          height: 18px;
          border-radius: 9px;
          border: none;
          background: #27272a;
          cursor: pointer;
          padding: 0;
          transition: background 0.2s;
        }
        .toggle-switch.active {
          background: #4f46e5;
        }
        .toggle-thumb {
          position: absolute;
          top: 2px;
          left: 2px;
          width: 14px;
          height: 14px;
          border-radius: 50%;
          background: #a1a1aa;
          transition: transform 0.2s, background 0.2s;
        }
        .toggle-switch.active .toggle-thumb {
          transform: translateX(14px);
          background: #e4e4e7;
        }

        /* Desktop: side-by-side layout */
        .editor-grid {
          flex: 1;
          display: grid;
          grid-template-columns: 1fr auto 1fr;
          min-height: 0;
          overflow: hidden;
        }

        .panel {
          display: flex;
          flex-direction: column;
          min-height: 0;
          overflow: hidden;
          background: #0c0c0f;
        }

        .panel-header {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 8px 16px;
          background: #141418;
          border-bottom: 1px solid #27272a;
        }

        .tag {
          display: inline-block;
          padding: 2px 10px;
          border-radius: 4px;
          font-size: 11px;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }
        .tag-dae {
          background: #064e3b;
          color: #6ee7b7;
        }
        .tag-sing {
          background: #1e3a5f;
          color: #7dd3fc;
        }

        .btn-copy {
          margin-left: auto;
          padding: 3px 10px;
          border-radius: 4px;
          border: 1px solid #27272a;
          background: transparent;
          color: #71717a;
          font-size: 12px;
          cursor: pointer;
          transition: all 0.15s;
        }
        .btn-copy:hover {
          background: #18181b;
          color: #d4d4d8;
        }

        .editor-wrap {
          flex: 1;
          min-height: 0;
          overflow: hidden;
        }

        .editor-wrap .prism-code-editor {
          height: 100%;
          font-size: 14px !important;
          line-height: 1.65 !important;
          --padding-inline: 1.2em;
          --number-spacing: 1em;
        }

        .editor-wrap .prism-code-editor,
        .editor-wrap .prism-code-editor textarea {
          font-family: "JetBrains Mono", "Fira Code", "Cascadia Code", Consolas, monospace !important;
        }

        .convert-col {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          gap: 8px;
          padding: 0 10px;
          background: #09090b;
          border-left: 1px solid #1e1e22;
          border-right: 1px solid #1e1e22;
        }

        .btn-convert {
          width: 48px;
          height: 48px;
          border-radius: 12px;
          border: none;
          background: #4f46e5;
          color: white;
          font-size: 20px;
          font-weight: 600;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all 0.2s;
          box-shadow: 0 0 0 1px rgba(79, 70, 229, 0.4), 0 2px 8px rgba(79, 70, 229, 0.15);
        }
        .btn-convert:hover:not(:disabled) {
          background: #6366f1;
          transform: scale(1.08);
          box-shadow: 0 0 0 1px rgba(99, 102, 241, 0.5), 0 4px 16px rgba(99, 102, 241, 0.25);
        }
        .btn-convert:active:not(:disabled) {
          background: #4338ca;
          transform: scale(1.0);
        }
        .btn-convert:disabled {
          opacity: 0.25;
          cursor: not-allowed;
          box-shadow: none;
        }

        .arrow-mobile {
          display: none;
        }

        .status-bar {
          padding: 6px 24px;
          background: #111114;
          border-top: 1px solid #27272a;
          min-height: 28px;
          display: flex;
          align-items: center;
        }

        .status-text {
          font-size: 12px;
        }
        .status-info {
          color: #52525b;
        }
        .status-success {
          color: #4ade80;
        }
        .status-error {
          color: #f87171;
        }

        /* Mobile: vertical stacked layout */
        @media (max-width: 768px) {
          .app-root {
            height: auto;
            min-height: 100vh;
          }

          .editor-grid {
            flex: none;
            grid-template-columns: 1fr;
            grid-template-rows: auto auto auto;
            overflow: visible;
          }

          .panel {
            height: calc(100vh - 180px);
            min-height: 300px;
            overflow: hidden;
          }

          .editor-wrap {
            flex: 1;
            min-height: 0;
            overflow: auto;
          }

          .editor-wrap .prism-code-editor {
            height: 100%;
          }

          .convert-col {
            flex-direction: row;
            justify-content: center;
            gap: 16px;
            padding: 10px 0;
            border-left: none;
            border-right: none;
            border-top: 1px solid #1e1e22;
            border-bottom: 1px solid #1e1e22;
          }

          .arrow-desktop {
            display: none;
          }
          .arrow-mobile {
            display: inline-flex;
          }

          .status-bar {
            position: sticky;
            bottom: 0;
          }
        }
      `}</style>
    </div>
  );
}

export default App;
