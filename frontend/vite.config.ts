import { defineConfig } from "vite";
import solidPlugin from "vite-plugin-solid";
import UnoCSS from "unocss/vite";

export default defineConfig({
  plugins: [UnoCSS(), solidPlugin()],
  server: {
    open: true,
  },
  build: {
    target: "esnext",
  },
  optimizeDeps: {
    exclude: ["sing-dae"],
  },
});
