import presetWind4, { type Theme } from "@unocss/preset-wind4";
import { defineConfig, type UserConfig } from "unocss";

export default defineConfig({
  presets: [presetWind4()],
}) satisfies UserConfig<Theme> as UserConfig<Theme>;
