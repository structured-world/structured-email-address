import { defineConfig } from "tsup";

// Dual ESM + CJS with declarations for both. Dependencies stay external, so
// the PSL loader and tr46 are shared with anything else that installs them.
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  outDir: "dist",
  target: "es2022",
  // Runtime-agnostic output that keeps `node:` specifiers intact.
  platform: "neutral",
  sourcemap: false,
  treeshake: true,
  external: [/^node:/],
});
