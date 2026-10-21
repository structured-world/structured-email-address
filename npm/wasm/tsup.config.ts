import { defineConfig } from "tsup";

// Dual ESM + CJS with declarations for both. The wasm-bindgen glue is bundled
// in; the base64 module (./wasm-data.cjs) is forced external, so one copy
// ships in dist and both entries load it.
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  outDir: "dist",
  target: "es2021",
  platform: "neutral",
  sourcemap: false,
  treeshake: true,
  esbuildPlugins: [
    {
      name: "external-wasm-data",
      setup(build) {
        build.onResolve({ filter: /wasm-data\.cjs$/ }, () => ({ path: "./wasm-data.cjs", external: true }));
      },
    },
  ],
});
