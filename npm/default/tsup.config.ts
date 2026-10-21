import { defineConfig } from "tsup";

// Dual ESM + CJS with declarations for both. The backends stay external
// dynamic imports, so a consumer's bundler loads only the one in use.
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
  // tsup externalizes `dependencies` but not `optionalDependencies`.
  external: ["@structured-world/structured-email-address-ts", "@structured-world/structured-email-address-wasm"],
});
