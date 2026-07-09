import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/cli.ts"],
  format: ["esm"],
  target: "node18",
  platform: "node",
  clean: true,
  sourcemap: false,
  dts: false,
  // The shebang in src/cli.ts is preserved by esbuild so dist/cli.js is directly
  // executable as the `tripwire` bin.
});
