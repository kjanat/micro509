import { defineConfig } from "tsdown";

export default defineConfig({
	entry: ["src/index.ts"],
	format: ["esm"],
	dts: true,
	clean: true,
	platform: "browser",
	target: "es2023",
	sourcemap: false,
	tsconfig: "tsconfig.base.json",
	exports: { devExports: true, enabled: true },
	onSuccess: "bunx sort-package-json --quiet package.json",
	attw: { profile: "esm-only", ignoreRules: ["no-resolution"] },
	unused: true,
	publint: true,
});
