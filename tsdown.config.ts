import { defineConfig } from "tsdown";

export default defineConfig({
	entry: "src/index.ts",
	format: ["esm"],
	dts: { oxc: true },
	clean: true,
	platform: "neutral",
	target: "es2023",
	tsconfig: "tsconfig.base.json",
	sourcemap: false,
	unbundle: false,
	inputOptions: {
		resolve: {
			mainFields: ["browser", "module", "main"],
		},
	},
	exports: true,
	onSuccess: "bunx sort-package-json --quiet package.json",
	attw: { profile: "esm-only", ignoreRules: ["no-resolution"] },
	unused: true,
	publint: true,
});
