/** The pinned uBO Core APIs used by the offline browser test harness. */
declare module '@gorhill/ubo-core' {
	export function pslInit(raw: string): object;
	export class StaticNetFilteringEngine {
		static create(options?: { noPSL: boolean }): Promise<StaticNetFilteringEngine>;
		static release(): Promise<void>;
		useLists(lists: readonly { name: string; raw?: string; compiled?: string }[]): Promise<void>;
		matchRequest(details: { url: string; originURL: string; type: string }): number;
		toLogData(): { raw: string } | undefined;
		createCompiler(): object;
		compileList(
			list: { name: string; raw: string },
			compiler: object,
			writer: object,
			options: { events: { type: string; text: string }[] },
		): string;
	}
}
declare module '@gorhill/ubo-core/js/static-filtering-parser.js' {
	export const utils: { preparser: { prune(raw: string, environment: string[]): string } };
}
declare module '@gorhill/ubo-core/js/static-filtering-io.js' {
	export class CompiledListWriter {}
}
