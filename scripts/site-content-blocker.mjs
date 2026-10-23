import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pslInit, StaticNetFilteringEngine } from '@gorhill/ubo-core';
import { CompiledListWriter } from '@gorhill/ubo-core/js/static-filtering-io.js';
import { utils } from '@gorhill/ubo-core/js/static-filtering-parser.js';
import manifest from './fixtures/content-blocker/manifest.json' with { type: 'json' };

/** @param {{file: string, sha256: string}} snapshot */
function readSnapshot({ file, sha256 }) {
	const raw = readFileSync(new URL(`./fixtures/content-blocker/${file}`, import.meta.url), 'utf8');
	if (createHash('sha256').update(raw).digest('hex') !== sha256) {
		throw new Error(`Content-blocker snapshot checksum mismatch: ${file}`);
	}
	return raw;
}
// uBO Core's serialized PSL is not revived as a Uint32Array in this release.
// Initialize from pinned source text so sibling hosts share their registered domain.
pslInit(readSnapshot(manifest.publicSuffixList));
const engine = await StaticNetFilteringEngine.create({ noPSL: true });
const compiler = engine.createCompiler();
const lists = manifest.lists.map((snapshot) => {
	const { file } = snapshot;
	const raw = readSnapshot(snapshot);
	/** @type {{type: string, text: string}[]} */
	const events = [];
	const compiled = engine.compileList(
		{ name: file, raw: utils.preparser.prune(raw, ['ublock', 'chromium', 'user_stylesheet']) },
		compiler,
		new CompiledListWriter(),
		{ events },
	);
	if (events.length > 0) {
		throw new Error(`Content-blocker compilation failed for ${file}: ${JSON.stringify(events)}`);
	}
	return { name: file, compiled };
});
await engine.useLists(lists);

/**
 * Match pinned EasyPrivacy and uBlock privacy network filters with uBO's engine.
 * The engine applies exceptions, request types and party/domain restrictions.
 * Cosmetic rules and response transformations are outside this request gate.
 * @param {string} url
 * @param {string} documentUrl
 * @param {string} [resourceType]
 * @returns {string | undefined}
 */
export function matchBlockedRequest(url, documentUrl, resourceType = 'script') {
	if (!/^https?:$/.test(new URL(url).protocol)) return undefined;
	const type =
		resourceType === 'xhr' || resourceType === 'fetch'
			? 'xmlhttprequest'
			: resourceType === 'document'
				? 'main_frame'
				: resourceType;
	if (engine.matchRequest({ url, originURL: documentUrl, type }) !== 1) return undefined;
	return engine.toLogData()?.raw ?? 'blocked by uBlock network engine';
}
