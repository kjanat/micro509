/**
 * Cloudflare Worker entry for the workerd smoke test (see ./smoke-workerd.mjs).
 * Imports src (not dist) so typecheck passes on a clean tree;
 * wrangler bundles the TS source, and the point here is exercising workerd's own WebCrypto.
 * dist-artifact integrity is covered by the Node/Deno/browser smokes.
 * @module
 */

import * as micro509 from '#micro509';
import * as cryptoApi from '#micro509/crypto';
import * as kdfApi from '#micro509/kdf';
import * as sshApi from '#micro509/ssh';
import { runSmoke } from '#smoke';

export default {
	async fetch() {
		try {
			return new Response(await runSmoke(micro509, cryptoApi, kdfApi, sshApi));
		} catch (e) {
			console.error('smoke-worker fetch failed', e);
			return new Response('smoke failed', { status: 500 });
		}
	},
};
