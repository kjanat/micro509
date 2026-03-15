<!--
	LiveCode — run code examples in the browser.

	The page's import map (derived from package.json exports, injected via
	transformHtml in config.ts) resolves bare `micro509` specifiers through
	esm.sh, so code runs exactly as written — no URL rewriting.

	Usage in markdown:

	  <LiveCode>
	  ```ts
	  import { createSelfSignedCertificate } from 'micro509';
	  const { certificate } = await createSelfSignedCertificate({ ... });
	  console.log(certificate.pem);
	  ```
	  </LiveCode>
-->
<script setup lang="ts">
import { nextTick, onMounted, ref } from 'vue';

const props = withDefaults(
	defineProps<{
		/** Auto-run on mount */
		auto?: boolean;
	}>(),
	{ auto: false },
);

const el = ref<HTMLElement>();
const logs = ref<string[]>([]);
const err = ref<string>();
const busy = ref(false);
const ran = ref(false);

/** Extract raw text from the Shiki-rendered code element in the slot. */
function extractCode(): string {
	return el.value?.querySelector('pre code')?.textContent?.trim() ?? '';
}

/**
 * Split source into import declarations and body.
 * Imports must stay at module top-level (can't be inside try/catch).
 */
function splitCode(src: string): { head: string; body: string } {
	const lines = src.split('\n');
	const head: string[] = [];
	const body: string[] = [];
	let importing = false;
	let pastImports = false;

	for (const line of lines) {
		if (pastImports) {
			body.push(line);
			continue;
		}
		if (importing) {
			head.push(line);
			if (/from\s+['"]/.test(line)) importing = false;
			continue;
		}
		const t = line.trim();
		if (t === '' || t.startsWith('//')) {
			head.push(line);
			continue;
		}
		if (/^import[\s{]/.test(t)) {
			head.push(line);
			if (!/from\s+['"]/.test(t)) importing = true;
			continue;
		}
		pastImports = true;
		body.push(line);
	}

	return { head: head.join('\n'), body: body.join('\n') };
}

const TIMEOUT = 30_000;

async function run() {
	busy.value = true;
	ran.value = true;

	try {
		const raw = extractCode();
		if (!raw) throw new Error('No code found');

		const { head, body } = splitCode(raw);
		const eid = `__lc${Date.now()}${Math.random().toString(36).slice(2)}`;

		const src = `${head}
			const __out = [];
			const console = Object.create(globalThis.console, {
			  log: { value: (...a) => {
			    globalThis.console.log(...a);
			    __out.push(a.map(v => typeof v === 'string' ? v : JSON.stringify(v, null, 2) ?? String(v)).join(' '));
			  }},
			});
			try {
			${body}
			} catch (__e) {
			  __out.push('Error: ' + (__e instanceof Error ? __e.message : String(__e)));
			}
			window.dispatchEvent(new CustomEvent('${eid}', { detail: __out }));
			`;

		const result = await new Promise<string[]>((resolve, reject) => {
			const script = document.createElement('script');
			const timer = setTimeout(() => {
				script.remove();
				reject(new Error('Execution timed out'));
			}, TIMEOUT);

			const cleanup = () => {
				clearTimeout(timer);
				script.remove();
			};

			window.addEventListener(
				eid,
				((e: CustomEvent) => {
					cleanup();
					resolve(e.detail);
				}) as EventListener,
				{ once: true },
			);

			script.addEventListener(
				'error',
				() => {
					cleanup();
					reject(new Error('Failed to load module'));
				},
				{ once: true },
			);

			script.type = 'module';
			script.textContent = src;
			document.body.appendChild(script);
		});

		err.value = undefined;
		logs.value = result;
	} catch (e) {
		logs.value = [];
		err.value = e instanceof Error ? e.message : String(e);
	} finally {
		busy.value = false;
	}
}

onMounted(() => {
	if (props.auto) nextTick(run);
});
</script>

<template>
	<div ref="el" class="live-code">
		<slot />
		<div class="live-code-bar">
			<button class="live-code-btn" :disabled="busy" @click="run">
				{{ busy ? 'Running\u2026' : ran ? '\u25B6 Run again' : '\u25B6 Run' }}
			</button>
		</div>
		<div v-if="ran" class="live-code-output">
			<div class="live-code-label">
				Output
				<button
					v-if="!busy"
					class="live-code-close"
					title="Clear output"
					@click="ran = false; logs = []; err = undefined"
				>&times;</button>
			</div>
			<pre v-if="err" class="live-code-pre live-code-err">{{ err }}</pre>
			<pre v-else-if="logs.length" class="live-code-pre">{{ logs.join('\n') }}</pre>
			<pre v-else class="live-code-pre live-code-empty">(no output)</pre>
		</div>
	</div>
</template>

<style scoped>
	.live-code {
		margin: 16px 0;
	}

	.live-code-bar {
		display: flex;
		justify-content: flex-end;
		margin-top: -4px;
		margin-bottom: 8px;
	}

	.live-code-btn {
		padding: 4px 16px;
		font-size: 13px;
		font-weight: 500;
		font-family: var(--vp-font-family-base);
		color: var(--vp-c-brand-1);
		background: var(--vp-c-bg-soft);
		border: 1px solid var(--vp-c-divider);
		border-radius: 6px;
		cursor: pointer;
		transition: background 0.2s, border-color 0.2s;
		user-select: none;
	}

	.live-code-btn:hover:not(:disabled) {
		background: var(--vp-c-brand-soft);
		border-color: var(--vp-c-brand-1);
	}

	.live-code-btn:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.live-code-output {
		border: 1px solid var(--vp-c-divider);
		border-radius: 8px;
		overflow: hidden;
		margin-bottom: 16px;
	}

	.live-code-label {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 6px 16px;
		font-size: 12px;
		font-weight: 600;
		color: var(--vp-c-text-2);
		background: var(--vp-c-bg-soft);
		border-bottom: 1px solid var(--vp-c-divider);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.live-code-close {
		padding: 0 4px;
		font-size: 16px;
		line-height: 1;
		color: var(--vp-c-text-3);
		background: none;
		border: none;
		cursor: pointer;
		transition: color 0.15s;
	}

	.live-code-close:hover {
		color: var(--vp-c-text-1);
	}

	.live-code-pre {
		margin: 0;
		padding: 12px 16px;
		font-size: 13px;
		line-height: 1.6;
		white-space: pre-wrap;
		word-break: break-all;
		overflow-y: auto;
		max-height: 400px;
		background: var(--vp-code-block-bg);
	}

	.live-code-err {
		color: var(--vp-c-danger-1);
	}

	.live-code-empty {
		color: var(--vp-c-text-3);
		font-style: italic;
	}
</style>
