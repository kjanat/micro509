#!/usr/bin/env bun
/**
 * Assembles the deployable docs tree from per-version builds.
 *
 * Channel model: the domain root serves the latest stable npm release,
 * `/next/` serves a fresh build of the checked-out HEAD, and `/vX.Y/`
 * serves archived minors. Release builds are made exactly once — by the
 * `docs-assets` job in publish.yml, which attaches `docs-root.tar.gz` and
 * `docs-vX.Y.tar.gz` to each stable GitHub Release — and this script only
 * downloads and composes those frozen tarballs. Nothing is ever rebuilt for
 * a version that already shipped.
 *
 * Wired in as `bun run site:build`, so Cloudflare Workers Builds runs it
 * unchanged on every master push; the release workflow additionally POSTs a
 * deploy hook so the root flips as soon as a release's tarballs exist.
 *
 * Modes:
 * - default: HEAD build → /next/; latest release tarball → root; up to
 *   `--keep` superseded minors → /vX.Y/; manifest → /versions.json.
 * - bootstrap (no docs-bearing release, or releases API unreachable):
 *   HEAD build also serves as the root — today's single-site behavior.
 * - `--offline`: skip the releases API entirely (local verification).
 *
 * @module
 */
import pkg from '#pkg' with { type: 'json' };
import { cp, mkdir, mkdtemp, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const root = path.resolve(import.meta.dir, '..');
const siteDir = path.join(root, 'site/.vitepress');
const buildOutput = path.join(siteDir, 'dist');

const args = process.argv.slice(2);
const offline = args.includes('--offline');
const outDir = path.resolve(root, argValue('--out') ?? 'site/.vitepress/dist');
const keepMinors = Number(argValue('--keep') ?? '2');
if (!Number.isInteger(keepMinors) || keepMinors < 0) {
	console.error(`--keep must be a non-negative integer`);
	process.exit(1);
}

/** GitHub `owner/repo` slug derived from package.json. */
const repoSlug = (() => {
	const url = pkg.repository.url.replace('git+', '').replace(/\.git$/, '');
	const slug = url.match(/github\.com[:/](.+\/.+?)$/)?.[1];
	if (slug === undefined) throw new Error(`Cannot derive GitHub slug from ${url}`);
	return slug;
})();

interface ReleaseAsset {
	readonly name: string;
	readonly browser_download_url: string;
}

interface Release {
	readonly tag_name: string;
	readonly draft: boolean;
	readonly prerelease: boolean;
	readonly assets: readonly ReleaseAsset[];
}

/** A stable release carrying frozen docs tarballs. */
interface DocsRelease {
	readonly version: readonly [number, number, number];
	readonly tag: string;
	readonly rootAsset: string;
	readonly archiveAsset: string | undefined;
}

interface VersionEntry {
	readonly label: string;
	readonly base: string;
}

function argValue(flag: string): string | undefined {
	const index = args.indexOf(flag);
	return index === -1 ? undefined : args[index + 1];
}

/** Run the single-flavor site build (examples gate + vitepress) for one channel. */
function buildFlavor(env: {
	readonly DOCS_BASE: string;
	readonly DOCS_CHANNEL: string;
	readonly DOCS_VERSION: string;
}): void {
	console.log(`build flavor: base=${env.DOCS_BASE} channel=${env.DOCS_CHANNEL}`);
	const result = Bun.spawnSync(['bun', 'run', 'build'], {
		cwd: siteDir,
		env: { ...process.env, ...env },
		stdout: 'inherit',
		stderr: 'inherit',
	});
	if (result.exitCode !== 0) {
		throw new Error(`site build failed for ${env.DOCS_BASE}`);
	}
}

function parseStableVersion(tag: string): readonly [number, number, number] | undefined {
	const match = tag.match(/^v(\d+)\.(\d+)\.(\d+)$/);
	if (!match) return undefined;
	return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function compareVersions(
	a: readonly [number, number, number],
	b: readonly [number, number, number],
): number {
	return a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
}

/** Stable releases with docs tarballs, newest first; [] on API failure. */
async function fetchDocsReleases(): Promise<readonly DocsRelease[]> {
	const headers: Record<string, string> = {
		accept: 'application/vnd.github+json',
		'user-agent': `${pkg.name}-site-assembly`,
	};
	const token = process.env.GITHUB_TOKEN;
	if (token !== undefined && token !== '') {
		headers.authorization = `Bearer ${token}`;
	}
	let releases: readonly Release[];
	try {
		const response = await fetch(`https://api.github.com/repos/${repoSlug}/releases?per_page=100`, {
			headers,
		});
		if (!response.ok) {
			console.warn(`releases API returned ${response.status}; falling back to bootstrap root`);
			return [];
		}
		releases = await response.json();
	} catch (error) {
		console.warn(`releases API unreachable (${String(error)}); falling back to bootstrap root`);
		return [];
	}
	return releases
		.flatMap((release): DocsRelease[] => {
			if (release.draft || release.prerelease) return [];
			const version = parseStableVersion(release.tag_name);
			if (version === undefined) return [];
			const rootAsset = release.assets.find((asset) => asset.name === 'docs-root.tar.gz');
			if (rootAsset === undefined) return [];
			const archiveName = `docs-v${version[0]}.${version[1]}.tar.gz`;
			const archiveAsset = release.assets.find((asset) => asset.name === archiveName);
			return [
				{
					version,
					tag: release.tag_name,
					rootAsset: rootAsset.browser_download_url,
					archiveAsset: archiveAsset?.browser_download_url,
				},
			];
		})
		.sort((a, b) => compareVersions(b.version, a.version));
}

/** Download a tarball and extract it into `destination`. */
async function extractTarball(url: string, destination: string): Promise<void> {
	console.log(`fetch ${url}`);
	const response = await fetch(url);
	if (!response.ok) {
		throw new Error(`download failed (${response.status}): ${url}`);
	}
	const tarball = path.join(await mkdtemp(path.join(tmpdir(), 'docs-tar-')), 'docs.tar.gz');
	await Bun.write(tarball, await response.arrayBuffer());
	await mkdir(destination, { recursive: true });
	const result = Bun.spawnSync(['tar', '-xzf', tarball, '-C', destination], {
		stdout: 'inherit',
		stderr: 'inherit',
	});
	await rm(path.dirname(tarball), { recursive: true, force: true });
	if (result.exitCode !== 0) {
		throw new Error(`tar extraction failed for ${url}`);
	}
}

/** Move the freshly written vitepress output into a staging directory. */
async function stashBuild(name: string): Promise<string> {
	const staged = path.join(await mkdtemp(path.join(tmpdir(), 'docs-stage-')), name);
	await rename(buildOutput, staged).catch(async () => {
		// Cross-device fallback (tmpdir on another filesystem).
		await cp(buildOutput, staged, { recursive: true });
		await rm(buildOutput, { recursive: true, force: true });
	});
	return staged;
}

async function countFiles(dir: string): Promise<number> {
	let count = 0;
	for await (const _ of new Bun.Glob('**/*').scan({ cwd: dir, onlyFiles: true })) {
		count += 1;
	}
	return count;
}

/** Short commit hash for the /next/ manifest entry. */
function headCommit(): string {
	for (const name of ['MICRO509_GIT_COMMIT', 'WORKERS_CI_COMMIT_SHA', 'GITHUB_SHA']) {
		const value = process.env[name]?.trim();
		if (value === undefined || value === '') continue;
		if (/^[0-9a-f]{7,40}$/i.test(value)) return value.slice(0, 7);
		// Loudly reject shape mismatches (e.g. a branch name in a sha slot) so
		// a misconfigured build variable shows up in logs, not in production.
		console.warn(`${name}='${value}' is not a commit sha; ignoring`);
	}
	const result = Bun.spawnSync(['git', 'rev-parse', '--short', 'HEAD'], { cwd: root });
	return result.exitCode === 0 ? result.stdout.toString().trim() : 'unknown';
}

// ── Assembly ──────────────────────────────────────────────────────────────

// 1. Build /next/ from HEAD and stash it out of the way.
buildFlavor({ DOCS_BASE: '/next/', DOCS_CHANNEL: 'next', DOCS_VERSION: 'next' });
const nextBuild = await stashBuild('next');

// 2. Resolve the frozen release builds.
const releases = offline ? [] : await fetchDocsReleases();
const latest = releases[0];

// 3. Root: latest release tarball, or a bootstrap HEAD build when none exists.
let bootstrapRoot: string | undefined;
if (latest === undefined) {
	console.log(
		offline ? 'offline mode: HEAD build as root' : 'no docs-bearing release: HEAD build as root',
	);
	buildFlavor({ DOCS_BASE: '/', DOCS_CHANNEL: 'latest', DOCS_VERSION: `v${pkg.version}` });
	bootstrapRoot = await stashBuild('bootstrap-root');
}

await rm(outDir, { recursive: true, force: true });
await mkdir(outDir, { recursive: true });
if (latest !== undefined) {
	await extractTarball(latest.rootAsset, outDir);
} else if (bootstrapRoot !== undefined) {
	await cp(bootstrapRoot, outDir, { recursive: true });
	await rm(path.dirname(bootstrapRoot), { recursive: true, force: true });
}

// 4. Archives: newest patch per superseded minor, capped at --keep.
const archived: VersionEntry[] = [];
if (latest !== undefined) {
	const seenMinors = new Set<string>([`${latest.version[0]}.${latest.version[1]}`]);
	for (const release of releases.slice(1)) {
		const minor = `${release.version[0]}.${release.version[1]}`;
		if (seenMinors.has(minor)) continue;
		seenMinors.add(minor);
		if (archived.length >= keepMinors) continue;
		if (release.archiveAsset === undefined) {
			console.warn(`release ${release.tag} has no archive-flavor tarball; skipping /v${minor}/`);
			continue;
		}
		await extractTarball(release.archiveAsset, path.join(outDir, `v${minor}`));
		archived.push({ label: `v${minor}`, base: `/v${minor}/` });
	}
}

// 5. Attach /next/ and write the manifest the version switcher fetches.
await cp(nextBuild, path.join(outDir, 'next'), { recursive: true });
await rm(path.dirname(nextBuild), { recursive: true, force: true });

const manifest = {
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	latest:
		latest === undefined ? null : { label: latest.tag, version: latest.tag.slice(1), base: '/' },
	next: { label: 'next', commit: headCommit(), base: '/next/' },
	archived,
};
await writeFile(path.join(outDir, 'versions.json'), `${JSON.stringify(manifest, null, '\t')}\n`);

// 6. Guardrail against the 20k-file Workers assets ceiling.
const totalFiles = await countFiles(outDir);
console.log(
	`assembled ${totalFiles} files: root=${manifest.latest?.label ?? `HEAD (v${pkg.version})`}, next=${manifest.next.commit}, archived=[${archived.map((entry) => entry.label).join(', ')}]`,
);
if (totalFiles > 19_500) {
	console.error(`file count ${totalFiles} exceeds the Workers assets safety ceiling (19500)`);
	process.exit(1);
}
if (totalFiles > 16_000) {
	console.warn(`file count ${totalFiles} approaching the 20k Workers assets limit`);
}
