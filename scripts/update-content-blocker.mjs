#!/usr/bin/env node
/** Refresh exact upstream snapshots from a local uAssets checkout and commit. */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const [checkout, revision] = process.argv.slice(2);
if (!checkout || !revision || !/^[a-f0-9]{40}$/.test(revision)) {
	throw new Error('Usage: node scripts/update-content-blocker.mjs UASSETS_CHECKOUT COMMIT_SHA');
}
const sources = [
	{ file: 'easyprivacy.txt', source: 'thirdparties/easylist/easyprivacy.txt' },
	{ file: 'ublock-privacy.txt', source: 'filters/privacy.txt' },
];
const suffixSource = 'thirdparties/publicsuffix.org/list/effective_tld_names.dat';
const suffixes = execFileSync('git', ['-C', checkout, 'show', `${revision}:${suffixSource}`], {
	maxBuffer: 2 * 1024 * 1024,
});
const publicSuffixList = {
	file: 'public-suffix-list.dat',
	source: suffixSource,
	sha256: createHash('sha256').update(suffixes).digest('hex'),
};
const directory = new URL('./fixtures/content-blocker/', import.meta.url);
// Read every source before writing, so a missing revision cannot partially update the snapshots.
const snapshots = sources.map(({ file, source }) => ({
	file,
	source,
	raw: execFileSync('git', ['-C', checkout, 'show', `${revision}:${source}`], {
		maxBuffer: 10 * 1024 * 1024,
	}),
}));
const license = execFileSync('git', ['-C', checkout, 'show', `${revision}:LICENSE`]);
const lists = snapshots.map(({ file, source, raw }) => ({
	file,
	source,
	sha256: createHash('sha256').update(raw).digest('hex'),
}));
for (const { file, raw } of snapshots) writeFileSync(new URL(file, directory), raw);
writeFileSync(new URL(publicSuffixList.file, directory), suffixes);
writeFileSync(new URL('LICENSE', directory), license);
writeFileSync(
	new URL('manifest.json', directory),
	`${JSON.stringify({ repository: 'https://github.com/uBlockOrigin/uAssets', revision, lists, publicSuffixList }, null, '\t')}\n`,
);
console.log(`Updated ${lists.length} content-blocker snapshots from ${revision}`);
