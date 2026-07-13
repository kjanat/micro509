/**
 * VitePress markdown rule: relative links to repository files point at the repo.
 *
 * A page linking `../src/x509/parse.ts` means the source file, not a docs page —
 * VitePress would call it a dead link. Rewrite it to a blob URL on the ref being
 * built, so it resolves to the code as it stood.
 *
 * Page links (`.md`, `.html`), absolute paths and external URLs are left alone.
 *
 * The repository URL and the ref are arguments: this does not shell `git`, read
 * a manifest, or guess a branch from the environment. What the caller knows, the
 * caller passes.
 *
 * @module
 */
import path from 'node:path';
import type { MarkdownRenderer } from 'vitepress';

export interface GithubLinksOptions {
	/** Repository web URL, e.g. `https://github.com/owner/repo`. */
	readonly repoUrl: string;
	/** Branch, tag or sha the links point at. */
	readonly ref: string;
}

/** Install the rule on a VitePress markdown renderer. */
export function githubLinks(options: GithubLinksOptions): (md: MarkdownRenderer) => void {
	return (md) => {
		const previous =
			md.renderer.rules.link_open ??
			((tokens, idx, opts, _env, self) => self.renderToken(tokens, idx, opts));

		md.renderer.rules.link_open = (tokens, idx, opts, env, self) => {
			const token = tokens[idx];
			const href = token?.attrGet('href');
			const page: string = env.relativePath ?? '';
			if (token === undefined || href === null || href === undefined) {
				return previous(tokens, idx, opts, env, self);
			}

			// `?query`/`#fragment` are not part of the path: `keys.md#generate` is a
			// page link, and whatever follows a repository path must survive rewriting.
			const [, location = '', suffix = ''] = /^([^?#]*)([?#].*)?$/.exec(href) ?? [];

			const isRepositoryFile =
				location !== '' &&
				!location.startsWith('/') &&
				!location.startsWith('//') &&
				// Any scheme — http(s), but also mailto, tel, data, ftp.
				!/^[a-z][a-z0-9+.-]*:/i.test(location) &&
				!/\.(?:md|html)$/i.test(location);

			if (isRepositoryFile) {
				const target = path.posix.normalize(path.posix.join(path.posix.dirname(page), location));
				const kind = target.endsWith('/') ? 'tree' : 'blob';
				token.attrSet('href', `${options.repoUrl}/${kind}/${options.ref}/${target}${suffix}`);
			}
			return previous(tokens, idx, opts, env, self);
		};
	};
}
