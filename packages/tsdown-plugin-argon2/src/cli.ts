import { fileURLToPath } from 'node:url';
import { CLIError, cli, command, flag } from '@kjanat/dreamcli';
import { buildArgon2 } from './build.ts';

const build = command('build')
	.description('Build the Argon2 WASM artifacts')
	.flag('force', flag.boolean().describe('Force recompilation'))
	.flag('check', flag.boolean().describe('Verify reproducibility without writing artifacts'))
	.derive(({ flags }) => {
		if (flags.force && flags.check) {
			throw new CLIError('--force and --check are mutually exclusive', {
				code: 'CONFLICTING_FLAGS',
			});
		}
	})
	.action(async ({ flags, out }) => {
		const mode = flags.check ? 'check' : flags.force ? 'force' : 'ensure';
		const root = fileURLToPath(new URL('../../../', import.meta.url));
		const result = await buildArgon2(root, { mode });
		const action = mode === 'check' ? 'verified' : result.rebuilt ? 'rebuilt' : 'up to date';
		if (out.jsonMode) out.json({ action, digest: result.digest });
		else out.log(`Argon2 ${action}: ${result.digest}`);
	});

await cli('build:argon2').default(build).run();
