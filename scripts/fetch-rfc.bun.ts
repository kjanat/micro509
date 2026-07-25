import { arg, CLIError, cli, command } from 'dreamcli';

const fetchRfc = command('rfc')
	.description('Refresh a vendored RFC text file from the RFC Editor')
	.arg('number', arg.number().int().min(1).env('RFC').describe('RFC number, e.g. 822'))
	.action(async ({ args, out }) => {
		const url = `https://www.rfc-editor.org/rfc/rfc${args.number}.txt`;
		out.status(`fetching ${url}`);
		const response = await fetch(url);
		if (!response.ok) {
			throw new CLIError(`rfc${args.number}: ${response.status} ${response.statusText}`, {
				code: 'RFC_FETCH_FAILED',
				suggest: 'Check the number against https://www.rfc-editor.org/',
			});
		}
		const destination = `docs/rfc/rfc${args.number}.txt`;
		await Bun.write(destination, await response.bytes());
		out.log(destination);
	});

cli('rfc').default(fetchRfc).run();
