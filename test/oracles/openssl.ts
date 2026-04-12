import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export interface OpenSslCommandResult {
	readonly exitCode: number;
	readonly stdout: string;
	readonly stderr: string;
}

export interface OpenSslPathValidationResult {
	readonly valid: boolean;
	readonly exitCode: number;
	readonly failureClass?: 'path_length' | 'name_constraints' | 'policy' | 'other';
	readonly output: string;
}

export interface OpenSslCrlStatusResult {
	readonly status: 'good' | 'revoked' | 'error';
	readonly exitCode: number;
	readonly output: string;
	readonly issuer?: string;
	readonly crlNumber?: number;
}

export interface OpenSslIdentityResult {
	readonly matches: boolean;
	readonly exitCode: number;
	readonly output: string;
}

export interface OpenSslOcspStatusResult {
	readonly accepted: boolean;
	readonly status?: 'good' | 'revoked' | 'unknown';
	readonly exitCode: number;
	readonly output: string;
	readonly responseDer: Uint8Array;
}

let cachedOpenSslAvailable: boolean | undefined;

export async function probeOpenSsl(): Promise<boolean> {
	if (cachedOpenSslAvailable !== undefined) {
		return cachedOpenSslAvailable;
	}
	const result = await runOpenSsl(['version']);
	cachedOpenSslAvailable = result.exitCode === 0;
	return cachedOpenSslAvailable;
}

export async function verifyChainWithOpenSsl(input: {
	readonly leafPem: string;
	readonly rootPem: string;
	readonly intermediatePems?: readonly string[];
	readonly at?: Date;
	readonly initialPolicySet?: readonly string[];
	readonly requireExplicitPolicy?: boolean;
	readonly inhibitPolicyMapping?: boolean;
	readonly inhibitAnyPolicy?: boolean;
}): Promise<OpenSslPathValidationResult> {
	return await withTempDir(async (directory) => {
		const leafPath = join(directory, 'leaf.pem');
		const rootPath = join(directory, 'root.pem');
		await Promise.all([
			writeFile(leafPath, input.leafPem, 'utf8'),
			writeFile(rootPath, input.rootPem, 'utf8'),
		]);

		const args = ['verify', '-trusted', rootPath, '-no-CApath', '-no-CAstore'];
		if (input.intermediatePems !== undefined && input.intermediatePems.length > 0) {
			const intermediatesPath = join(directory, 'intermediates.pem');
			await writeFile(intermediatesPath, input.intermediatePems.join('\n'), 'utf8');
			args.push('-untrusted', intermediatesPath);
		}
		if (input.at !== undefined) {
			args.push('-attime', String(Math.floor(input.at.getTime() / 1000)));
		}
		const shouldCheckPolicy =
			(input.initialPolicySet?.length ?? 0) > 0 ||
			input.requireExplicitPolicy === true ||
			input.inhibitPolicyMapping === true ||
			input.inhibitAnyPolicy === true;
		if (shouldCheckPolicy) {
			args.push('-policy_check');
			for (const policyOid of input.initialPolicySet ?? []) {
				args.push('-policy', policyOid);
			}
			if (input.requireExplicitPolicy === true) {
				args.push('-explicit_policy');
			}
			if (input.inhibitPolicyMapping === true) {
				args.push('-inhibit_map');
			}
			if (input.inhibitAnyPolicy === true) {
				args.push('-inhibit_any');
			}
		}
		args.push(leafPath);

		const result = await runOpenSsl(args);
		const output = mergeCommandOutput(result);
		return result.exitCode === 0
			? { valid: true, exitCode: result.exitCode, output }
			: {
					valid: false,
					exitCode: result.exitCode,
					failureClass: classifyVerifyFailure(output),
					output,
				};
	});
}

export async function checkRevocationWithOpenSsl(input: {
	readonly certificatePem: string;
	readonly issuerCertificatePem: string;
	readonly crlPem: string;
	readonly at?: Date;
}): Promise<OpenSslCrlStatusResult> {
	return await withTempDir(async (directory) => {
		const certificatePath = join(directory, 'certificate.pem');
		const issuerPath = join(directory, 'issuer.pem');
		const crlPath = join(directory, 'crl.pem');
		await Promise.all([
			writeFile(certificatePath, input.certificatePem, 'utf8'),
			writeFile(issuerPath, input.issuerCertificatePem, 'utf8'),
			writeFile(crlPath, input.crlPem, 'utf8'),
		]);

		const metadata = await runOpenSsl(['crl', '-in', crlPath, '-noout', '-crlnumber', '-issuer']);
		const verifyArgs = [
			'verify',
			'-trusted',
			issuerPath,
			'-CRLfile',
			crlPath,
			'-crl_check',
			'-no-CApath',
			'-no-CAstore',
		];
		if (input.at !== undefined) {
			verifyArgs.push('-attime', String(Math.floor(input.at.getTime() / 1000)));
		}
		verifyArgs.push(certificatePath);

		const verification = await runOpenSsl(verifyArgs);
		const output = mergeCommandOutput(verification);
		const metadataOutput = mergeCommandOutput(metadata);
		const lowerOutput = output.toLowerCase();
		const crlNumber = parseCrlNumber(metadataOutput);
		const issuer = parseCrlIssuer(metadataOutput);
		const metadataFields = {
			...(issuer === undefined ? {} : { issuer }),
			...(crlNumber === undefined ? {} : { crlNumber }),
		};
		if (verification.exitCode === 0) {
			return { status: 'good', exitCode: verification.exitCode, output, ...metadataFields };
		}
		if (lowerOutput.includes('certificate revoked')) {
			return { status: 'revoked', exitCode: verification.exitCode, output, ...metadataFields };
		}
		return { status: 'error', exitCode: verification.exitCode, output, ...metadataFields };
	});
}

export async function checkIdentityWithOpenSsl(input: {
	readonly certificatePem: string;
	readonly kind: 'dns' | 'ip';
	readonly value: string;
}): Promise<OpenSslIdentityResult> {
	return await withTempDir(async (directory) => {
		const certificatePath = join(directory, 'certificate.pem');
		await writeFile(certificatePath, input.certificatePem, 'utf8');
		const result = await runOpenSsl([
			'x509',
			'-in',
			certificatePath,
			'-noout',
			input.kind === 'dns' ? '-checkhost' : '-checkip',
			input.value,
		]);
		return {
			matches: result.exitCode === 0,
			exitCode: result.exitCode,
			output: mergeCommandOutput(result),
		};
	});
}

export async function issueAndValidateOcspResponseWithOpenSsl(input: {
	readonly issuerCertificatePem: string;
	readonly issuerPrivateKeyPem: string;
	readonly certificatePem: string;
	readonly certificateStatus: 'good' | 'revoked';
	readonly revocationTime?: Date;
}): Promise<OpenSslOcspStatusResult> {
	return await withTempDir(async (directory) => {
		const issuerPath = join(directory, 'issuer.pem');
		const issuerKeyPath = join(directory, 'issuer-key.pem');
		const certificatePath = join(directory, 'certificate.pem');
		const requestPath = join(directory, 'request.der');
		const responsePath = join(directory, 'response.der');
		const indexPath = join(directory, 'index.txt');
		await Promise.all([
			writeFile(issuerPath, input.issuerCertificatePem, 'utf8'),
			writeFile(issuerKeyPath, input.issuerPrivateKeyPem, 'utf8'),
			writeFile(certificatePath, input.certificatePem, 'utf8'),
		]);

		const requestResult = await runOpenSsl([
			'ocsp',
			'-issuer',
			issuerPath,
			'-cert',
			certificatePath,
			'-no_nonce',
			'-reqout',
			requestPath,
		]);
		if (requestResult.exitCode !== 0) {
			throw new Error(mergeCommandOutput(requestResult));
		}

		const serialResult = await runOpenSsl(['x509', '-in', certificatePath, '-noout', '-serial']);
		const subjectResult = await runOpenSsl([
			'x509',
			'-in',
			certificatePath,
			'-noout',
			'-subject',
			'-nameopt',
			'RFC2253',
		]);
		if (serialResult.exitCode !== 0 || subjectResult.exitCode !== 0) {
			throw new Error(`${mergeCommandOutput(serialResult)}\n${mergeCommandOutput(subjectResult)}`);
		}

		const serial = serialResult.stdout.trim().replace(/^serial=/, '');
		const subject = subjectResult.stdout.trim().replace(/^subject=/, '');
		const indexLine =
			input.certificateStatus === 'good'
				? `V\t351231235959Z\t\t${serial}\tunknown\t${subject}\n`
				: `R\t351231235959Z\t${formatOcspIndexTime(input.revocationTime ?? new Date('2026-03-12T00:00:00Z'))}\t${serial}\tunknown\t${subject}\n`;
		await writeFile(indexPath, indexLine, 'utf8');

		const responseResult = await runOpenSsl([
			'ocsp',
			'-index',
			indexPath,
			'-resp_no_certs',
			'-rsigner',
			issuerPath,
			'-rkey',
			issuerKeyPath,
			'-CA',
			issuerPath,
			'-reqin',
			requestPath,
			'-respout',
			responsePath,
		]);
		if (responseResult.exitCode !== 0) {
			throw new Error(mergeCommandOutput(responseResult));
		}

		const validation = await runOpenSsl([
			'ocsp',
			'-issuer',
			issuerPath,
			'-cert',
			certificatePath,
			'-respin',
			responsePath,
			'-CAfile',
			issuerPath,
			'-no-CApath',
			'-no-CAstore',
			'-no_nonce',
		]);
		const output = mergeCommandOutput(validation);
		const status = parseOcspStatus(output);
		return {
			accepted: validation.exitCode === 0,
			...(status === undefined ? {} : { status }),
			exitCode: validation.exitCode,
			output,
			responseDer: new Uint8Array(await readFile(responsePath)),
		};
	});
}

async function withTempDir<T>(fn: (directory: string) => Promise<T>): Promise<T> {
	const directory = await mkdtemp(join(tmpdir(), 'micro509-openssl-'));
	try {
		return await fn(directory);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
}

async function runOpenSsl(args: readonly string[]): Promise<OpenSslCommandResult> {
	try {
		const process = Bun.spawn(['openssl', ...args], {
			stdin: 'ignore',
			stdout: 'pipe',
			stderr: 'pipe',
		});
		const [stdout, stderr, exitCode] = await Promise.all([
			streamToText(process.stdout),
			streamToText(process.stderr),
			process.exited,
		]);
		return { exitCode, stdout, stderr };
	} catch {
		return {
			exitCode: 127,
			stdout: '',
			stderr: 'openssl command not available',
		};
	}
}

async function streamToText(stream: ReadableStream<Uint8Array> | null): Promise<string> {
	if (stream === null) {
		return '';
	}
	return await new Response(stream).text();
}

function mergeCommandOutput(result: OpenSslCommandResult): string {
	return [result.stdout.trim(), result.stderr.trim()]
		.filter((value) => value.length > 0)
		.join('\n');
}

function classifyVerifyFailure(
	output: string,
): 'path_length' | 'name_constraints' | 'policy' | 'other' {
	const lowerOutput = output.toLowerCase();
	if (lowerOutput.includes('path length constraint exceeded')) {
		return 'path_length';
	}
	if (
		lowerOutput.includes('permitted subtree violation') ||
		lowerOutput.includes('excluded subtree violation')
	) {
		return 'name_constraints';
	}
	if (lowerOutput.includes('policy')) {
		return 'policy';
	}
	return 'other';
}

function parseCrlNumber(output: string): number | undefined {
	const line = output.split('\n').find((value) => value.toLowerCase().startsWith('crlnumber='));
	if (line === undefined) {
		return undefined;
	}
	const value = Number.parseInt(line.slice('crlnumber='.length), 16);
	return Number.isNaN(value) ? undefined : value;
}

function parseCrlIssuer(output: string): string | undefined {
	const line = output.split('\n').find((value) => value.toLowerCase().startsWith('issuer='));
	return line?.slice('issuer='.length);
}

function parseOcspStatus(output: string): 'good' | 'revoked' | 'unknown' | undefined {
	for (const line of output.split('\n')) {
		const trimmed = line.trim().toLowerCase();
		if (trimmed.endsWith(': good')) {
			return 'good';
		}
		if (trimmed.endsWith(': revoked')) {
			return 'revoked';
		}
		if (trimmed.endsWith(': unknown')) {
			return 'unknown';
		}
	}
	return undefined;
}

function formatOcspIndexTime(value: Date): string {
	const year = value.getUTCFullYear() % 100;
	const parts = [
		year,
		value.getUTCMonth() + 1,
		value.getUTCDate(),
		value.getUTCHours(),
		value.getUTCMinutes(),
		value.getUTCSeconds(),
	].map((part) => String(part).padStart(2, '0'));
	return `${parts.join('')}Z`;
}
