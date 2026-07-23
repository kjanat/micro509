// biome-ignore-all format: lsp overwrites formatting sometimes...
import { mkdtemp } from 'node:fs/promises';
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

interface VerifyChainWithOpenSslInput {
	readonly leafPem: string;
	readonly rootPem: string;
	readonly intermediatePems?: readonly string[];
	readonly at?: Date;
	readonly initialPolicySet?: readonly string[];
	readonly requireExplicitPolicy?: boolean;
	readonly inhibitPolicyMapping?: boolean;
	readonly inhibitAnyPolicy?: boolean;
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

export async function verifyChainWithOpenSsl(
	input: VerifyChainWithOpenSslInput,
): Promise<OpenSslPathValidationResult> {
	return await withTempDir(async (directory) => {
		const { leafPath, rootPath } = await writeVerifyChainCertificates(directory, input);
		const args = ['verify', '-trusted', rootPath, '-no-CApath', '-no-CAstore'];
		await appendVerifyChainIntermediates(args, directory, input.intermediatePems);
		if (input.at !== undefined) {
			args.push('-attime', String(Math.floor(input.at.getTime() / 1000)));
		}
		appendVerifyChainPolicyArgs(args, input);
		args.push(leafPath);

		const result = await runOpenSsl(args);
		return formatVerifyChainResult(result);
	});
}

async function writeVerifyChainCertificates(
	directory: string,
	input: VerifyChainWithOpenSslInput,
): Promise<{ readonly leafPath: string; readonly rootPath: string }> {
	const leafPath = join(directory, 'leaf.pem');
	const rootPath = join(directory, 'root.pem');
	await Promise.all([
		Bun.write(leafPath, input.leafPem),
		Bun.write(rootPath, input.rootPem),
	]);
	return { leafPath, rootPath };
}

async function appendVerifyChainIntermediates(
	args: string[],
	directory: string,
	intermediatePems: readonly string[] | undefined,
): Promise<void> {
	if (intermediatePems === undefined || intermediatePems.length === 0) return;
	const intermediatesPath = join(directory, 'intermediates.pem');
	await Bun.write(intermediatesPath, intermediatePems.join('\n'));
	args.push('-untrusted', intermediatesPath);
}

function appendVerifyChainPolicyArgs(args: string[], input: VerifyChainWithOpenSslInput): void {
	if (!verifyChainShouldCheckPolicy(input)) return;
	args.push('-policy_check');
	for (const policyOid of input.initialPolicySet ?? []) {
		args.push('-policy', policyOid);
	}
	if (input.requireExplicitPolicy === true) args.push('-explicit_policy');
	if (input.inhibitPolicyMapping === true) args.push('-inhibit_map');
	if (input.inhibitAnyPolicy === true) args.push('-inhibit_any');
}

function verifyChainShouldCheckPolicy(input: VerifyChainWithOpenSslInput): boolean {
	return (
		(input.initialPolicySet?.length ?? 0) > 0 ||
		input.requireExplicitPolicy === true ||
		input.inhibitPolicyMapping === true ||
		input.inhibitAnyPolicy === true
	);
}

function formatVerifyChainResult(result: OpenSslCommandResult): OpenSslPathValidationResult {
	const output = mergeCommandOutput(result);
	return result.exitCode === 0
		? { valid: true, exitCode: result.exitCode, output }
		: {
			valid: false,
			exitCode: result.exitCode,
			failureClass: classifyVerifyFailure(output),
			output,
		};
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
			Bun.write(certificatePath, input.certificatePem),
			Bun.write(issuerPath, input.issuerCertificatePem),
			Bun.write(crlPath, input.crlPem),
		]);

		// -nameopt RFC2253 pins DN formatting; the default drifted across OpenSSL versions ("CN = X" in 3.0, "CN=X" elsewhere).
		const metadata = await runOpenSsl(['crl', '-in', crlPath, '-noout', '-crlnumber', '-issuer', '-nameopt', 'RFC2253']);
		const verifyArgs = ['verify', '-trusted', issuerPath, '-CRLfile', crlPath, '-crl_check', '-no-CApath', '-no-CAstore'];
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
		await Bun.write(certificatePath, input.certificatePem);
		const result = await runOpenSsl(['x509', '-in', certificatePath, '-noout', input.kind === 'dns' ? '-checkhost' : '-checkip', input.value]);
		const output = mergeCommandOutput(result);
		// OpenSSL < 3.4 exits 0 even on mismatch; the printed verdict text is version-stable, so parse that instead of the exit code.
		return {
			matches: !/does NOT match/i.test(output) && /does match/i.test(output),
			exitCode: result.exitCode,
			output,
		};
	});
}

export async function fingerprintCertificateWithOpenSsl(input: {
	readonly certificatePem: string;
	readonly algorithm: 'sha1' | 'sha256' | 'sha384' | 'sha512';
}): Promise<string> {
	return await withTempDir(async (directory) => {
		const certificatePath = join(directory, 'certificate.pem');
		await Bun.write(certificatePath, input.certificatePem);
		const result = await runOpenSsl(['x509', '-in', certificatePath, '-noout', '-fingerprint', `-${input.algorithm}`]);
		// Output looks like: "sha256 Fingerprint=AB:CD:...". Return the colon-hex portion.
		const match = /Fingerprint=([0-9A-Fa-f:]+)/.exec(result.stdout);
		if (match?.[1] === undefined) {
			throw new Error(`unexpected openssl fingerprint output: ${mergeCommandOutput(result)}`);
		}
		return match[1];
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
			Bun.write(issuerPath, input.issuerCertificatePem),
			Bun.write(issuerKeyPath, input.issuerPrivateKeyPem),
			Bun.write(certificatePath, input.certificatePem),
		]);

		const requestResult = await runOpenSsl(['ocsp', '-issuer', issuerPath, '-cert', certificatePath, '-no_nonce', '-reqout', requestPath]);
		if (requestResult.exitCode !== 0) {
			throw new Error(mergeCommandOutput(requestResult));
		}

		const serialResult = await runOpenSsl(['x509', '-in', certificatePath, '-noout', '-serial']);
		const subjectResult = await runOpenSsl(['x509', '-in', certificatePath, '-noout', '-subject', '-nameopt', 'RFC2253']);
		if (serialResult.exitCode !== 0 || subjectResult.exitCode !== 0) {
			throw new Error(`${mergeCommandOutput(serialResult)}\n${mergeCommandOutput(subjectResult)}`);
		}

		const serial = serialResult.stdout.trim().replace(/^serial=/, '');
		const subject = subjectResult.stdout.trim().replace(/^subject=/, '');
		const indexLine =
			input.certificateStatus === 'good'
				? `V\t351231235959Z\t\t${serial}\tunknown\t${subject}\n`
				: `R\t351231235959Z\t${formatOcspIndexTime(input.revocationTime ?? new Date('2026-03-12T00:00:00Z'))}\t${serial}\tunknown\t${subject}\n`;
		await Bun.write(indexPath, indexLine);

		// dprint-ignore
		const responseResult = await runOpenSsl([
			'ocsp',
			'-index', indexPath,
			'-resp_no_certs',
			'-rsigner', issuerPath,
			'-rkey', issuerKeyPath,
			'-CA', issuerPath,
			'-reqin', requestPath,
			'-respout', responsePath,
		]);
		if (responseResult.exitCode !== 0) {
			throw new Error(mergeCommandOutput(responseResult));
		}

		const validation = await runOpenSsl([
			'ocsp',
			'-issuer', issuerPath,
			'-cert', certificatePath,
			'-respin', responsePath,
			'-CAfile', issuerPath,
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
			responseDer: new Uint8Array(await Bun.file(responsePath).arrayBuffer()),
		};
	});
}

/**
 * Has OpenSSL parse and validate an OCSP response produced by micro509, proving
 * the emitted DER (EXPLICIT byKey ResponderID, GeneralizedTime fields) is
 * interoperable. The response must be signed by the issuer key.
 */
export async function validateMicro509OcspResponseWithOpenSsl(input: {
	readonly issuerCertificatePem: string;
	readonly certificatePem: string;
	readonly responseDer: Uint8Array;
}): Promise<OpenSslOcspStatusResult> {
	return await withTempDir(async (directory) => {
		const issuerPath = join(directory, 'issuer.pem');
		const certificatePath = join(directory, 'certificate.pem');
		const responsePath = join(directory, 'response.der');
		await Promise.all([
			Bun.write(issuerPath, input.issuerCertificatePem),
			Bun.write(certificatePath, input.certificatePem),
			Bun.write(responsePath, input.responseDer),
		]);
		// dprint-ignore
		const validation = await runOpenSsl([
			'ocsp',
			'-issuer', issuerPath,
			'-cert', certificatePath,
			'-respin', responsePath,
			'-CAfile', issuerPath,
			'-VAfile', issuerPath,
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
			responseDer: input.responseDer,
		};
	});
}

/** A normalized view of the SubjectAltName extension as OpenSSL decodes it. */
export interface OpenSslSanObservation {
	/** `true` when OpenSSL parsed the certificate and its SAN extension. */
	readonly accepted: boolean;
	/** The whitespace-normalized SAN value (`"DNS:…, DirName:CN=…"`), or `undefined`. */
	readonly subjectAltName?: string;
}

/**
 * Reads the SubjectAltName a micro509-produced certificate encodes, as OpenSSL
 * decodes it, proving the emitted SAN (directoryName [4], otherName [0]) is
 * interoperable. Returns a normalized SAN string rather than raw CLI text.
 */
export async function readCertificateSanWithOpenSsl(
	certificatePem: string,
): Promise<OpenSslSanObservation> {
	return await withTempDir(async (directory) => {
		const certificatePath = join(directory, 'certificate.pem');
		await Bun.write(certificatePath, certificatePem);
		// dprint-ignore
		const result = await runOpenSsl([
			'x509',
			'-in', certificatePath,
			'-noout',
			'-ext', 'subjectAltName',
			'-nameopt', 'RFC2253',
		]);
		if (result.exitCode !== 0) {
			return { accepted: false };
		}
		const text = mergeCommandOutput(result);
		const marker = 'Subject Alternative Name:';
		const markerIndex = text.indexOf(marker);
		if (markerIndex === -1) {
			return { accepted: true };
		}
		const subjectAltName = text
			.slice(markerIndex + marker.length)
			.replace(/\s+/g, ' ')
			.trim();
		return { accepted: true, subjectAltName };
	});
}

/** A normalized view of the Authority Information Access extension as OpenSSL decodes it. */
export interface OpenSslAiaObservation {
	/** `true` when OpenSSL parsed the certificate and its AIA extension. */
	readonly accepted: boolean;
	/** The whitespace-normalized AIA value (`"OCSP - URI:…, CA Issuers - DirName:…"`), or `undefined`. */
	readonly authorityInfoAccess?: string;
}

/**
 * Reads the Authority Information Access a micro509-produced certificate encodes,
 * as OpenSSL decodes it, proving the emitted accessLocation GeneralNames (a URI
 * OCSP responder and a directoryName caIssuers) are interoperable.
 */
export async function readCertificateAiaWithOpenSsl(
	certificatePem: string,
): Promise<OpenSslAiaObservation> {
	return await withTempDir(async (directory) => {
		const certificatePath = join(directory, 'certificate.pem');
		await Bun.write(certificatePath, certificatePem);
		// dprint-ignore
		const result = await runOpenSsl([
			'x509',
			'-in', certificatePath,
			'-noout',
			'-ext', 'authorityInfoAccess',
			'-nameopt', 'RFC2253',
		]);
		if (result.exitCode !== 0) {
			return { accepted: false };
		}
		const text = mergeCommandOutput(result);
		const marker = 'Authority Information Access:';
		const markerIndex = text.indexOf(marker);
		if (markerIndex === -1) {
			return { accepted: true };
		}
		const authorityInfoAccess = text
			.slice(markerIndex + marker.length)
			.replace(/\s+/g, ' ')
			.trim();
		return { accepted: true, authorityInfoAccess };
	});
}

export async function withTempDir<T>(fn: (directory: string) => Promise<T>): Promise<T> {
	const directory = await mkdtemp(join(tmpdir(), 'micro509-openssl-'));
	try {
		return await fn(directory);
	} finally {
		await Bun.$`rm -rf ${directory}`
	}
}

export async function runOpenSsl(args: readonly string[]): Promise<OpenSslCommandResult> {
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
