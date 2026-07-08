// biome-ignore-all format: lsp overwrites formatting sometimes...
/**
 * OpenSSL-as-generator oracle for the differential fuzzer.
 *
 * Everything here treats `openssl` as the source of truth: it generates keys
 * and certificates from a {@link CertSpec}, and reads a certificate's fields
 * back into structured values for comparison against micro509's decode. Key and
 * cert are always produced through a CSR + `x509 -req -extfile` path so that
 * subjectKeyIdentifier / basicConstraints / keyUsage are computed by OpenSSL
 * (not merely copied), and so self-signed and CA-signed share one code path
 * (`-signkey` vs `-CA/-CAkey`).
 *
 * The subject/issuer are read with a fixed non-`esc_msb` nameopt so UTF-8 DN
 * values survive as raw bytes and compare cleanly against micro509's decoded
 * strings; {@link compare.ts} renders micro509 names with the matching rules.
 */

import { Buffer } from 'node:buffer';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { runOpenSsl, withTempDir } from './openssl.ts';
import type { CertSpec, FuzzKeyAlgo, FuzzSan } from '../fuzz/spec.ts';

/** nameopt shared with the comparator: RFC2253-like but keeps UTF-8 raw. */
export const NAME_OPT = 'esc_2253,utf8,sep_comma_plus,dn_rev,sname';

export interface OpenSslCertFields {
	readonly serialHex: string;
	readonly subject: string;
	readonly issuer: string;
	readonly notBeforeMs: number;
	readonly notAfterMs: number;
	readonly spkiDer: Uint8Array;
	readonly sans: readonly FuzzSan[];
	readonly skiHex?: string;
	/** Full TLV of the outer signatureAlgorithm parameters (e.g. RSA-PSS params), if present. */
	readonly sigAlgParamsDer?: Uint8Array;
	readonly der: Uint8Array;
	readonly pem: string;
}

const CURVE_OSSL: Record<'P-256' | 'P-384' | 'P-521', string> = {
	'P-256': 'prime256v1',
	'P-384': 'secp384r1',
	'P-521': 'secp521r1',
};

function digestFlag(hash: string): string {
	return `-${hash.toLowerCase().replace('-', '')}`;
}

function keygenArgs(algo: FuzzKeyAlgo, outPath: string): readonly string[] {
	if (algo.kind === 'ed25519') return ['genpkey', '-algorithm', 'ED25519', '-out', outPath];
	if (algo.kind === 'ecdsa') {
		return ['genpkey', '-algorithm', 'EC', '-pkeyopt', `ec_paramgen_curve:${CURVE_OSSL[algo.curve]}`, '-out', outPath];
	}
	return ['genpkey', '-algorithm', 'RSA', '-pkeyopt', `rsa_keygen_bits:${algo.bits}`, '-out', outPath];
}

/** Digest + PSS sigopts for signing with `algo`; empty for Ed25519 (PureEdDSA). */
function signingArgs(algo: FuzzKeyAlgo): readonly string[] {
	if (algo.kind === 'ed25519') return [];
	const args = [digestFlag(algo.hash)];
	if (algo.kind === 'rsa' && algo.pss) {
		args.push('-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:digest');
	}
	return args;
}

function subjectString(spec: CertSpec): string {
	return `/${spec.subject.map((a) => `${a.short}=${a.value}`).join('/')}`;
}

function sanValue(sans: readonly FuzzSan[]): string {
	const label: Record<FuzzSan['type'], string> = {
		dns: 'DNS',
		ip: 'IP',
		email: 'email',
		uri: 'URI',
	};
	return sans.map((s) => `${label[s.type]}:${s.value}`).join(',');
}

/** OpenSSL x509v3 extension config applied by `x509 -req -extfile`. */
function extConfig(spec: CertSpec): string {
	const lines = [
		`basicConstraints=critical,CA:${spec.isCa ? 'TRUE' : 'FALSE'}`,
		`keyUsage=critical,${spec.isCa ? 'keyCertSign,cRLSign' : 'digitalSignature'}`,
	];
	if (spec.addSki) lines.push('subjectKeyIdentifier=hash');
	if (spec.sans.length > 0) lines.push(`subjectAltName=${sanValue(spec.sans)}`);
	return `[ext]\n${lines.join('\n')}\n`;
}

/** Generate a PKCS#8 private key PEM for `algo`. */
export async function generateKeyPem(algo: FuzzKeyAlgo): Promise<string> {
	return await withTempDir(async (dir) => {
		const keyPath = join(dir, 'key.pem');
		const result = await runOpenSsl(keygenArgs(algo, keyPath));
		if (result.exitCode !== 0) throw new Error(`openssl genpkey failed: ${result.stderr}`);
		return await readFile(keyPath, 'utf8');
	});
}

/** Public SubjectPublicKeyInfo (PEM + DER) for a private key PEM. */
export async function publicSpki(
	keyPem: string,
): Promise<{ readonly pem: string; readonly der: Uint8Array }> {
	return await withTempDir(async (dir) => {
		const keyPath = join(dir, 'key.pem');
		await writeFile(keyPath, keyPem, 'utf8');
		const result = await runOpenSsl(['pkey', '-in', keyPath, '-pubout']);
		if (result.exitCode !== 0) throw new Error(`openssl pkey -pubout failed: ${result.stderr}`);
		return { pem: result.stdout, der: decodePem('PUBLIC KEY', result.stdout) };
	});
}

/**
 * Generate a certificate for `spec` signed by `issuerAlgo` with `issuerKeyPem`,
 * over subject key `subjectKeyPem`. When `caCertPem` is given the cert is
 * CA-signed (issuer ≠ subject); otherwise it is self-signed.
 */
async function issueCert(input: {
	readonly spec: CertSpec;
	readonly subjectKeyPem: string;
	readonly issuerKeyPem: string;
	readonly issuerAlgo: FuzzKeyAlgo;
	readonly caCertPem?: string;
	readonly issuerName?: string;
}): Promise<{ readonly pem: string; readonly der: Uint8Array }> {
	return await withTempDir(async (dir) => {
		const subjectKeyPath = join(dir, 'subject.key');
		const csrPath = join(dir, 'req.csr');
		const extPath = join(dir, 'ext.cnf');
		const certPath = join(dir, 'cert.pem');
		await Promise.all([
			writeFile(subjectKeyPath, input.subjectKeyPem, 'utf8'),
			writeFile(extPath, extConfig(input.spec), 'utf8'),
		]);

		// -utf8: without it OpenSSL reads the -subj bytes as Latin-1 and
		// double-encodes multi-byte values (Müller → MÃ¼ller) — silently, on both
		// sides of the differential.
		const csr = await runOpenSsl(['req', '-new', '-utf8', '-key', subjectKeyPath, '-subj', subjectString(input.spec), '-out', csrPath]);
		if (csr.exitCode !== 0) throw new Error(`openssl req -new failed: ${csr.stderr}`);

		const signArgs = ['x509', '-req', '-in', csrPath, '-set_serial', `0x${input.spec.serialHex}`, '-days', String(input.spec.validityDays), '-extfile', extPath, '-extensions', 'ext', ...signingArgs(input.issuerAlgo), '-out', certPath];
		if (input.caCertPem === undefined) {
			signArgs.push('-signkey', subjectKeyPath);
		} else {
			const caCertPath = join(dir, 'ca.pem');
			const caKeyPath = join(dir, 'ca.key');
			await Promise.all([
				writeFile(caCertPath, input.caCertPem, 'utf8'),
				writeFile(caKeyPath, input.issuerKeyPem, 'utf8'),
			]);
			signArgs.push('-CA', caCertPath, '-CAkey', caKeyPath);
		}

		const signed = await runOpenSsl(signArgs);
		if (signed.exitCode !== 0) throw new Error(`openssl x509 -req failed: ${signed.stderr}`);
		const pem = await readFile(certPath, 'utf8');
		return { pem, der: decodePem('CERTIFICATE', pem) };
	});
}

/**
 * Produce the certificate + subject key for a spec. For CA-signed specs an
 * issuer key/cert of the same algorithm family is generated so the leaf's
 * signatureAlgorithm is predictable from `spec.algo`.
 */
export async function generateCertificate(spec: CertSpec): Promise<{
	readonly certPem: string;
	readonly certDer: Uint8Array;
	readonly subjectKeyPem: string;
}> {
	const subjectKeyPem = await generateKeyPem(spec.algo);
	if (spec.issuance === 'self') {
		const { pem, der } = await issueCert({
			spec,
			subjectKeyPem,
			issuerKeyPem: subjectKeyPem,
			issuerAlgo: spec.algo,
		});
		return { certPem: pem, certDer: der, subjectKeyPem };
	}

	// CA-signed: issuer shares the leaf's algorithm so the expected signature OID
	// still derives from spec.algo. The CA cert itself is self-signed.
	const caKeyPem = await generateKeyPem(spec.algo);
	const caSpec: CertSpec = {
		...spec,
		subject: [{ oid: '2.5.4.3', short: 'CN', value: `Fuzz CA ${spec.serialHex.slice(0, 6)}` }],
		sans: [],
		isCa: true,
		addSki: true,
		issuance: 'self',
	};
	const { pem: caCertPem } = await issueCert({
		spec: caSpec,
		subjectKeyPem: caKeyPem,
		issuerKeyPem: caKeyPem,
		issuerAlgo: spec.algo,
	});
	const { pem, der } = await issueCert({
		spec,
		subjectKeyPem,
		issuerKeyPem: caKeyPem,
		issuerAlgo: spec.algo,
		caCertPem,
	});
	return { certPem: pem, certDer: der, subjectKeyPem };
}

/** Read a certificate's fields into structured values via OpenSSL. */
export async function readCertFields(certPem: string): Promise<OpenSslCertFields> {
	return await withTempDir(async (dir) => {
		const certPath = join(dir, 'cert.pem');
		const derPath = join(dir, 'cert.der');
		await writeFile(certPath, certPem, 'utf8');
		const base = ['x509', '-in', certPath, '-noout'] as const;

		const [serial, subject, issuer, dates, pubkey, san, ski, asn1, derWrite] = await Promise.all([
			runOpenSsl([...base, '-serial']),
			runOpenSsl([...base, '-subject', '-nameopt', NAME_OPT]),
			runOpenSsl([...base, '-issuer', '-nameopt', NAME_OPT]),
			runOpenSsl([...base, '-dates']),
			runOpenSsl([...base, '-pubkey']),
			runOpenSsl([...base, '-ext', 'subjectAltName']),
			runOpenSsl([...base, '-ext', 'subjectKeyIdentifier']),
			runOpenSsl(['asn1parse', '-in', certPath]),
			runOpenSsl(['x509', '-in', certPath, '-outform', 'DER', '-out', derPath]),
		]);
		for (const [name, r] of [
			['serial', serial],
			['subject', subject],
			['issuer', issuer],
			['dates', dates],
			['pubkey', pubkey],
			['asn1parse', asn1],
			['der', derWrite],
		] as const) {
			if (r.exitCode !== 0) throw new Error(`openssl ${name} read failed: ${r.stderr}`);
		}

		const der = new Uint8Array(await readFile(derPath));
		const skiHex = parseSki(ski.stdout);
		const sigAlgParamsDer = sigAlgParamsFromAsn1(asn1.stdout, der);
		return {
			serialHex: serial.stdout
				.trim()
				.replace(/^serial=/, '')
				.toLowerCase(),
			subject: subject.stdout.trim().replace(/^subject=/, ''),
			issuer: issuer.stdout.trim().replace(/^issuer=/, ''),
			notBeforeMs: parseOpenSslDate(dates.stdout, 'notBefore'),
			notAfterMs: parseOpenSslDate(dates.stdout, 'notAfter'),
			spkiDer: decodePem('PUBLIC KEY', pubkey.stdout),
			sans: parseSans(san.stdout),
			...(skiHex === undefined ? {} : { skiHex }),
			...(sigAlgParamsDer === undefined ? {} : { sigAlgParamsDer }),
			der,
			pem: certPem,
		};
	});
}

interface Asn1Row {
	readonly offset: number;
	readonly depth: number;
	readonly headerLength: number;
	readonly length: number;
}

/** Structural rows of `openssl asn1parse` output (offset:d=depth hl=… l=…). */
function parseAsn1Rows(output: string): readonly Asn1Row[] {
	const rows: Asn1Row[] = [];
	for (const line of output.split('\n')) {
		const match = /^\s*(\d+):d=(\d+)\s+hl=(\d+)\s+l=\s*(\d+)/.exec(line);
		if (match === null) continue;
		const [, offset, depth, headerLength, length] = match;
		if (
			offset === undefined ||
			depth === undefined ||
			headerLength === undefined ||
			length === undefined
		) {
			continue;
		}
		rows.push({
			offset: Number(offset),
			depth: Number(depth),
			headerLength: Number(headerLength),
			length: Number(length),
		});
	}
	return rows;
}

/**
 * Slice the outer signatureAlgorithm's parameters TLV out of the certificate
 * DER using OpenSSL's own asn1parse offsets: Certificate ::= SEQUENCE {
 * tbsCertificate, signatureAlgorithm, signatureValue }, so the second depth-1
 * element is the AlgorithmIdentifier and its optional second child the params
 * (NULL for RSA v1.5, a SEQUENCE for RSA-PSS, absent for ECDSA/Ed25519).
 */
function sigAlgParamsFromAsn1(output: string, der: Uint8Array): Uint8Array | undefined {
	const rows = parseAsn1Rows(output);
	const sigAlg = rows.filter((row) => row.depth === 1)[1];
	if (sigAlg === undefined) throw new Error(`asn1parse: no signatureAlgorithm row in: ${output}`);
	const sigAlgEnd = sigAlg.offset + sigAlg.headerLength + sigAlg.length;
	const children = rows.filter(
		(row) => row.depth === 2 && row.offset > sigAlg.offset && row.offset < sigAlgEnd,
	);
	const params = children[1];
	if (params === undefined) return undefined;
	return der.slice(params.offset, params.offset + params.headerLength + params.length);
}

function decodePem(label: string, pem: string): Uint8Array {
	const body = pem
		.replace(new RegExp(`-----BEGIN ${label}-----`), '')
		.replace(new RegExp(`-----END ${label}-----`), '')
		.replace(/\s+/g, '');
	return new Uint8Array(Buffer.from(body, 'base64'));
}

function parseOpenSslDate(output: string, field: 'notBefore' | 'notAfter'): number {
	const line = output.split('\n').find((l) => l.startsWith(`${field}=`));
	if (line === undefined) throw new Error(`missing ${field} in: ${output}`);
	const ms = Date.parse(line.slice(`${field}=`.length).replace(/\s+/g, ' ').trim());
	if (Number.isNaN(ms)) throw new Error(`unparseable ${field}: ${line}`);
	return ms;
}

function parseSans(output: string): readonly FuzzSan[] {
	// Body follows the "X509v3 Subject Alternative Name:" header line.
	const body = output
		.split('\n')
		.map((l) => l.trim())
		.filter((l) => l.length > 0 && !l.startsWith('X509v3'));
	const sans: FuzzSan[] = [];
	for (const token of body.join(', ').split(', ')) {
		const [rawType, ...rest] = token.split(':');
		const value = rest.join(':');
		if (rawType === 'DNS') sans.push({ type: 'dns', value });
		else if (rawType === 'IP Address' || rawType === 'IP') sans.push({ type: 'ip', value });
		else if (rawType === 'email') sans.push({ type: 'email', value });
		else if (rawType === 'URI') sans.push({ type: 'uri', value });
	}
	return sans;
}

function parseSki(output: string): string | undefined {
	const hex = output
		.split('\n')
		.map((l) => l.trim())
		.find((l) => /^[0-9A-Fa-f:]+$/.test(l) && l.includes(':'));
	return hex === undefined ? undefined : hex.replace(/:/g, '').toLowerCase();
}
