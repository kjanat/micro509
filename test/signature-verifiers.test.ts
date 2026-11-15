import { describe, expect, it } from 'bun:test';
import { readFile } from 'node:fs/promises';
import type { SignatureVerifierInput, SignatureVerifiers } from '#micro509/crypto';
import { verifySignature } from '#micro509/crypto';
import {
	bitString,
	explicitContext,
	octetString,
	readSequenceChildren,
	sequence,
} from '#micro509/internal/asn1/der';
import { generateKeyPair } from '#micro509/keys';
import { verifyPkcs7SignedData } from '#micro509/pkcs';
import { unwrap } from '#micro509/result';
import {
	checkCertificateRevocation,
	checkCertificateRevocationAgainstCrl,
	checkChainRevocation,
	createCertificateRevocationList,
	createOcspResponse,
	validateCertificateRevocationList,
	validateOcspResponse,
	verifyCertificateRevocationListSignature,
	verifyOcspResponseSignature,
} from '#micro509/revocation';
import {
	buildCandidatePath,
	trustAnchorFromCertificate,
	validateCandidatePath,
	validateForTlsServer,
	verifyCertificateChain,
	verifyCertificateSigningRequest,
} from '#micro509/verify';
import {
	createCertificate,
	createSelfSignedCertificate,
	parseCertificateDer,
} from '#micro509/x509';
import { callUntyped, issueChain, sliceElement, withSignatureValue } from '#test/helpers';
import { DSA_WITH_SHA1, DSA_WITH_SHA256, dsaSignatureVerifiers } from '#test/oracles/dsa';
import type { ParameterKey } from '#test/oracles/parameter-signature';
import {
	parameterKey,
	parameterSignatureVerifiers,
	rekeyedCertificate,
	resignedCrl,
	resignedOcspResponse,
} from '#test/oracles/parameter-signature';

const at = new Date('2011-04-15T00:00:00Z');

async function pkitsCertificate(name: string): Promise<Uint8Array> {
	return new Uint8Array(
		await readFile(new URL(`./fixtures/pkits/certs/${name}.crt`, import.meta.url)),
	);
}

const root = await pkitsCertificate('TrustAnchorRootCertificate');
const dsaCa = await pkitsCertificate('DSACACert');
const inheritedCa = await pkitsCertificate('DSAParametersInheritedCACert');
const test4Leaf = await pkitsCertificate('ValidDSASignaturesTest4EE');
const test5Leaf = await pkitsCertificate('ValidDSAParameterInheritanceTest5EE');

function keyParameters(certificateDer: Uint8Array): Uint8Array | undefined {
	return unwrap(parseCertificateDer(certificateDer)).publicKeyAlgorithmParametersDer;
}

function recordingVerifiers(inputs: SignatureVerifierInput[]): SignatureVerifiers {
	return {
		[DSA_WITH_SHA1]: (input) => {
			inputs.push(input);
			return dsaSignatureVerifiers[DSA_WITH_SHA1]?.(input) ?? Promise.resolve(false);
		},
	};
}

function withFlippedSignatureOctet(certificateDer: Uint8Array): Uint8Array {
	const signature = readSequenceChildren(certificateDer)[2];
	if (signature === undefined) throw new Error('certificate has no signatureValue');
	const changed = certificateDer.slice();
	const target = signature.end - 1;
	changed[target] = (changed[target] ?? 0) ^ 0x01;
	return changed;
}

describe('signatureVerifiers', () => {
	it('never reaches a caller verifier for a natively verified chain', async () => {
		const chain = await issueChain();
		const inputs: SignatureVerifierInput[] = [];
		expect(
			await verifyCertificateChain({
				leaf: chain.leaf.pem,
				intermediates: [chain.intermediate.pem],
				roots: [chain.root.certificate.pem],
				signatureVerifiers: recordingVerifiers(inputs),
			}),
		).toMatchObject({ ok: true });
		expect(inputs).toEqual([]);
	});

	it.each([
		['a natively verified OID', { '1.2.840.113549.1.1.11': () => Promise.resolve(true) }],
		['a key that is no OID', { dsa: () => Promise.resolve(true) }],
		['an OID that has no encoding', { '3.1': () => Promise.resolve(true) }],
		[
			'two spellings of one OID',
			{
				[DSA_WITH_SHA1]: () => Promise.resolve(true),
				'1.2.840.10040.4.03': () => Promise.resolve(true),
			},
		],
		['a value that is no function', { [DSA_WITH_SHA1]: 'verify' }],
	] as const)('throws RangeError for %s', async (_case, signatureVerifiers) => {
		const leaf = unwrap(parseCertificateDer(test4Leaf));
		for (const run of [
			() =>
				callUntyped(verifyCertificateChain, { leaf: test4Leaf, roots: [root], signatureVerifiers }),
			() => callUntyped(validateCandidatePath, { chain: [leaf], signatureVerifiers }),
		]) {
			const error = await run().then(
				() => undefined,
				(rejection: unknown) => rejection,
			);
			expect(error).toBeInstanceOf(RangeError);
		}
	});

	it('hands the verifier the issuer key parameters for PKITS 4.1.4', async () => {
		const inputs: SignatureVerifierInput[] = [];
		const result = await verifyCertificateChain({
			leaf: test4Leaf,
			intermediates: [dsaCa],
			roots: [root],
			at,
			signatureVerifiers: recordingVerifiers(inputs),
		});
		expect(result).toMatchObject({ ok: true });
		const leaf = unwrap(parseCertificateDer(test4Leaf));
		expect(inputs.length).toBeGreaterThan(0);
		for (const input of inputs) {
			expect(input).toEqual({
				signatureAlgorithm: { oid: DSA_WITH_SHA1 },
				signerSpkiDer: unwrap(parseCertificateDer(dsaCa)).subjectPublicKeyInfoDer,
				signerPublicKeyParametersDer: keyParameters(dsaCa),
				signature: leaf.signatureValue,
				signatureUnusedBits: 0,
				data: leaf.tbsCertificateDer,
			});
		}
	});

	it('hands the verifier inherited parameters for PKITS 4.1.5 (RFC 5280 §6.1.4 (e))', async () => {
		expect(keyParameters(inheritedCa)).toBeUndefined();
		const inputs: SignatureVerifierInput[] = [];
		const result = await verifyCertificateChain({
			leaf: test5Leaf,
			intermediates: [inheritedCa, dsaCa],
			roots: [root],
			at,
			signatureVerifiers: recordingVerifiers(inputs),
		});
		expect(result).toMatchObject({ ok: true });
		const inheritedSpki = unwrap(parseCertificateDer(inheritedCa)).subjectPublicKeyInfoDer;
		const leafChecks = inputs.filter((input) => equalBytes(input.signerSpkiDer, inheritedSpki));
		expect(leafChecks.length).toBeGreaterThan(0);
		for (const input of leafChecks) {
			expect(input.signerPublicKeyParametersDer).toEqual(keyParameters(dsaCa));
		}
	});

	it('inherits parameters from a bare DSA trust anchor', async () => {
		const trustAnchor = trustAnchorFromCertificate(unwrap(parseCertificateDer(dsaCa)));
		const input = {
			leaf: test5Leaf,
			intermediates: [inheritedCa],
			roots: [],
			trustAnchors: [trustAnchor],
			at,
			signatureVerifiers: dsaSignatureVerifiers,
		};
		expect(await verifyCertificateChain(input)).toMatchObject({ ok: true });
		const built = unwrap(await buildCandidatePath(input));
		expect(built.anchorCertificateInChain).toBe(false);
		const validation = {
			chain: built.chain,
			anchorCertificateInChain: false,
			at,
			signatureVerifiers: dsaSignatureVerifiers,
		};
		expect(await validateCandidatePath({ ...validation, trustAnchor })).toMatchObject({ ok: true });
		expect(await validateCandidatePath(validation)).toMatchObject({
			ok: false,
			code: 'signature_invalid',
			index: 0,
		});
	});

	it('checks revocation with the parameters a bare DSA trust anchor passes down', async () => {
		expect(
			await verifyCertificateChain({
				leaf: test5Leaf,
				intermediates: [inheritedCa],
				roots: [],
				trustAnchors: [trustAnchorFromCertificate(unwrap(parseCertificateDer(dsaCa)))],
				at,
				signatureVerifiers: dsaSignatureVerifiers,
				revocation: {
					crls: await Promise.all(['DSACACRL', 'DSAParametersInheritedCACRL'].map(pkitsCrl)),
				},
			}),
		).toMatchObject({ ok: true });
	});

	it('searches past a root whose key leaves an inherited link without parameters', async () => {
		const result = await verifyCertificateChain({
			leaf: test5Leaf,
			roots: [inheritedCa, dsaCa],
			at,
			signatureVerifiers: dsaSignatureVerifiers,
		});
		expect(result).toMatchObject({ ok: true });
		if (result.ok)
			expect(result.value.chain.map((member) => member.der)).toEqual([
				test5Leaf,
				inheritedCa,
				dsaCa,
			]);
	});

	it('lets a bare anchor end the path when a root leaves an inherited link without parameters', async () => {
		const trustAnchor = trustAnchorFromCertificate(unwrap(parseCertificateDer(dsaCa)));
		const input = {
			leaf: test5Leaf,
			roots: [inheritedCa],
			trustAnchors: [trustAnchor],
			at,
			signatureVerifiers: dsaSignatureVerifiers,
		};
		const built = unwrap(await buildCandidatePath(input));
		expect(built.chain.map((member) => member.der)).toEqual([test5Leaf, inheritedCa]);
		expect(built).toMatchObject({ anchorCertificateInChain: false, trustAnchor });
		expect(await verifyCertificateChain(input)).toMatchObject({ ok: true });
	});

	it('refuses a path whose deferred inherited-parameter link fails', async () => {
		expect(
			await verifyCertificateChain({
				leaf: withFlippedSignatureOctet(test5Leaf),
				intermediates: [inheritedCa, dsaCa],
				roots: [root],
				at,
				signatureVerifiers: dsaSignatureVerifiers,
			}),
		).toMatchObject({ ok: false, code: 'signature_invalid', index: 0 });
	});

	it.each([
		['an empty SubjectPublicKeyInfo', Uint8Array.of(0x30, 0x00)],
		['a malformed SubjectPublicKeyInfo', Uint8Array.of(0x30, 0x80, 0x00, 0x00)],
		[
			'an AlgorithmIdentifier without parameters',
			Uint8Array.of(
				0x30,
				0x0d,
				0x30,
				0x09,
				0x06,
				0x07,
				0x2a,
				0x86,
				0x48,
				0xce,
				0x38,
				0x04,
				0x01,
				0x03,
				0x00,
			),
		],
	])('leaves no parameters to inherit from a bare anchor with %s', async (_case, spki) => {
		const trustAnchor = {
			...trustAnchorFromCertificate(unwrap(parseCertificateDer(dsaCa))),
			subjectPublicKeyInfoDer: spki,
		};
		const inputs: SignatureVerifierInput[] = [];
		expect(
			await validateCandidatePath({
				chain: [test5Leaf, inheritedCa].map((der) => unwrap(parseCertificateDer(der))),
				anchorCertificateInChain: false,
				trustAnchor,
				at,
				signatureVerifiers: recordingVerifiers(inputs),
			}),
		).toMatchObject({ ok: false, code: 'signature_invalid', index: 0 });
		expect(inputs.map((input) => input.signerPublicKeyParametersDer)).toEqual([undefined]);
	});

	it('reports signature_invalid when the verifier refuses the signature', async () => {
		expect(
			await verifyCertificateChain({
				leaf: withFlippedSignatureOctet(test4Leaf),
				intermediates: [dsaCa],
				roots: [root],
				at,
				signatureVerifiers: dsaSignatureVerifiers,
			}),
		).toMatchObject({ ok: false, code: 'signature_invalid', index: 0 });
	});

	it('reports signature_invalid with the reason when the verifier rejects', async () => {
		const result = await verifyCertificateChain({
			leaf: test4Leaf,
			intermediates: [dsaCa],
			roots: [root],
			at,
			signatureVerifiers: { [DSA_WITH_SHA1]: () => Promise.reject(new Error('boom')) },
		});
		expect(result).toMatchObject({ ok: false, code: 'signature_invalid', index: 0 });
		if (!result.ok) expect(result.message).toBe('signature verifier failed: boom');
	});

	it('treats any resolution other than true as an invalid signature', async () => {
		expect(
			await callUntyped(verifyCertificateChain, {
				leaf: test4Leaf,
				intermediates: [dsaCa],
				roots: [root],
				at,
				signatureVerifiers: { [DSA_WITH_SHA1]: () => Promise.resolve(1) },
			}),
		).toMatchObject({ ok: false, code: 'signature_invalid', index: 0 });
	});
});

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
	return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

async function dsaFixture(name: string): Promise<Uint8Array> {
	return new Uint8Array(await readFile(new URL(`./fixtures/dsa/${name}.der`, import.meta.url)));
}

async function pkitsCrl(name: string): Promise<Uint8Array> {
	return new Uint8Array(
		await readFile(new URL(`./fixtures/pkits/crls/${name}.crl`, import.meta.url)),
	);
}

const dsaCaCert = await dsaFixture('ca');
const dsaLeaf = await dsaFixture('leaf');
const dsaCrl = await dsaFixture('ca-crl');
const dsaOcspRequest = await dsaFixture('ocsp-request');
const dsaOcspResponse = await dsaFixture('ocsp-response');

describe('signatureVerifiers for CRL, OCSP, CMS, CSR and detached signatures', () => {
	it('verifySignature dispatches an unsupported algorithm to the caller verifier', async () => {
		const ca = unwrap(parseCertificateDer(dsaCaCert));
		const leaf = unwrap(parseCertificateDer(dsaLeaf));
		const input = {
			signerSpkiDer: ca.subjectPublicKeyInfoDer,
			signatureAlgorithm: { oid: leaf.signatureAlgorithmOid },
			publicKeyAlgorithm: { oid: ca.publicKeyAlgorithmOid },
			signature: leaf.signatureValue,
			data: leaf.tbsCertificateDer,
		};
		expect(await verifySignature(input)).toMatchObject({
			ok: false,
			code: 'unsupported_signature_algorithm_parameters',
		});
		expect(await verifySignature({ ...input, signatureVerifiers: dsaSignatureVerifiers })).toEqual({
			ok: true,
			valid: true,
		});
		expect(
			await verifySignature({
				...input,
				data: Uint8Array.of(0),
				signatureVerifiers: dsaSignatureVerifiers,
			}),
		).toEqual({ ok: true, valid: false });
	});

	it('hands the verifier copies that leave Buffer inputs untouched', async () => {
		const ca = unwrap(parseCertificateDer(dsaCaCert));
		const leaf = unwrap(parseCertificateDer(dsaLeaf));
		const input = {
			signerSpkiDer: Buffer.from(ca.subjectPublicKeyInfoDer),
			signatureAlgorithm: { oid: leaf.signatureAlgorithmOid },
			publicKeyAlgorithm: { oid: ca.publicKeyAlgorithmOid },
			signature: Buffer.from(leaf.signatureValue),
			data: Buffer.from(leaf.tbsCertificateDer),
		};
		const scribble = async (verifierInput: SignatureVerifierInput): Promise<boolean> => {
			const valid = (await dsaSignatureVerifiers[DSA_WITH_SHA256]?.(verifierInput)) === true;
			verifierInput.signerSpkiDer.fill(0);
			verifierInput.signerPublicKeyParametersDer?.fill(0);
			verifierInput.signature.fill(0);
			verifierInput.data.fill(0);
			return valid;
		};
		expect(
			await verifySignature({ ...input, signatureVerifiers: { [DSA_WITH_SHA256]: scribble } }),
		).toEqual({ ok: true, valid: true });
		expect(input.signerSpkiDer).toEqual(Buffer.from(ca.subjectPublicKeyInfoDer));
		expect(input.signature).toEqual(Buffer.from(leaf.signatureValue));
		expect(input.data).toEqual(Buffer.from(leaf.tbsCertificateDer));
	});

	it('verifies a DSA CSR self-signature', async () => {
		const csr = await dsaFixture('leaf-csr');
		expect(await verifyCertificateSigningRequest(csr)).toMatchObject({
			ok: false,
			code: 'unsupported_signature_algorithm_parameters',
		});
		expect(
			await verifyCertificateSigningRequest(csr, { signatureVerifiers: dsaSignatureVerifiers }),
		).toMatchObject({ ok: true });
	});

	it('verifies, validates and checks against a DSA CRL', async () => {
		const options = { signatureVerifiers: dsaSignatureVerifiers };
		expect(await verifyCertificateRevocationListSignature(dsaCrl, dsaCaCert)).toMatchObject({
			ok: false,
			code: 'signature_invalid',
		});
		expect(
			await verifyCertificateRevocationListSignature(dsaCrl, dsaCaCert, options),
		).toMatchObject({ ok: true });
		expect(
			await validateCertificateRevocationList({
				crl: dsaCrl,
				issuerCertificate: dsaCaCert,
				...options,
			}),
		).toMatchObject({ ok: true });
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: dsaLeaf,
				issuerCertificate: dsaCaCert,
				crl: dsaCrl,
				...options,
			}),
		).toMatchObject({ ok: true, value: { status: 'good' } });
		expect(
			await checkCertificateRevocation({
				certificate: dsaLeaf,
				issuerCertificate: dsaCaCert,
				evidence: [{ kind: 'crl', crl: dsaCrl }],
				...options,
			}),
		).toMatchObject({ ok: true, value: { status: 'good' } });
	});

	it('verifies and validates a DSA-signed OCSP response', async () => {
		const options = { signatureVerifiers: dsaSignatureVerifiers };
		expect(await verifyOcspResponseSignature(dsaOcspResponse, dsaCaCert, options)).toMatchObject({
			ok: true,
		});
		const input = {
			response: dsaOcspResponse,
			issuerCertificate: dsaCaCert,
			request: dsaOcspRequest,
		};
		expect(await validateOcspResponse(input)).toMatchObject({
			ok: false,
			code: 'signature_invalid',
		});
		const validated = await validateOcspResponse({ ...input, ...options });
		expect(validated).toMatchObject({ ok: true });
		if (validated.ok) expect(validated.value.responses?.[0]?.certStatus).toBe('good');
	});

	it.each([
		{ kind: 'CRL', evidence: { crls: [dsaCrl] } },
		{ kind: 'OCSP', evidence: { ocspResponses: [dsaOcspResponse] } },
	])('checks DSA $kind evidence for a chain', async ({ evidence }) => {
		const chain = [unwrap(parseCertificateDer(dsaLeaf)), unwrap(parseCertificateDer(dsaCaCert))];
		const unchecked = await checkChainRevocation({ chain, ...evidence });
		expect(unchecked.value.summary.indeterminateCertificates).toHaveLength(1);
		const checked = await checkChainRevocation({
			chain,
			...evidence,
			signatureVerifiers: dsaSignatureVerifiers,
		});
		expect(checked.value).toMatchObject({
			decision: 'allow',
			summary: { revokedCertificates: [], indeterminateCertificates: [] },
		});
		expect(
			await verifyCertificateChain({
				leaf: dsaLeaf,
				roots: [dsaCaCert],
				signatureVerifiers: dsaSignatureVerifiers,
				revocation: evidence,
			}),
		).toMatchObject({ ok: true });
	});

	it('validates a DSA chain through validateForTlsServer', async () => {
		const input = { leaf: dsaLeaf, roots: [dsaCaCert] };
		expect(await validateForTlsServer(input)).toMatchObject({
			ok: false,
			code: 'unsupported_signature_algorithm_parameters',
		});
		expect(
			await validateForTlsServer({ ...input, signatureVerifiers: dsaSignatureVerifiers }),
		).toMatchObject({ ok: true });
	});

	it('verifies a CRL signed by a CA that inherits its DSA parameters along the chain', async () => {
		const inheritedCrl = await pkitsCrl('DSAParametersInheritedCACRL');
		expect(
			await verifyCertificateRevocationListSignature(inheritedCrl, inheritedCa, {
				signatureVerifiers: dsaSignatureVerifiers,
			}),
		).toMatchObject({ ok: false, code: 'signature_invalid' });
		expect(
			await verifyCertificateChain({
				leaf: test5Leaf,
				intermediates: [inheritedCa, dsaCa],
				roots: [root],
				at,
				signatureVerifiers: dsaSignatureVerifiers,
				revocation: {
					crls: await Promise.all(
						['TrustAnchorRootCRL', 'DSACACRL', 'DSAParametersInheritedCACRL'].map(pkitsCrl),
					),
				},
			}),
		).toMatchObject({ ok: true });
	});

	it('verifies a DSA CMS SignerInfo and rejects invalid verifiers as invalid_options', async () => {
		const cms = await dsaFixture('cms');
		expect(await verifyPkcs7SignedData(cms)).toMatchObject({ ok: false });
		expect(
			await verifyPkcs7SignedData(cms, { signatureVerifiers: dsaSignatureVerifiers }),
		).toMatchObject({ ok: true });
		expect(
			await verifyPkcs7SignedData(cms, {
				signatureVerifiers: { '1.2.840.113549.1.1.11': () => Promise.resolve(true) },
			}),
		).toMatchObject({ ok: false, code: 'invalid_options' });
	});
});

function withUnusedSignatureBit(signedDer: Uint8Array): Uint8Array {
	const signature = readSequenceChildren(signedDer)[2];
	if (signature?.tag !== 0x03) throw new Error('expected a signatureValue BIT STRING');
	return withSignatureValue(
		signedDer,
		bitString(Uint8Array.of(...signature.value.subarray(1), 0x00), 1),
	);
}

function ocspWithUnusedSignatureBit(responseDer: Uint8Array): Uint8Array {
	const [status, responseBytes] = readSequenceChildren(responseDer);
	if (status === undefined || responseBytes?.tag !== 0xa0)
		throw new Error('expected responseBytes');
	const [responseType, response] = readSequenceChildren(responseBytes.value);
	if (responseType === undefined || response?.tag !== 0x04) throw new Error('expected response');
	return sequence([
		sliceElement(responseDer, status),
		explicitContext(
			0,
			sequence([
				sliceElement(responseBytes.value, responseType),
				octetString(withUnusedSignatureBit(response.value)),
			]),
		),
	]);
}

describe('signatureValue with unused bits (RFC 3279 §2.2)', () => {
	it('fails a natively verified signature whose bytes verify once the unused bit is dropped', async () => {
		const chain = await evenSignatureChain();
		const signature = readSequenceChildren(chain.leaf.der)[2];
		if (signature === undefined) throw new Error('expected a signatureValue');
		const leaf = withSignatureValue(chain.leaf.der, bitString(signature.value.subarray(1), 1));
		const input = { intermediates: [chain.intermediate.der], roots: [chain.root.certificate.der] };
		expect(await verifyCertificateChain({ ...input, leaf: chain.leaf.der })).toMatchObject({
			ok: true,
		});
		expect(await verifyCertificateChain({ ...input, leaf })).toMatchObject({
			ok: false,
			code: 'signature_invalid',
			index: 0,
		});
	});

	it.each([
		{
			kind: 'certificate',
			verify: (verifiers: SignatureVerifiers) =>
				verifyCertificateChain({
					leaf: withUnusedSignatureBit(dsaLeaf),
					roots: [dsaCaCert],
					signatureVerifiers: verifiers,
				}),
		},
		{
			kind: 'CSR',
			verify: async (verifiers: SignatureVerifiers) =>
				verifyCertificateSigningRequest(withUnusedSignatureBit(await dsaFixture('leaf-csr')), {
					signatureVerifiers: verifiers,
				}),
		},
		{
			kind: 'CRL',
			verify: (verifiers: SignatureVerifiers) =>
				verifyCertificateRevocationListSignature(withUnusedSignatureBit(dsaCrl), dsaCaCert, {
					signatureVerifiers: verifiers,
				}),
		},
		{
			kind: 'OCSP response',
			verify: (verifiers: SignatureVerifiers) =>
				verifyOcspResponseSignature(ocspWithUnusedSignatureBit(dsaOcspResponse), dsaCaCert, {
					signatureVerifiers: verifiers,
				}),
		},
	])('parses a DSA $kind and hands the verifier its unused bits', async ({ verify }) => {
		const inputs: SignatureVerifierInput[] = [];
		const verifiers: SignatureVerifiers = {
			[DSA_WITH_SHA256]: (input) => {
				inputs.push(input);
				return dsaSignatureVerifiers[DSA_WITH_SHA256]?.(input) ?? Promise.resolve(false);
			},
		};
		expect(await verify(verifiers)).toMatchObject({ ok: false, code: 'signature_invalid' });
		expect(inputs.length).toBeGreaterThan(0);
		for (const input of inputs) expect(input.signatureUnusedBits).toBe(1);
	});
});

async function evenSignatureChain(): ReturnType<typeof issueChain> {
	for (let attempt = 0; attempt < 64; attempt += 1) {
		const chain = await issueChain();
		const signature = readSequenceChildren(chain.leaf.der)[2]?.value;
		if (signature !== undefined && ((signature[signature.length - 1] ?? 1) & 1) === 0) return chain;
	}
	throw new Error('no ECDSA signature ending in a zero bit after 64 chains');
}

type CertificateExtensions = Parameters<typeof createCertificate>[0]['extensions'];

/**
 * A certificate built with an ECDSA key for its names and extensions, then
 * rekeyed to `key` and signed by `issuer` under the parameter signature algorithm.
 */
async function parameterCertificate(
	commonName: string,
	key: ParameterKey,
	issuer: { readonly commonName: string; readonly key: ParameterKey } | 'self',
	extensions: CertificateExtensions,
): Promise<Uint8Array> {
	const built =
		issuer === 'self'
			? (
					await createSelfSignedCertificate({
						subject: { commonName },
						...(extensions === undefined ? {} : { extensions }),
					})
				).certificate.der
			: (
					await createCertificate({
						issuer: { commonName: issuer.commonName },
						subject: { commonName },
						publicKey: (await generateKeyPair()).publicKey,
						signerPrivateKey: (await generateKeyPair()).privateKey,
						...(extensions === undefined ? {} : { extensions }),
					})
				).der;
	return await rekeyedCertificate(built, key, issuer === 'self' ? key : issuer.key);
}

const CA_EXTENSIONS = {
	basicConstraints: { ca: true },
	keyUsage: ['keyCertSign', 'cRLSign'],
} as const satisfies CertificateExtensions;
const RESPONDER_EXTENSIONS = {
	extendedKeyUsage: ['ocspSigning'],
} as const satisfies CertificateExtensions;

async function delegatedOcspResponse(
	leaf: Uint8Array,
	issuer: Uint8Array,
	responderKey: ParameterKey,
	embedded: readonly Uint8Array[],
	when: Date,
): Promise<Uint8Array> {
	const stand = await createSelfSignedCertificate({ subject: { commonName: 'Stand-in Signer' } });
	const built = await createOcspResponse({
		signerPrivateKey: stand.keyPair.privateKey,
		signerCertificate: stand.certificate.der,
		responses: [
			{
				certificate: leaf,
				issuerCertificate: issuer,
				certStatus: 'good',
				thisUpdate: new Date(when.getTime() - 60_000),
				nextUpdate: new Date(when.getTime() + 60_000),
			},
		],
	});
	return await resignedOcspResponse(built.der, responderKey, embedded);
}

describe('revocation signers and inherited key parameters', () => {
	it('validates a responder under an issuer whose key inherits its parameters', async () => {
		const root = parameterKey('P', true);
		const ca = parameterKey('P', false);
		const responder = parameterKey('P', false);
		const leaf = parameterKey('P', false);
		const rootDer = await parameterCertificate('Parameter Root', root, 'self', CA_EXTENSIONS);
		const caIssuer = { commonName: 'Parameter Root', key: root };
		const caDer = await parameterCertificate('Parameter CA', ca, caIssuer, CA_EXTENSIONS);
		const underCa = { commonName: 'Parameter CA', key: ca };
		const responderDer = await parameterCertificate(
			'Parameter Responder',
			responder,
			underCa,
			RESPONDER_EXTENSIONS,
		);
		const leafDer = await parameterCertificate('parameter-leaf.example', leaf, underCa, undefined);
		const now = new Date(Date.now() + 5_000);
		const result = await checkChainRevocation({
			chain: [leafDer, caDer, rootDer].map((der) => unwrap(parseCertificateDer(der))),
			ocspResponses: [await delegatedOcspResponse(leafDer, caDer, responder, [responderDer], now)],
			at: now,
			signatureVerifiers: parameterSignatureVerifiers,
		});
		expect(result.value.certificates[0]).toMatchObject({
			status: 'good',
			source: { kind: 'ocsp' },
		});
	});

	it('verifies a chained responder with the parameters its own path gives it', async () => {
		const issuer = parameterKey('P1', true);
		const intermediate = parameterKey('P2', true);
		const responder = parameterKey('P2', false);
		const leaf = parameterKey('P1', false);
		const issuerDer = await parameterCertificate('Parameter Issuer', issuer, 'self', CA_EXTENSIONS);
		const underIssuer = { commonName: 'Parameter Issuer', key: issuer };
		const intermediateDer = await parameterCertificate(
			'Parameter Responder CA',
			intermediate,
			underIssuer,
			CA_EXTENSIONS,
		);
		const responderDer = await parameterCertificate(
			'Parameter Chained Responder',
			responder,
			{ commonName: 'Parameter Responder CA', key: intermediate },
			RESPONDER_EXTENSIONS,
		);
		const leafDer = await parameterCertificate(
			'parameter-chained.example',
			leaf,
			underIssuer,
			undefined,
		);
		const now = new Date(Date.now() + 5_000);
		expect(
			await validateOcspResponse({
				response: await delegatedOcspResponse(
					leafDer,
					issuerDer,
					responder,
					[responderDer, intermediateDer],
					now,
				),
				issuerCertificate: issuerDer,
				allowChainedResponderCertificate: true,
				responderRevocationPolicy: 'skip',
				at: now,
				signatureVerifiers: parameterSignatureVerifiers,
			}),
		).toMatchObject({ ok: true });
	});

	it('authenticates a CRL from a separate signer with the parameters its path gives it', async () => {
		const root = parameterKey('P', true);
		const ca = parameterKey('P', false);
		const crlSigner = parameterKey('P', false);
		const leaf = parameterKey('P', false);
		const rootDer = await parameterCertificate('Parameter Root', root, 'self', CA_EXTENSIONS);
		const underRoot = { commonName: 'Parameter Root', key: root };
		const caDer = await parameterCertificate('Parameter CA', ca, underRoot, CA_EXTENSIONS);
		const crlSignerDer = await parameterCertificate('Parameter CA', crlSigner, underRoot, {
			basicConstraints: { ca: true },
			keyUsage: ['cRLSign'],
		});
		const leafDer = await parameterCertificate(
			'parameter-crl.example',
			leaf,
			{ commonName: 'Parameter CA', key: ca },
			undefined,
		);
		const now = new Date(Date.now() + 5_000);
		const stand = await createSelfSignedCertificate({ subject: { commonName: 'Parameter CA' } });
		const built = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: 'Parameter CA' },
			signerPrivateKey: stand.keyPair.privateKey,
			issuerCertificate: stand.certificate.der,
			thisUpdate: new Date(now.getTime() - 60_000),
			nextUpdate: new Date(now.getTime() + 60_000),
		});
		const result = await checkChainRevocation({
			chain: [leafDer, caDer, rootDer].map((der) => unwrap(parseCertificateDer(der))),
			crls: [await resignedCrl(built.der, crlSigner)],
			extraCertificates: [crlSignerDer],
			at: now,
			signatureVerifiers: parameterSignatureVerifiers,
		});
		expect(result.value.certificates[0]).toMatchObject({ status: 'good', source: { kind: 'crl' } });
	});
});
