import { describe, expect, it } from 'bun:test';
import { readFile } from 'node:fs/promises';
import type { SignatureVerifierInput, SignatureVerifiers } from '#micro509/crypto';
import { verifySignature } from '#micro509/crypto';
import { readSequenceChildren } from '#micro509/internal/asn1/der';
import { verifyPkcs7SignedData } from '#micro509/pkcs';
import { unwrap } from '#micro509/result';
import {
	checkCertificateRevocation,
	checkCertificateRevocationAgainstCrl,
	checkChainRevocation,
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
import { parseCertificateDer } from '#micro509/x509';
import { callUntyped, issueChain } from '#test/helpers';
import { DSA_WITH_SHA1, dsaSignatureVerifiers } from '#test/oracles/dsa';

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
