import { describe, expect, it } from 'bun:test';
import { readFile } from 'node:fs/promises';
import type { SignatureVerifierInput, SignatureVerifiers } from '#micro509/crypto';
import { readSequenceChildren } from '#micro509/internal/asn1/der';
import { unwrap } from '#micro509/result';
import {
	buildCandidatePath,
	trustAnchorFromCertificate,
	validateCandidatePath,
	verifyCertificateChain,
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
