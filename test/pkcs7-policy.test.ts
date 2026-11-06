import { describe, expect, it } from 'bun:test';
import {
	createPkcs7SignedData,
	createSelfSignedCertificate,
	unwrap,
	verifyPkcs7SignedData,
} from '#micro509';
import { childrenOf } from '#micro509/internal/asn1/asn1';
import type { DerElement } from '#micro509/internal/asn1/der';
import {
	explicitContext,
	integerFromNumber,
	objectIdentifier,
	octetString,
	readElement,
	sequence,
	setOf,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';

function required(element: DerElement | undefined): DerElement {
	if (element === undefined) throw new Error('Missing CMS element');
	return element;
}

function bytes(der: Uint8Array, element: DerElement): Uint8Array {
	return der.slice(element.start - element.headerLength, element.end);
}

function parts(der: Uint8Array) {
	const outer = childrenOf(der, readElement(der));
	const signed = required(childrenOf(der, required(outer[1]))[0]);
	const fields = childrenOf(der, signed);
	const signers = childrenOf(der, required(fields.at(-1)));
	return { fields, signers };
}

function rebuild(
	der: Uint8Array,
	content: Uint8Array | undefined,
	signers: readonly Uint8Array[],
	oid = OIDS.pkcs7Data,
): Uint8Array {
	const { fields } = parts(der);
	return sequence([
		objectIdentifier(OIDS.pkcs7SignedData),
		explicitContext(
			0,
			sequence([
				integerFromNumber(oid === OIDS.pkcs7Data ? 1 : 3),
				bytes(der, required(fields[1])),
				sequence([
					objectIdentifier(oid),
					...(content === undefined ? [] : [explicitContext(0, octetString(content))]),
				]),
				...fields.slice(3, -1).map((field) => bytes(der, field)),
				setOf([...signers]),
			]),
		),
	]);
}

describe('CMS application verification policy', () => {
	it.each([false, true])(
		'rejects signed-attribute transplantation (detached=%s)',
		async (detached) => {
			const identity = await createSelfSignedCertificate({ subject: { commonName: 'CMS policy' } });
			const original = unwrap(
				await createPkcs7SignedData({
					content: new TextEncoder().encode('application payload'),
					signers: [
						{ certificate: identity.certificate.der, privateKey: identity.keyPair.privateKey },
					],
				}),
			).der;
			const signer = required(parts(original).signers[0]);
			const fields = childrenOf(original, signer);
			const attributes = required(fields.find((field) => field.tag === 0xa0));
			const transplanted = bytes(original, attributes);
			transplanted[0] = 0x31;
			const bare = sequence(
				fields.filter((field) => field !== attributes).map((field) => bytes(original, field)),
			);
			const transformed = rebuild(original, detached ? undefined : transplanted, [bare]);
			const options = detached ? { content: transplanted } : {};
			// The same original signature really verifies over the transplanted SET.
			expect(
				await verifyPkcs7SignedData(transformed, { ...options, signedAttributes: 'allowed' }),
			).toMatchObject({ ok: true });
			expect(
				await verifyPkcs7SignedData(transformed, { ...options, signedAttributes: 'forbidden' }),
			).toMatchObject({ ok: true });
			expect(await verifyPkcs7SignedData(transformed, options)).toMatchObject({
				ok: false,
				code: 'signed_attributes_required',
			});
			expect(
				await verifyPkcs7SignedData(original, { signedAttributes: 'forbidden' }),
			).toMatchObject({ ok: false, code: 'signed_attributes_forbidden' });
			expect(
				await verifyPkcs7SignedData(original, { expectedContentTypeOid: OIDS.pkcs7SignedData }),
			).toMatchObject({ ok: false, code: 'content_type_mismatch' });
			const nonData = rebuild(
				original,
				detached ? undefined : transplanted,
				[bare],
				OIDS.pkcs7SignedData,
			);
			for (const signedAttributes of ['allowed', 'forbidden', 'required'] as const) {
				expect(
					await verifyPkcs7SignedData(nonData, {
						...options,
						expectedContentTypeOid: OIDS.pkcs7SignedData,
						signedAttributes,
					}),
				).toMatchObject({ ok: false, code: 'signed_attributes_required' });
			}
			const second = unwrap(
				await createPkcs7SignedData({
					content: transplanted,
					signers: [
						{ certificate: identity.certificate.der, privateKey: identity.keyPair.privateKey },
					],
				}),
			).der;
			const mixed = rebuild(original, detached ? undefined : transplanted, [
				bare,
				bytes(second, required(parts(second).signers[0])),
			]);
			expect(
				await verifyPkcs7SignedData(mixed, { ...options, signedAttributes: 'allowed' }),
			).toMatchObject({ ok: true });
			expect(await verifyPkcs7SignedData(mixed, options)).toMatchObject({
				ok: false,
				code: 'signed_attributes_required',
			});
		},
	);

	it('requires an explicit expected type for non-id-data signatures with attributes', async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'CMS custom type' },
		});
		const cms = unwrap(
			await createPkcs7SignedData({
				content: Uint8Array.of(1),
				encapsulatedContentTypeOid: OIDS.pkcs7SignedData,
				signers: [{ certificate: signer.certificate.der, privateKey: signer.keyPair.privateKey }],
			}),
		);
		expect(await verifyPkcs7SignedData(cms.der)).toMatchObject({
			ok: false,
			code: 'content_type_mismatch',
		});
		expect(
			await verifyPkcs7SignedData(cms.der, { expectedContentTypeOid: OIDS.pkcs7SignedData }),
		).toMatchObject({ ok: true });
		expect(
			await verifyPkcs7SignedData(cms.der, { expectedContentTypeOid: 'invalid' }),
		).toMatchObject({ ok: false, code: 'invalid_options' });
	});
});
