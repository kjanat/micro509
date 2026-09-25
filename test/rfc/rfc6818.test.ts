import { describe, expect, it } from 'bun:test';
import {
	type CertificatePolicies,
	createSelfSignedCertificate,
	isResultError,
	parseCertificateDerOrThrow,
} from '#micro509';
import { ia5String, objectIdentifier, sequence, utf8String } from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { flattenedText, rfcDir } from '#test/helpers';

const rfc6818 = (await flattenedText(`${rfcDir}/rfc6818.txt`)).replaceAll(' | ', ' ');

const DECOMPOSED_E_ACUTE = String.fromCharCode(0x65, 0x301);
const COMPOSED_E_ACUTE = String.fromCharCode(0xe9);

const POLICY = '1.2.3.4';

function notice(
	explicitText: string,
	explicitTextType?: 'utf8String' | 'ia5String' | 'visibleString' | 'bmpString',
): CertificatePolicies {
	return [
		{
			policyIdentifier: POLICY,
			policyQualifiers: [
				{
					type: 'userNotice',
					explicitText,
					...(explicitTextType === undefined ? {} : { explicitTextType }),
				},
			],
		},
	];
}

function issue(extensions: Parameters<typeof createSelfSignedCertificate>[0]['extensions']) {
	return createSelfSignedCertificate({ subject: { commonName: 'rfc6818.example' }, extensions });
}

function builderErrorCode(run: () => Promise<unknown>): Promise<string | undefined> {
	return run().then(
		() => undefined,
		(error: unknown) => (isResultError(error) ? error.code : undefined),
	);
}

function userNoticePayload(explicitText: Uint8Array): Uint8Array {
	return sequence([
		sequence([
			objectIdentifier(POLICY),
			sequence([
				sequence([objectIdentifier(OIDS.userNoticePolicyQualifier), sequence([explicitText])]),
			]),
		]),
	]);
}

async function receivedType(policies: CertificatePolicies): Promise<string | undefined> {
	const issued = await issue({ certificatePolicies: policies });
	const qualifier = parseCertificateDerOrThrow(issued.certificate.der).certificatePolicies?.[0]
		?.policyQualifiers?.[0];
	return qualifier?.type === 'userNotice' ? qualifier.explicitTextType : undefined;
}

describe('RFC 6818 §3: explicitText encodings (replacing the RFC 5280 §4.2.1.4 paragraph)', () => {
	it('prints the sentences this suite relies on', () => {
		expect(rfc6818).toContain(
			'Conforming CAs SHOULD use the UTF8String encoding for explicitText. VisibleString or BMPString are acceptable but less preferred alternatives. Conforming CAs MUST NOT encode explicitText as IA5String.',
		);
		expect(rfc6818).toContain(
			'The explicitText string SHOULD NOT include any control characters (e.g., U+0000 to U+001F and U+007F to U+009F).',
		);
		expect(rfc6818).toContain(
			'When the UTF8String or BMPString encoding is used, all character sequences SHOULD be normalized according to Unicode normalization form C (NFC) [NFC].',
		);
	});

	it('encodes explicitText as UTF8String by default and as VisibleString or BMPString on request', async () => {
		expect(await receivedType(notice('notice'))).toBe('utf8String');
		expect(await receivedType(notice('notice', 'visibleString'))).toBe('visibleString');
		expect(await receivedType(notice('notice', 'bmpString'))).toBe('bmpString');
	});

	it('reports the received string type when parsing', async () => {
		for (const type of ['utf8String', 'visibleString', 'bmpString'] as const) {
			const issued = await issue({ certificatePolicies: notice('notice', type) });
			expect(parseCertificateDerOrThrow(issued.certificate.der).certificatePolicies).toEqual(
				notice('notice', type),
			);
		}
	});

	it('refuses IA5String explicitText, typed or through customExtensions', async () => {
		expect(
			await builderErrorCode(() => issue({ certificatePolicies: notice('notice', 'ia5String') })),
		).toBe('display_text_ia5_string');
		expect(
			await builderErrorCode(() =>
				issue({
					customExtensions: [
						{ oid: OIDS.certificatePolicies, value: userNoticePayload(ia5String('IA5 notice')) },
					],
				}),
			),
		).toBe('display_text_ia5_string');
	});

	it('accepts a UTF8String explicitText through customExtensions', async () => {
		const issued = await issue({
			customExtensions: [
				{ oid: OIDS.certificatePolicies, value: userNoticePayload(utf8String('UTF8 notice')) },
			],
		});
		expect(parseCertificateDerOrThrow(issued.certificate.der).certificatePolicies).toEqual(
			notice('UTF8 notice', 'utf8String'),
		);
	});

	it('refuses control characters in explicitText', async () => {
		for (const text of ['bell\u0007', 'delete\u007f', 'csi\u009b']) {
			expect(await builderErrorCode(() => issue({ certificatePolicies: notice(text) }))).toBe(
				'display_text_control_character',
			);
		}
	});

	it('refuses UTF8String and BMPString explicitText that is not in NFC', async () => {
		for (const type of ['utf8String', 'bmpString'] as const) {
			expect(
				await builderErrorCode(() =>
					issue({ certificatePolicies: notice(DECOMPOSED_E_ACUTE, type) }),
				),
			).toBe('display_text_not_nfc');
		}
		expect(await receivedType(notice(COMPOSED_E_ACUTE))).toBe('utf8String');
	});

	it('refuses characters a VisibleString or BMPString cannot carry', async () => {
		expect(
			await builderErrorCode(() =>
				issue({ certificatePolicies: notice(`caf${COMPOSED_E_ACUTE}`, 'visibleString') }),
			),
		).toBe('invalid_visible_string');
		expect(
			await builderErrorCode(() =>
				issue({ certificatePolicies: notice('\u{1F600}', 'bmpString') }),
			),
		).toBe('invalid_bmp_string');
	});
});
