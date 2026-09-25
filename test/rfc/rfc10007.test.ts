import { describe, expect, it } from 'bun:test';
import {
	checkCertificateRevocationAgainstCrl,
	createCertificateRevocationList,
	createSelfSignedCertificate,
	parseCertificateDerOrThrow,
	validateCertificateRevocationList,
} from '#micro509';
import { readSequenceChildren, sequence } from '#micro509/internal/asn1/der';
import { FAR_FUTURE_NEXT_UPDATE, flattenedText, rfcDir, sliceElement } from '#test/helpers';

const rfc10007 = (await flattenedText(`${rfcDir}/rfc10007.txt`)).replaceAll(' | ', ' ');

const THIS_UPDATE = new Date('2025-01-01T00:00:00Z');
const AT = new Date('2025-01-02T00:00:00Z');

async function crlSignedBy(
	issuer: Awaited<ReturnType<typeof createSelfSignedCertificate>>,
	commonName: string,
) {
	return createCertificateRevocationList({
		issuer: { commonName },
		signerPrivateKey: issuer.keyPair.privateKey,
		issuerPublicKey: issuer.keyPair.publicKey,
		thisUpdate: THIS_UPDATE,
		nextUpdate: FAR_FUTURE_NEXT_UPDATE,
	});
}

function asVersion1(certificateDer: Uint8Array): Uint8Array {
	const [tbsElement, algorithm, signature] = readSequenceChildren(certificateDer);
	if (tbsElement === undefined || algorithm === undefined || signature === undefined) {
		throw new Error('certificate is not a three-field SEQUENCE');
	}
	const tbs = sliceElement(certificateDer, tbsElement);
	const v1Fields = readSequenceChildren(tbs)
		.filter((field) => field.tag !== 0xa0 && field.tag !== 0xa3)
		.map((field) => sliceElement(tbs, field));
	return sequence([
		sequence(v1Fields),
		sliceElement(certificateDer, algorithm),
		sliceElement(certificateDer, signature),
	]);
}

describe('RFC 10007 §4: step (f) of RFC 5280 §6.3.3 requires the key usage extension on a v3 CRL issuer', () => {
	it('prints the sentences this suite relies on', () => {
		expect(rfc10007).toContain(
			"If the version of the CRL issuer's certificate is version 3 (v3), then verify that the key usage extension is present and verify that the cRLSign bit is set.",
		);
		expect(rfc10007).toContain(
			"this check is not performed if the CRL issuer's key is certified using a version 1 (v1) or version 2 (v2) X.509 certificate",
		);
	});

	it('rejects a CRL whose v3 issuer certificate has no key usage extension', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'RFC 10007 no keyUsage' },
			extensions: { basicConstraints: { ca: true } },
		});
		const parsedIssuer = parseCertificateDerOrThrow(issuer.certificate.der);
		expect(parsedIssuer.version).toBe(3);
		expect(parsedIssuer.keyUsage).toBeUndefined();
		const crl = await crlSignedBy(issuer, 'RFC 10007 no keyUsage');

		const result = await validateCertificateRevocationList({
			crl: crl.der,
			issuerCertificate: issuer.certificate.der,
			at: AT,
		});
		expect(result).toMatchObject({ ok: false, code: 'crl_sign_not_permitted' });

		const checked = await checkCertificateRevocationAgainstCrl({
			certificate: issuer.certificate.der,
			crl: crl.der,
			issuerCertificate: issuer.certificate.der,
			at: AT,
		});
		expect(checked).toMatchObject({ ok: false, code: 'crl_sign_not_permitted' });
	});

	it('rejects a CRL whose v3 issuer asserts key usage without cRLSign', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'RFC 10007 keyCertSign only' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] },
		});
		const crl = await crlSignedBy(issuer, 'RFC 10007 keyCertSign only');

		const result = await validateCertificateRevocationList({
			crl: crl.der,
			issuerCertificate: issuer.certificate.der,
			at: AT,
		});
		expect(result).toMatchObject({ ok: false, code: 'crl_sign_not_permitted' });
	});

	it('accepts a CRL whose v3 issuer asserts cRLSign', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'RFC 10007 cRLSign' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const crl = await crlSignedBy(issuer, 'RFC 10007 cRLSign');

		const result = await validateCertificateRevocationList({
			crl: crl.der,
			issuerCertificate: issuer.certificate.der,
			at: AT,
		});
		expect(result.ok).toBe(true);
	});

	it('skips the check for a v1 CRL issuer certificate, which has no extensions field', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'RFC 10007 v1' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] },
		});
		const v1Der = asVersion1(issuer.certificate.der);
		const parsedIssuer = parseCertificateDerOrThrow(v1Der);
		expect(parsedIssuer.version).toBe(1);
		expect(parsedIssuer.keyUsage).toBeUndefined();
		const crl = await crlSignedBy(issuer, 'RFC 10007 v1');

		const result = await validateCertificateRevocationList({
			crl: crl.der,
			issuerCertificate: v1Der,
			at: AT,
		});
		expect(result.ok).toBe(true);
	});
});
