import { describe, expect, it } from 'bun:test';
import {
	checkCertificateRevocation,
	checkCertificateRevocationAgainstCrl,
	createCertificate,
	createCertificateRevocationList,
	createOcspResponse,
	createSelfSignedCertificate,
	generateKeyPair,
	matchCertificatePrivateKey,
	parseCertificatePem,
	validateCertificateRevocationList,
	validateOcspResponse,
	verifyCertificateRevocationListSignature,
	verifyOcspResponseSignature,
} from '#micro509';
import { toHex } from '#micro509/internal/asn1/asn1';
import {
	nullValue,
	objectIdentifier,
	octetString,
	sequence,
	setOf,
	tlv,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import {
	appendCertificateExtensions,
	FAR_FUTURE_NEXT_UPDATE,
	issueChain,
	rewriteCertificateSubject,
} from '#test/helpers';

const teletexSubject = sequence([
	setOf([sequence([objectIdentifier(OIDS.commonName), tlv(0x14, Uint8Array.of(0xc1, 0x41))])]),
]);

async function fixture() {
	const chain = await issueChain();
	const crl = await createCertificateRevocationList({
		issuer: { commonName: 'Verify Intermediate CA' },
		signerPrivateKey: chain.intermediateKeys.privateKey,
		issuerPublicKey: chain.intermediateKeys.publicKey,
		nextUpdate: FAR_FUTURE_NEXT_UPDATE,
	});
	const ocsp = await createOcspResponse({
		signerPrivateKey: chain.intermediateKeys.privateKey,
		signerCertificate: chain.intermediate.pem,
		responses: [
			{
				certificate: chain.leaf.pem,
				issuerCertificate: chain.intermediate.pem,
				certStatus: 'good',
			},
		],
	});
	return {
		...chain,
		crl,
		ocsp,
		unsupportedIssuer: rewriteCertificateSubject(chain.intermediate.der, teletexSubject),
		unsupportedLeaf: rewriteCertificateSubject(chain.leaf.der, teletexSubject),
	};
}

const unsupported = { ok: false, code: 'unsupported' };

describe('decode refusals at the CRL boundaries', () => {
	it('verifyCertificateRevocationListSignature reports an undecodable issuer as unsupported', async () => {
		const { crl, unsupportedIssuer } = await fixture();
		expect(
			await verifyCertificateRevocationListSignature(crl.pem, unsupportedIssuer),
		).toMatchObject(unsupported);
	});

	it('validateCertificateRevocationList reports an undecodable issuer as unsupported', async () => {
		const { crl, unsupportedIssuer } = await fixture();
		expect(
			await validateCertificateRevocationList({
				crl: crl.pem,
				issuerCertificate: unsupportedIssuer,
			}),
		).toMatchObject(unsupported);
	});

	it('checkCertificateRevocationAgainstCrl reports an undecodable certificate or issuer as unsupported', async () => {
		const { crl, intermediate, leaf, unsupportedIssuer, unsupportedLeaf } = await fixture();
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: unsupportedLeaf,
				issuerCertificate: intermediate.pem,
				crl: crl.pem,
			}),
		).toMatchObject(unsupported);
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: unsupportedIssuer,
				crl: crl.pem,
			}),
		).toMatchObject(unsupported);
	});

	it('checkCertificateRevocationAgainstCrl reports a distribution point name it cannot decode as unsupported', async () => {
		const { intermediate, intermediateKeys } = await fixture();
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Verify Intermediate CA' },
			subject: { commonName: 'teletex-distribution-point.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'directoryName', derHex: toHex(teletexSubject) }],
						},
					},
				],
			},
		});
		expect(parseCertificatePem(leaf.pem).ok).toBe(true);
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Verify Intermediate CA' },
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'directoryName', derHex: toHex(sequence([])) }],
				},
			},
			nextUpdate: FAR_FUTURE_NEXT_UPDATE,
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: intermediate.pem,
				crl: crl.pem,
			}),
		).toMatchObject(unsupported);
	});
});

describe('decode refusals at the OCSP boundaries', () => {
	it('verifyOcspResponseSignature reports an undecodable signer as unsupported', async () => {
		const { ocsp, unsupportedIssuer } = await fixture();
		expect(await verifyOcspResponseSignature(ocsp.der, unsupportedIssuer)).toMatchObject(
			unsupported,
		);
	});

	it('validateOcspResponse reports an undecodable issuer as unsupported', async () => {
		const { ocsp, unsupportedIssuer } = await fixture();
		expect(
			await validateOcspResponse({ response: ocsp.der, issuerCertificate: unsupportedIssuer }),
		).toMatchObject(unsupported);
	});
});

describe('decode refusals in checkCertificateRevocation', () => {
	it('reports an undecodable certificate as an unsupported indeterminate status', async () => {
		const { crl, intermediate, unsupportedLeaf } = await fixture();
		expect(
			await checkCertificateRevocation({
				certificate: unsupportedLeaf,
				issuerCertificate: intermediate.pem,
				evidence: [{ kind: 'crl', crl: crl.pem }],
			}),
		).toMatchObject({ ok: true, value: { status: 'indeterminate', code: 'unsupported' } });
	});

	it('reports evidence whose issuer is undecodable with the unsupported reason', async () => {
		const { crl, leaf, ocsp, unsupportedIssuer } = await fixture();
		const result = await checkCertificateRevocation({
			certificate: leaf.pem,
			issuerCertificate: unsupportedIssuer,
			evidence: [
				{ kind: 'crl', crl: crl.pem },
				{ kind: 'ocsp', response: ocsp.der },
			],
		});
		expect(result).toMatchObject({
			ok: true,
			value: {
				status: 'indeterminate',
				details: {
					indeterminateEvidence: [
						{ kind: 'crl', code: 'unsupported' },
						{ kind: 'ocsp', code: 'unsupported' },
					],
				},
			},
		});
	});
});

describe('decode refusals in matchCertificatePrivateKey', () => {
	it('reports an undecodable certificate as unsupported', async () => {
		const { leafKeys, unsupportedLeaf } = await fixture();
		expect(await matchCertificatePrivateKey(unsupportedLeaf, leafKeys.privateKey)).toMatchObject(
			unsupported,
		);
	});

	it('reports a certificate over a decoding limit as limit_exceeded', async () => {
		const { certificate, keyPair } = await createSelfSignedCertificate({
			subject: { commonName: 'arc-bound.example' },
		});
		const overlongArc = Uint8Array.of(0x2a, ...new Array<number>(64).fill(0xff), 0x7f);
		const refused = await appendCertificateExtensions(certificate.der, keyPair.privateKey, [
			sequence([tlv(0x06, overlongArc), octetString(nullValue())]),
		]);
		expect(await matchCertificatePrivateKey(refused, keyPair.privateKey)).toMatchObject({
			ok: false,
			code: 'limit_exceeded',
		});
	});
});
