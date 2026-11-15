import { expect, test } from 'bun:test';
import {
	checkCertificateRevocationAgainstCrl,
	checkChainRevocation,
	createCertificate,
	createCertificateRevocationList,
	createOcspResponse,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificateDer,
	unwrap,
	validateOcspResponse,
} from '#micro509';
import { hexToBytes } from '#test/helpers';

test.each(['chain', 'ocsp'] as const)(
	'four older current deltas cannot hide a newer permanent revocation through %s',
	async (api) => {
		const at = new Date();
		const hour = 3_600_000;
		const time = (hours: number) => new Date(at.getTime() + hours * hour);
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Newer Stale Review CA' },
			validity: { notBefore: time(-24), notAfter: time(24) },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const keys = await generateKeyPair();
		const responder = await createCertificate({
			issuer: { commonName: 'Newer Stale Review CA' },
			subject: { commonName: 'Review Responder' },
			publicKey: keys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerCertificate: issuer.certificate.der,
			validity: { notBefore: time(-24), notAfter: time(24) },
			extensions: { extendedKeyUsage: ['ocspSigning'] },
		});
		const crl = (number: number, issued: number, next: number, revoked = false) =>
			createCertificateRevocationList({
				issuer: { commonName: 'Newer Stale Review CA' },
				signerPrivateKey: issuer.keyPair.privateKey,
				issuerCertificate: issuer.certificate.der,
				crlNumber: number,
				...(number === 1 ? {} : { baseCrlNumber: 1 }),
				thisUpdate: time(issued),
				nextUpdate: time(next),
				...(revoked
					? {
							revokedCertificates: [
								{
									serialNumber: hexToBytes(
										unwrap(parseCertificateDer(responder.der)).serialNumberHex,
									),
									reasonCode: 'keyCompromise' as const,
									revocationDate: time(-2),
								},
							],
						}
					: {}),
			});
		const base = await crl(1, -8, 8);
		const clean = await Promise.all([2, 3, 4, 5].map((n) => crl(n, n - 9, 8)));
		const revoking = await crl(6, -2, -1, true);
		const direct = await checkCertificateRevocationAgainstCrl({
			certificate: responder.der,
			issuerCertificate: issuer.certificate.der,
			crl: base.der,
			deltaCrl: revoking.der,
			at,
		});
		expect(direct.ok ? direct.value.status : direct.code).toBe('revoked');
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Newer Stale Review CA' },
			subject: { commonName: 'review.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerCertificate: issuer.certificate.der,
			validity: { notBefore: time(-24), notAfter: time(24) },
		});
		const response = await createOcspResponse({
			signerPrivateKey: keys.privateKey,
			signerCertificate: responder.der,
			includedCertificates: [responder.der],
			producedAt: at,
			responses: [
				{
					certificate: leaf.der,
					issuerCertificate: issuer.certificate.der,
					certStatus: 'good',
					thisUpdate: at,
					nextUpdate: time(1),
				},
			],
		});
		const check = async (count: number) => {
			const crls = [base.der, ...clean.slice(0, count).map((item) => item.der), revoking.der];
			if (api === 'ocsp') {
				const result = await validateOcspResponse({
					response: response.der,
					issuerCertificate: issuer.certificate.der,
					at,
					responderRevocationCrls: crls,
				});
				return result.ok ? 'accepted' : result.code;
			}
			const result = await checkChainRevocation({
				chain: [
					unwrap(parseCertificateDer(responder.der)),
					unwrap(parseCertificateDer(issuer.certificate.der)),
				],
				crls,
				at,
				policy: { mode: 'hard-fail' },
			});
			return result.value.decision;
		};
		const expected = api === 'ocsp' ? 'responder_revoked' : 'deny';
		expect(await check(3)).toBe(expected);
		const result = await check(4);
		console.log(api, 'with four older current deltas:', result);
		expect(result).toBe(expected);
	},
);
