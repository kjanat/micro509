import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createCertificateRevocationList,
	createSelfSignedCertificate,
	generateKeyPair,
	isCertificateRevoked,
	parseCertificatePem,
	parseCertificateRevocationListDer,
	parseCertificateRevocationListPem,
	pemDecode,
	validateCertificateRevocationList,
	verifyCertificateRevocationList,
} from '#micro509';
import { hexToBytes } from './helpers.ts';

describe('crl', () => {
	it('creates, parses, and verifies CRLs', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'CRL Issuer' },
			subject: { commonName: 'revoked.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const parsedLeaf = parseCertificatePem(leaf.pem);
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'CRL Issuer' },
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			crlNumber: 7,
			revokedCertificates: [{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) }],
		});
		const parsedCrl = parseCertificateRevocationListPem(crl.pem);
		expect(parsedCrl.issuer.commonName).toBe('CRL Issuer');
		expect(parsedCrl.crlNumber).toBe(7);
		expect(parsedCrl.revokedCertificates).toHaveLength(1);
		expect(isCertificateRevoked(parsedLeaf.serialNumberHex, parsedCrl)).toBe(true);
		expect(await verifyCertificateRevocationList(crl.pem, issuer.certificate.pem)).toMatchObject({
			ok: true,
		});

		const wrongSigner = await generateKeyPair();
		const badCrl = await createCertificateRevocationList({
			issuer: { commonName: 'CRL Issuer' },
			signerPrivateKey: wrongSigner.privateKey,
			revokedCertificates: [{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) }],
		});
		expect(await verifyCertificateRevocationList(badCrl.der, issuer.certificate.der)).toMatchObject(
			{
				ok: false,
				code: 'signature_invalid',
			},
		);
	});

	it('parses CRL entry extensions and delta CRL indicator', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Delta CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta CRL Issuer' },
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			crlNumber: 9,
			baseCrlNumber: 8,
			issuingDistributionPointUri: 'http://example.test/idp.crl',
			freshestCrlUris: ['http://example.test/freshest.crl'],
			revokedCertificates: [
				{
					serialNumber: Uint8Array.of(0x01),
					reasonCode: 'keyCompromise',
					invalidityDate: new Date('2024-01-01T00:00:00Z'),
				},
			],
		});
		const parsed = parseCertificateRevocationListPem(crl.pem);
		expect(parsed.baseCrlNumber).toBe(8);
		expect(parsed.issuingDistributionPointUri).toBe('http://example.test/idp.crl');
		expect(parsed.freshestCrlUris).toEqual(['http://example.test/freshest.crl']);
		expect(parsed.revokedCertificates[0]).toMatchObject({
			serialNumberHex: '01',
			reasonCode: 'keyCompromise',
		});
		expect(parsed.revokedCertificates[0]?.invalidityDate?.toISOString()).toBe(
			'2024-01-01T00:00:00.000Z',
		);
	});

	it('validates CRL with issuer linkage and freshness', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'CRL Validate CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: 'Other CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const now = new Date();
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'CRL Validate CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			thisUpdate: now,
			nextUpdate: new Date(now.getTime() + 3_600_000),
		});
		// Valid case
		const valid = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: ca.certificate.pem,
			at: now,
		});
		expect(valid.ok).toBe(true);
		// Wrong issuer
		const wrongIssuer = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: otherCa.certificate.pem,
			at: now,
		});
		expect(wrongIssuer.ok).toBe(false);
		if (!wrongIssuer.ok) {
			expect(wrongIssuer.code).toBe('issuer_mismatch');
		}
		// Stale CRL (well past nextUpdate)
		const stale = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: ca.certificate.pem,
			at: new Date(now.getTime() + 7_200_000),
		});
		expect(stale.ok).toBe(false);
		if (!stale.ok) {
			expect(stale.code).toBe('stale_crl');
		}
		// Barely stale CRL rescued by clock skew tolerance
		// Use 5s margin to avoid ASN.1 second-truncation races
		const staleWithSkew = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: ca.certificate.pem,
			at: new Date(now.getTime() + 3_605_000),
			clockSkewMs: 10_000,
		});
		expect(staleWithSkew.ok).toBe(true);
	});

	it('validates CRL with AKI mismatch', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'AKI CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: 'AKI CRL CA' }, // Same name, different key
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'AKI CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const result = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: otherCa.certificate.pem,
		});
		expect(result.ok).toBe(false);
	});

	it('creates CRL with all revocation reason codes', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Reason CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const reasons = [
			'unspecified',
			'keyCompromise',
			'cACompromise',
			'affiliationChanged',
			'superseded',
			'cessationOfOperation',
			'certificateHold',
			'removeFromCRL',
			'privilegeWithdrawn',
			'aACompromise',
		] as const;
		const revokedCerts = reasons.map((reason, index) => ({
			serialNumber: Uint8Array.of(index + 1),
			reasonCode: reason,
		}));
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Reason CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			revokedCertificates: revokedCerts,
		});
		const parsed = parseCertificateRevocationListPem(crl.pem);
		expect(parsed.revokedCertificates).toHaveLength(reasons.length);
		for (let i = 0; i < reasons.length; i++) {
			expect(parsed.revokedCertificates[i]?.reasonCode).toBe(reasons[i]);
		}
	});

	it('validates CRL with DER sources', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'DER CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const now = new Date();
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'DER CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			thisUpdate: now,
			nextUpdate: new Date(now.getTime() + 3_600_000),
		});
		const caDer = new Uint8Array(pemDecode('CERTIFICATE', ca.certificate.pem));
		// Use DER for both CRL and issuer
		const result = await validateCertificateRevocationList({
			crl: crl.der,
			issuerCertificate: caDer,
			at: now,
		});
		expect(result.ok).toBe(true);
	});

	it('validates CRL with pre-parsed sources', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Parsed CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const now = new Date();
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Parsed CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			thisUpdate: now,
			nextUpdate: new Date(now.getTime() + 3_600_000),
		});
		const parsedCrl = parseCertificateRevocationListPem(crl.pem);
		const parsedCa = parseCertificatePem(ca.certificate.pem);
		const result = await validateCertificateRevocationList({
			crl: parsedCrl,
			issuerCertificate: parsedCa,
			at: now,
		});
		expect(result.ok).toBe(true);
	});

	it('verifyCertificateRevocationList rejects CRL signed by wrong key', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: 'CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		// Sign CRL with ca but verify with otherCa (same subject, different key)
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const result = await verifyCertificateRevocationList(crl.pem, otherCa.certificate.pem);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('signature_invalid');
	});

	it('validateCertificateRevocationList rejects signature with wrong key', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'CRL Validate CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: 'CRL Validate CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		// Create CRL without AKI to bypass AKI check, signed by ca
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'CRL Validate CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			// omit issuerPublicKey → no AKI extension
		});
		const result = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: otherCa.certificate.pem,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('signature_invalid');
	});

	it('verifies CRL with PEM string sources', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'PEM CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'PEM CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const result = await verifyCertificateRevocationList(crl.pem, ca.certificate.pem);
		expect(result.ok).toBe(true);
	});

	it('parseCertificateRevocationListDer handles IDP with no dist point name (lines 586-587)', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'IDP CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		// Create CRL with IDP extension
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'IDP CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPointUri: 'http://crl.example.com/crl.pem',
		});
		const derBytes = new Uint8Array(pemDecode('X509 CRL', crl.pem));
		// Find the IDP OID bytes (2.5.29.28 = 55 1D 1C) in the CRL DER
		const idpOidBytes = [0x55, 0x1d, 0x1c];
		let idpOffset = -1;
		for (let i = 0; i < derBytes.length - 3; i++) {
			if (
				derBytes[i] === idpOidBytes[0] &&
				derBytes[i + 1] === idpOidBytes[1] &&
				derBytes[i + 2] === idpOidBytes[2]
			) {
				idpOffset = i;
				break;
			}
		}
		expect(idpOffset).not.toBe(-1);
		// Inside the IDP SEQUENCE, the distributionPoint is tagged [0] (0xa0).
		// Find all 0xa0 bytes after the IDP OID. The inner one (inside OCTET STRING > SEQUENCE)
		// is the distributionPoint. Change it to 0x81 (onlyContainsUserCerts [1]).
		// Structure: OID, [BOOL critical], OCTET STRING { SEQUENCE { [0] distributionPoint { ... } } }
		// The first 0xa0 after OID is the outer extension wrapper — we need the one inside SEQUENCE.
		// Count 0xa0 occurrences after OID: skip the first one (or two) and modify the deepest.
		let count = 0;
		let targetOffset = -1;
		for (let i = idpOffset + 3; i < derBytes.length; i++) {
			if (derBytes[i] === 0xa0) {
				count++;
				targetOffset = i;
				// The IDP SEQUENCE contains [0] as distributionPoint — it's nested inside
				// outer wrappers. The deepest [0] within ~30 bytes is the one we want.
				if (count >= 2) break; // second 0xa0 after OID is the inner one
			}
		}
		if (targetOffset !== -1) {
			// Change [0] to [1] (onlyContainsUserCerts) — tag 0xa0 → 0x81
			derBytes[targetOffset] = 0x81;
			const modified = parseCertificateRevocationListDer(derBytes);
			expect(modified.issuingDistributionPointUri).toBeUndefined();
		}
	});

	it('parseCertificateRevocationListDer handles AKI with no keyIdentifier (lines 680-682)', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'AKI CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'AKI CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const derBytes = new Uint8Array(pemDecode('X509 CRL', crl.pem));
		// Find AKI OID bytes (2.5.29.35 = 55 1D 23)
		const akiOidBytes = [0x55, 0x1d, 0x23];
		let akiOffset = -1;
		for (let i = 0; i < derBytes.length - 3; i++) {
			if (
				derBytes[i] === akiOidBytes[0] &&
				derBytes[i + 1] === akiOidBytes[1] &&
				derBytes[i + 2] === akiOidBytes[2]
			) {
				akiOffset = i;
				break;
			}
		}
		expect(akiOffset).not.toBe(-1);
		// Find the 0x80 tag (keyIdentifier [0]) after AKI OID and change to 0x82
		// (authorityCertSerialNumber [2]) — which is not 0x80 or 0xa0
		let tagOffset = akiOffset + 3;
		while (tagOffset < derBytes.length && derBytes[tagOffset] !== 0x80) {
			tagOffset++;
		}
		if (tagOffset < derBytes.length) {
			derBytes[tagOffset] = 0x82; // Change keyIdentifier [0] to serialNumber [2]
		}
		const parsed = parseCertificateRevocationListDer(derBytes);
		// AKI was parsed but without keyIdentifier → authorityKeyIdentifier should be undefined
		expect(parsed.authorityKeyIdentifier).toBeUndefined();
	});
});
