import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificatePem,
	unwrap,
} from '#micro509';
import { OIDS } from '#micro509/internal/asn1/oids';
import { pemEncode } from '#micro509/pem';
import {
	createPfx,
	createPkcs7CertBag,
	createPkcs12MacData,
	parsePfxDer,
	parsePfxPem,
	parsePkcs7CertBagDer,
	parsePkcs7CertBagPem,
	parsePkcs7SignedDataPem,
	parsePkcs12MacDataOrThrow,
	verifyPkcs7SignedData,
} from '#micro509/pkcs';
import { createCmsSignedDataWithSignedAttrs } from '#test/helpers';

describe('pkcs domain', () => {
	it('roundtrips passwordless PFX bundles via the PKCS domain', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'PKCS Domain Root' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'PKCS Domain Root' },
			subject: { commonName: 'pkcs-domain-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});

		const pfx = unwrap(
			await createPfx({
				certificates: [
					{
						certificate: leaf.pem,
						attributes: { friendlyName: 'leaf', localKeyId: Uint8Array.of(1, 2, 3) },
					},
					{ certificate: ca.certificate.pem, attributes: { friendlyName: 'root' } },
				],
				privateKeys: [
					{
						privateKey: leafKeys.privateKey,
						attributes: { friendlyName: 'leaf-key', localKeyId: Uint8Array.of(1, 2, 3) },
					},
				],
			}),
		);

		const parsedPem = await parsePfxPem(pfx.pem);
		expect(parsedPem.ok).toBe(true);
		if (!parsedPem.ok) {
			throw new Error(`Expected PFX PEM parse to succeed: ${parsedPem.code}`);
		}
		expect(
			parsedPem.value.certificates.map((certificate) => certificate.subject.values.commonName),
		).toEqual(['pkcs-domain-leaf.example', 'PKCS Domain Root']);
		expect(parsedPem.value.privateKeys).toHaveLength(1);
		expect(parsedPem.value.bags[0]).toMatchObject({
			kind: 'certificate',
			attributes: { friendlyName: 'leaf', localKeyId: '010203' },
		});

		const parsedDer = await parsePfxDer(pfx.der);
		expect(parsedDer.ok).toBe(true);
		if (!parsedDer.ok) {
			throw new Error(`Expected PFX DER parse to succeed: ${parsedDer.code}`);
		}
		expect(parsedDer.value.bags.map((bag) => bag.kind)).toEqual([
			'certificate',
			'certificate',
			'privateKey',
		]);
	});

	it('creates and verifies PKCS#12 MAC data via the PKCS domain', async () => {
		const authenticatedSafe = Uint8Array.of(1, 2, 3, 4, 5);
		const mac = await createPkcs12MacData(authenticatedSafe, {
			password: 'integrity123',
			iterations: 32,
			salt: Uint8Array.of(9, 8, 7, 6),
		});

		expect(mac.parsed).toMatchObject({
			digestAlgorithmOid: OIDS.sha256,
			digestAlgorithmName: 'SHA-256',
			iterations: 32,
			saltHex: '09080706',
		});

		const verified = await parsePkcs12MacDataOrThrow(mac.der, authenticatedSafe, 'integrity123');
		expect(verified).toMatchObject({
			digestAlgorithmOid: OIDS.sha256,
			digestAlgorithmName: 'SHA-256',
			iterations: 32,
			saltHex: '09080706',
			verification: 'valid',
		});

		const wrongPassword = await parsePkcs12MacDataOrThrow(mac.der, authenticatedSafe, 'wrong');
		expect(wrongPassword.verification).toBe('invalid');
		expect(wrongPassword.digestHex).toBe(mac.parsed.digestHex);
	});

	it('round-trips a PFX whose MacData omits the DEFAULT iteration count', async () => {
		const key = await generateKeyPair();
		const cert = await createSelfSignedCertificate({ subject: { commonName: 'PFX Iter One' } });
		const pfx = unwrap(
			await createPfx({
				certificates: [{ certificate: cert.certificate.pem }],
				privateKeys: [{ privateKey: key.privateKey }],
				mac: { password: 'pw', iterations: 1 },
			}),
		);
		const parsed = await parsePfxDer(pfx.der, { password: 'pw' });
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) {
			throw new Error(`Expected PFX DER parse to succeed: ${parsed.code}`);
		}
		expect(parsed.value.macData?.iterations).toBe(1);
		expect(parsed.value.macData?.verification).toBe('valid');
	});

	it('creates and parses PKCS#7 certificate bags via the PKCS domain', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'PKCS7 Domain Root' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'PKCS7 Domain Root' },
			subject: { commonName: 'pkcs7-domain-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
		});

		const bag = unwrap(createPkcs7CertBag([leaf.pem, root.certificate.pem]));
		expect(bag.pem).toContain('BEGIN PKCS7');

		const parsedPem = parsePkcs7CertBagPem(bag.pem);
		expect(parsedPem.ok).toBe(true);
		if (!parsedPem.ok) {
			throw new Error(`Expected PKCS7 PEM parse to succeed: ${parsedPem.code}`);
		}
		expect(parsedPem.value.map((certificate) => certificate.subject.values.commonName)).toEqual([
			'pkcs7-domain-leaf.example',
			'PKCS7 Domain Root',
		]);

		const parsedDer = parsePkcs7CertBagDer(bag.der);
		expect(parsedDer.ok).toBe(true);
		if (!parsedDer.ok) {
			throw new Error(`Expected PKCS7 DER parse to succeed: ${parsedDer.code}`);
		}
		expect(parsedDer.value).toHaveLength(2);
	});

	it('parses and verifies signedData via the PKCS domain', async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'PKCS Domain Signer' },
		});
		const parsedSigner = unwrap(parseCertificatePem(signer.certificate.pem));
		const content = new TextEncoder().encode('pkcs-domain-signed-content');
		const signedDataDer = await createCmsSignedDataWithSignedAttrs(
			parsedSigner,
			signer.keyPair.privateKey,
			content,
		);

		const parsedPem = parsePkcs7SignedDataPem(pemEncode('PKCS7', signedDataDer));
		expect(parsedPem.ok).toBe(true);
		if (!parsedPem.ok) {
			throw new Error(`Expected PKCS7 SignedData PEM parse to succeed: ${parsedPem.code}`);
		}
		expect(parsedPem.value.encapsulatedContent).toEqual(content);
		expect(parsedPem.value.signerInfos[0]).toMatchObject({
			hasSignedAttrs: true,
			digestAlgorithmOid: OIDS.sha256,
			digestAlgorithmName: 'SHA-256',
		});
		expect(parsedPem.value.digestAlgorithmNames).toEqual(['SHA-256']);

		const verified = await verifyPkcs7SignedData(signedDataDer);
		expect(verified.ok).toBe(true);
		if (!verified.ok) {
			throw new Error(`Expected PKCS7 verification to succeed: ${verified.code}`);
		}
		expect(verified.value.encapsulatedContent).toEqual(content);
	});
});
