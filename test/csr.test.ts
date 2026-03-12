import { describe, expect, it } from 'bun:test';
import {
	createCertificateSigningRequest,
	findExtension,
	generateKeyPair,
	parseCertificateSigningRequestPem,
	verifyCertificateSigningRequest,
} from '#micro509';
import { readElement } from '#micro509/der.ts';
import { OIDS } from '#micro509/oids.ts';
import { childrenOf, decodeObjectIdentifier } from './helpers.ts';

describe('csr', () => {
	it('includes basicConstraints and customExtensions in CSR requested extensions', async () => {
		const keyPair = await generateKeyPair({ kind: 'ed25519' });
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'csr-bc.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 2 },
				customExtensions: [
					{
						oid: '1.2.3.4.999',
						value: Uint8Array.of(0x05, 0x00),
						critical: true,
					},
				],
			},
		});
		const parsed = parseCertificateSigningRequestPem(csr.pem);
		expect(parsed.basicConstraints).toEqual({ ca: true, pathLength: 2 });
		const custom = findExtension(parsed.requestedExtensions, '1.2.3.4.999');
		expect(custom).toBeDefined();
		expect(custom?.critical).toBe(true);
	});

	it('verifies certificate request signatures for RSA and Ed25519', async () => {
		const rsaKeys = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
			hash: 'SHA-512',
		});
		const rsaCsr = await createCertificateSigningRequest({
			subject: { commonName: 'rsa-csr' },
			publicKey: rsaKeys.publicKey,
			signerPrivateKey: rsaKeys.privateKey,
		});
		expect(await verifyCertificateSigningRequest(rsaCsr.pem)).toMatchObject({
			ok: true,
		});

		const edKeys = await generateKeyPair({ kind: 'ed25519' });
		const edCsr = await createCertificateSigningRequest({
			subject: { commonName: 'ed-csr' },
			publicKey: edKeys.publicKey,
			signerPrivateKey: edKeys.privateKey,
		});
		expect(await verifyCertificateSigningRequest(edCsr.der)).toMatchObject({
			ok: true,
		});
	});

	it('parses CSR without extensionRequest attributes', async () => {
		const keyPair = await generateKeyPair({ kind: 'ed25519' });
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'csr-noext.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
		});
		const parsed = parseCertificateSigningRequestPem(csr.pem);
		expect(parsed.requestedExtensions).toEqual([]);
	});

	it('creates a CSR with extensionRequest attributes', async () => {
		const keyPair = await generateKeyPair({ kind: 'ed25519' });
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'csr.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
			extensions: {
				subjectAltNames: [{ type: 'dns', value: 'csr.example' }],
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['clientAuth', { type: 'oid', value: '1.2.3.4.6' }],
				authorityInfoAccess: [{ method: 'ocsp', uri: 'http://csr.example/ocsp' }],
				crlDistributionPoints: ['http://csr.example/crl'],
			},
		});

		expect(csr.pem).toContain('BEGIN CERTIFICATE REQUEST');
		const top = childrenOf(csr.der, readElement(csr.der));
		const certificationRequestInfo = top[0];
		if (certificationRequestInfo === undefined) {
			throw new Error('Missing certificationRequestInfo');
		}
		const criChildren = childrenOf(csr.der, certificationRequestInfo);
		const attributes = criChildren[3];
		if (attributes === undefined) {
			throw new Error('Missing attributes');
		}
		const attribute = childrenOf(csr.der, attributes)[0];
		if (attribute === undefined) {
			throw new Error('Missing extensionRequest attribute');
		}
		const attributeChildren = childrenOf(csr.der, attribute);
		const oidElement = attributeChildren[0];
		if (oidElement === undefined) {
			throw new Error('Missing attribute OID');
		}
		expect(decodeObjectIdentifier(oidElement.value)).toBe(OIDS.extensionRequest);
		const parsed = parseCertificateSigningRequestPem(csr.pem);
		expect(parsed.subject.values.commonName).toBe('csr.example');
		expect(parsed.subjectAltNames).toEqual([{ type: 'dns', value: 'csr.example' }]);
		expect(parsed.keyUsage).toEqual(['digitalSignature']);
		expect(parsed.extendedKeyUsage).toEqual(['clientAuth', { type: 'oid', value: '1.2.3.4.6' }]);
		expect(parsed.authorityInfoAccess).toEqual([
			{ method: 'ocsp', uri: 'http://csr.example/ocsp' },
		]);
		expect(parsed.crlDistributionPoints).toEqual(['http://csr.example/crl']);
	});

	it('verifies certificate request signatures with WebCrypto', async () => {
		const goodKeyPair = await generateKeyPair({
			kind: 'ecdsa',
			namedCurve: 'P-256',
		});
		const goodCsr = await createCertificateSigningRequest({
			subject: { commonName: 'verify-csr.example' },
			publicKey: goodKeyPair.publicKey,
			signerPrivateKey: goodKeyPair.privateKey,
		});
		expect(await verifyCertificateSigningRequest(goodCsr.pem)).toMatchObject({
			ok: true,
		});

		const wrongSigner = await generateKeyPair({
			kind: 'ecdsa',
			namedCurve: 'P-256',
		});
		const badCsr = await createCertificateSigningRequest({
			subject: { commonName: 'bad-csr.example' },
			publicKey: goodKeyPair.publicKey,
			signerPrivateKey: wrongSigner.privateKey,
		});
		expect(await verifyCertificateSigningRequest(badCsr.der)).toMatchObject({
			ok: false,
			code: 'signature_invalid',
			details: { subjectCommonName: 'bad-csr.example' },
		});
	});
});
