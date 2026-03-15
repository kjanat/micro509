import { describe, expect, it } from 'bun:test';
import { createHash } from 'node:crypto';
import {
	createCertificate,
	createPkcs7CertBagPem,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificatePem,
	parsePkcs7CertBagDer,
	parsePkcs7CertBagPem,
	parsePkcs7SignedDataDer,
	parsePkcs7SignedDataPem,
	verifyPkcs7SignedData,
} from 'micro509';
import {
	concatBytes,
	explicitContext,
	integerFromNumber,
	nullValue,
	objectIdentifier,
	octetString,
	sequence,
	setOf,
	tlv,
} from '#micro509/internal/asn1/der.ts';
import { OIDS } from '#micro509/internal/asn1/oids.ts';
import { getSignatureAlgorithm, signBytes } from '#micro509/internal/crypto/signing.ts';
import {
	createCmsSignedDataWithSignedAttrs,
	createSyntheticPkcs7SignedData,
	hexToBytes,
} from './helpers.ts';

describe('pkcs7', () => {
	it('creates and parses PKCS#7 certificate bags', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'PKCS7 Root' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'PKCS7 Root' },
			subject: { commonName: 'pkcs7-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
		});
		const bag = createPkcs7CertBagPem([leaf.pem, root.certificate.pem]);
		const parsed = parsePkcs7CertBagPem(bag.pem);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		expect(parsed.value.map((certificate) => certificate.subject.values.commonName)).toEqual([
			'pkcs7-leaf.example',
			'PKCS7 Root',
		]);
	});

	it('verifies PKCS#7 signedData with signed attributes (CMS digest-then-sign)', async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'CMS SignedAttrs Signer' },
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const content = new TextEncoder().encode('Hello CMS signed attributes');
		const signedDataDer = await createCmsSignedDataWithSignedAttrs(
			parsedSigner,
			signer.keyPair.privateKey,
			content,
		);
		const result = await verifyPkcs7SignedData(signedDataDer);
		expect(result.ok).toBe(true);
		if (!result.ok) {
			throw new Error(`Verify failed: ${result.code} — ${result.message}`);
		}
		expect(result.value.signerInfos[0]?.hasSignedAttrs).toBe(true);
		expect(result.value.encapsulatedContent).toEqual(content);
	});

	it('rejects PKCS#7 signedData with tampered content (message digest mismatch)', async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'CMS Tamper Test' },
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const content = new TextEncoder().encode('Original content');
		const signedDataDer = await createCmsSignedDataWithSignedAttrs(
			parsedSigner,
			signer.keyPair.privateKey,
			content,
		);
		// Tamper: replace encapsulated content bytes in the DER
		const tampered = new Uint8Array(signedDataDer);
		// Find "Original content" and change first byte
		const target = new TextEncoder().encode('Original content');
		for (let i = 0; i < tampered.length - target.length; i++) {
			if (
				tampered[i] === target[0] &&
				tampered.slice(i, i + target.length).every((b, j) => b === target[j])
			) {
				tampered[i] = 0xff;
				break;
			}
		}
		const result = await verifyPkcs7SignedData(tampered);
		expect(result.ok).toBe(false);
		if (result.ok) throw new Error('unreachable');
		expect(result.code).toBe('message_digest_mismatch');
		expect(result.error.code).toBe('message_digest_mismatch');
	});

	it('parses generic PKCS#7 signedData signer metadata', async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'CMS Signer' },
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const signedDataDer = createSyntheticPkcs7SignedData(parsedSigner);
		const parsed = parsePkcs7SignedDataDer(signedDataDer);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		expect(parsed.value.contentTypeOid).toBe(OIDS.pkcs7SignedData);
		expect(parsed.value.certificates).toHaveLength(1);
		expect(parsed.value.digestAlgorithmNames).toEqual(['SHA-256']);
		expect(parsed.value.signerInfos[0]).toMatchObject({
			version: 1,
			digestAlgorithmOid: OIDS.sha256,
			digestAlgorithmName: 'SHA-256',
			signatureAlgorithmOid: OIDS.sha256WithRSAEncryption,
			signatureAlgorithmName: 'RSA PKCS#1 v1.5 with SHA-256',
			serialNumberHex: parsedSigner.serialNumberHex,
		});
	});

	// -----------------------------------------------------------------------
	// Parse error paths
	// -----------------------------------------------------------------------

	it('parsePkcs7CertBagDer returns failure on malformed DER', () => {
		const result = parsePkcs7CertBagDer(Uint8Array.of(0x00));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePkcs7CertBagPem rejects zero or multiple PKCS7 blocks', () => {
		const noPkcs7 = parsePkcs7CertBagPem('not a PEM');
		expect(noPkcs7.ok).toBe(false);
		if (!noPkcs7.ok) expect(noPkcs7.code).toBe('malformed');
	});

	it('parsePkcs7SignedDataDer rejects non-signedData content type', () => {
		const { objectIdentifier, sequence, octetString, explicitContext } =
			require('#micro509/internal/asn1/der.ts') as typeof import('#micro509/internal/asn1/der.ts');
		const wrong = sequence([
			objectIdentifier(OIDS.pkcs7Data),
			explicitContext(0, octetString(Uint8Array.of(0x01))),
		]);
		const result = parsePkcs7SignedDataDer(wrong);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('not_signed_data');
	});

	it('parsePkcs7SignedDataDer handles malformed content info', () => {
		const { sequence, objectIdentifier } =
			require('#micro509/internal/asn1/der.ts') as typeof import('#micro509/internal/asn1/der.ts');
		const truncated = sequence([objectIdentifier(OIDS.pkcs7SignedData)]);
		const result = parsePkcs7SignedDataDer(truncated);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePkcs7SignedDataPem parses valid PEM', async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'PEM Parse Signer' },
		});
		const bag = createPkcs7CertBagPem([signer.certificate.pem]);
		const result = parsePkcs7SignedDataPem(bag.pem);
		expect(result.ok).toBe(true);
	});

	it('parsePkcs7SignedDataPem rejects empty PEM', () => {
		const result = parsePkcs7SignedDataPem('not a PEM');
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePkcs7SignedDataPem returns malformed for invalid PEM body text', () => {
		const result = parsePkcs7SignedDataPem('-----BEGIN PKCS7-----\n%%%\n-----END PKCS7-----');
		expect(result).toMatchObject({ ok: false, code: 'malformed' });
		if (!result.ok) {
			expect(result.error.code).toBe('malformed');
		}
	});

	// -----------------------------------------------------------------------
	// verifyPkcs7SignedData input variants
	// -----------------------------------------------------------------------

	it('verifyPkcs7SignedData with PEM string input', async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'PEM Verify Signer' },
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const content = new TextEncoder().encode('PEM verify test');
		const der = await createCmsSignedDataWithSignedAttrs(
			parsedSigner,
			signer.keyPair.privateKey,
			content,
		);
		const pem = `-----BEGIN PKCS7-----\n${Buffer.from(der).toString('base64')}\n-----END PKCS7-----`;
		const result = await verifyPkcs7SignedData(pem);
		expect(result.ok).toBe(true);
	});

	it('verifyPkcs7SignedData with pre-parsed object input', async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'Parsed Verify Signer' },
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const content = new TextEncoder().encode('Parsed verify test');
		const der = await createCmsSignedDataWithSignedAttrs(
			parsedSigner,
			signer.keyPair.privateKey,
			content,
		);
		const parsed = parsePkcs7SignedDataDer(der);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		const result = await verifyPkcs7SignedData(parsed.value);
		expect(result.ok).toBe(true);
	});

	it('verifyPkcs7SignedData accepts signer lookup by subject key identifier', async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'SKI Verify Signer' },
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const subjectKeyIdentifier = parsedSigner.subjectKeyIdentifier;
		if (subjectKeyIdentifier === undefined) {
			throw new Error('expected subjectKeyIdentifier');
		}
		const content = new TextEncoder().encode('SKI verify test');
		const der = await createCmsSignedDataWithSignedAttrs(
			parsedSigner,
			signer.keyPair.privateKey,
			content,
		);
		const parsed = parsePkcs7SignedDataDer(der);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		const signerInfo = parsed.value.signerInfos[0];
		if (signerInfo === undefined) {
			throw new Error('expected signer info');
		}
		const {
			issuer: _ignoredIssuer,
			serialNumberHex: _ignoredSerialNumberHex,
			...signerInfoWithoutIssuerAndSerial
		} = signerInfo;
		const result = await verifyPkcs7SignedData({
			...parsed.value,
			signerInfos: [
				{
					...signerInfoWithoutIssuerAndSerial,
					subjectKeyIdentifier,
				},
			],
		});
		expect(result.ok).toBe(true);
	});

	it('verifyPkcs7SignedData does not fall back to SKI when issuer-and-serial is present', async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'Dual Identifier Signer' },
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const subjectKeyIdentifier = parsedSigner.subjectKeyIdentifier;
		if (subjectKeyIdentifier === undefined) {
			throw new Error('expected subjectKeyIdentifier');
		}
		const content = new TextEncoder().encode('Dual identifier test');
		const der = await createCmsSignedDataWithSignedAttrs(
			parsedSigner,
			signer.keyPair.privateKey,
			content,
		);
		const parsed = parsePkcs7SignedDataDer(der);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		const signerInfo = parsed.value.signerInfos[0];
		if (signerInfo === undefined) {
			throw new Error('expected signer info');
		}
		const result = await verifyPkcs7SignedData({
			...parsed.value,
			signerInfos: [
				{
					...signerInfo,
					serialNumberHex: 'deadbeef',
					subjectKeyIdentifier,
				},
			],
		});
		expect(result).toMatchObject({ ok: false, code: 'signer_not_found' });
	});

	it('verifyPkcs7SignedData returns malformed for unsupported signature algorithm', async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'Unsupported PKCS7 Signer' },
		});
		const parsed = parsePkcs7SignedDataDer(
			createSyntheticPkcs7SignedData(parseCertificatePem(signer.certificate.pem)),
		);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		const signerInfo = parsed.value.signerInfos[0];
		if (signerInfo === undefined) throw new Error('expected signer info');
		const result = await verifyPkcs7SignedData({
			...parsed.value,
			encapsulatedContent: new TextEncoder().encode('pkcs7-bad-sig-alg'),
			signerInfos: [
				((existingSignerInfo) => ({
					...existingSignerInfo,
					hasSignedAttrs: false,
					signatureAlgorithmOid: '1.2.3.4.5',
				}))(signerInfo),
			],
		});
		expect(result).toMatchObject({ ok: false, code: 'malformed' });
		if (!result.ok) {
			expect(result.error.code).toBe('malformed');
		}
	});

	it('verifyPkcs7SignedData rejects when signer not found', async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'Signer' },
		});
		const other = await createSelfSignedCertificate({
			subject: { commonName: 'Other' },
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const syntheticData = createSyntheticPkcs7SignedData(parsedSigner);
		// Replace the embedded certificate with a different one
		const parsed = parsePkcs7SignedDataDer(syntheticData);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		const otherParsed = parseCertificatePem(other.certificate.pem);
		const tampered = {
			...parsed.value,
			certificates: [otherParsed],
			encapsulatedContent: new TextEncoder().encode('test'),
		};
		const result = await verifyPkcs7SignedData(tampered);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('signer_not_found');
	});

	it('verifyPkcs7SignedData rejects malformed signedAttrs on pre-parsed input', async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'Malformed Attrs Signer' },
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const content = new TextEncoder().encode('Malformed attrs content');
		const der = await createCmsSignedDataWithSignedAttrs(
			parsedSigner,
			signer.keyPair.privateKey,
			content,
		);
		const parsed = parsePkcs7SignedDataDer(der);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		const signerInfo = parsed.value.signerInfos[0];
		if (signerInfo === undefined) {
			throw new Error('expected signer info');
		}
		const result = await verifyPkcs7SignedData({
			...parsed.value,
			signerInfos: [{ ...signerInfo, signedAttrsDer: Uint8Array.of(0x31, 0x80) }],
		});
		expect(result).toMatchObject({ ok: false, code: 'malformed' });
	});

	it('verifyPkcs7SignedData rejects retagged signedAttrs on pre-parsed input', async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'Retagged Attrs Signer' },
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const content = new TextEncoder().encode('Retagged attrs content');
		const der = await createCmsSignedDataWithSignedAttrs(
			parsedSigner,
			signer.keyPair.privateKey,
			content,
		);
		const parsed = parsePkcs7SignedDataDer(der);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		const signerInfo = parsed.value.signerInfos[0];
		if (signerInfo === undefined || signerInfo.signedAttrsDer === undefined) {
			throw new Error('expected signed attrs');
		}
		const retagged = new Uint8Array(signerInfo.signedAttrsDer);
		retagged[0] = 0x31;
		const result = await verifyPkcs7SignedData({
			...parsed.value,
			signerInfos: [{ ...signerInfo, signedAttrsDer: retagged }],
		});
		expect(result).toMatchObject({ ok: false, code: 'malformed' });
	});

	it('verifies signedData with SHA-384 signed attrs', async () => {
		const rsaKeys = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
			hash: 'SHA-384',
		});
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'SHA384 CMS Signer' },
			keyPair: rsaKeys,
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const content = new TextEncoder().encode('SHA-384 signed data');
		// Build CMS with SHA-384 digest
		const contentDigest = createHash('sha384').update(content).digest();
		const signedAttrsContent = concatBytes([
			sequence([objectIdentifier(OIDS.cmsContentType), setOf([objectIdentifier(OIDS.pkcs7Data)])]),
			sequence([
				objectIdentifier(OIDS.cmsMessageDigest),
				setOf([octetString(new Uint8Array(contentDigest))]),
			]),
		]);
		const signedAttrsForSigning = tlv(0x31, signedAttrsContent);
		const signedAttrsImplicit = tlv(0xa0, signedAttrsContent);
		const sigAlgorithm = getSignatureAlgorithm(rsaKeys.privateKey);
		const sig = await signBytes(rsaKeys.privateKey, sigAlgorithm, signedAttrsForSigning);
		const signerInfo = sequence([
			integerFromNumber(1),
			sequence([
				hexToBytes(parsedSigner.issuer.derHex),
				tlv(0x02, hexToBytes(parsedSigner.serialNumberHex)),
			]),
			sequence([objectIdentifier(OIDS.sha384), nullValue()]),
			signedAttrsImplicit,
			sequence([
				objectIdentifier(sigAlgorithm.algorithmOid),
				...(sigAlgorithm.parameters !== undefined ? [sigAlgorithm.parameters] : []),
			]),
			octetString(sig),
		]);
		const signedData = sequence([
			integerFromNumber(1),
			setOf([sequence([objectIdentifier(OIDS.sha384), nullValue()])]),
			sequence([objectIdentifier(OIDS.pkcs7Data), explicitContext(0, octetString(content))]),
			explicitContext(0, parsedSigner.der),
			setOf([signerInfo]),
		]);
		const der = sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
		const result = await verifyPkcs7SignedData(der);
		expect(result.ok).toBe(true);
	});

	it('rejects signedData when signedAttrs signature is invalid', async () => {
		const rsaKeys = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
		});
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'Bad Sig CMS' },
			keyPair: rsaKeys,
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const content = new TextEncoder().encode('content for bad sig test');
		const contentDigest = createHash('sha256').update(content).digest();
		const signedAttrsContent = concatBytes([
			sequence([objectIdentifier(OIDS.cmsContentType), setOf([objectIdentifier(OIDS.pkcs7Data)])]),
			sequence([
				objectIdentifier(OIDS.cmsMessageDigest),
				setOf([octetString(new Uint8Array(contentDigest))]),
			]),
		]);
		const signedAttrsImplicit = tlv(0xa0, signedAttrsContent);
		const sigAlgorithm = getSignatureAlgorithm(rsaKeys.privateKey);
		// Use a WRONG signature (just random bytes)
		const badSig = new Uint8Array(256);
		badSig[0] = 0x01;
		const signerInfo = sequence([
			integerFromNumber(1),
			sequence([
				hexToBytes(parsedSigner.issuer.derHex),
				tlv(0x02, hexToBytes(parsedSigner.serialNumberHex)),
			]),
			sequence([objectIdentifier(OIDS.sha256), nullValue()]),
			signedAttrsImplicit,
			sequence([
				objectIdentifier(sigAlgorithm.algorithmOid),
				...(sigAlgorithm.parameters !== undefined ? [sigAlgorithm.parameters] : []),
			]),
			octetString(badSig),
		]);
		const signedData = sequence([
			integerFromNumber(1),
			setOf([sequence([objectIdentifier(OIDS.sha256), nullValue()])]),
			sequence([objectIdentifier(OIDS.pkcs7Data), explicitContext(0, octetString(content))]),
			explicitContext(0, parsedSigner.der),
			setOf([signerInfo]),
		]);
		const der = sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
		const result = await verifyPkcs7SignedData(der);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('signature_invalid');
	});

	it('rejects signedData with missing messageDigest attribute', async () => {
		const rsaKeys = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
		});
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'No Digest CMS' },
			keyPair: rsaKeys,
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const content = new TextEncoder().encode('content for no digest');
		// signedAttrs without messageDigest attribute
		const signedAttrsContent = concatBytes([
			sequence([objectIdentifier(OIDS.cmsContentType), setOf([objectIdentifier(OIDS.pkcs7Data)])]),
		]);
		const signedAttrsForSigning = tlv(0x31, signedAttrsContent);
		const signedAttrsImplicit = tlv(0xa0, signedAttrsContent);
		const sigAlgorithm = getSignatureAlgorithm(rsaKeys.privateKey);
		const sig = await signBytes(rsaKeys.privateKey, sigAlgorithm, signedAttrsForSigning);
		const signerInfo = sequence([
			integerFromNumber(1),
			sequence([
				hexToBytes(parsedSigner.issuer.derHex),
				tlv(0x02, hexToBytes(parsedSigner.serialNumberHex)),
			]),
			sequence([objectIdentifier(OIDS.sha256), nullValue()]),
			signedAttrsImplicit,
			sequence([
				objectIdentifier(sigAlgorithm.algorithmOid),
				...(sigAlgorithm.parameters !== undefined ? [sigAlgorithm.parameters] : []),
			]),
			octetString(sig),
		]);
		const signedData = sequence([
			integerFromNumber(1),
			setOf([sequence([objectIdentifier(OIDS.sha256), nullValue()])]),
			sequence([objectIdentifier(OIDS.pkcs7Data), explicitContext(0, octetString(content))]),
			explicitContext(0, parsedSigner.der),
			setOf([signerInfo]),
		]);
		const der = sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
		const result = await verifyPkcs7SignedData(der);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('verifyPkcs7SignedData rejects when encapsulated content missing', async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'No Content Signer' },
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const syntheticData = createSyntheticPkcs7SignedData(parsedSigner);
		const parsed = parsePkcs7SignedDataDer(syntheticData);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		// Build object without encapsulatedContent (exactOptionalPropertyTypes)
		const noContent: import('#micro509').ParsedPkcs7SignedData = {
			contentTypeOid: parsed.value.contentTypeOid,
			version: parsed.value.version,
			digestAlgorithmOids: parsed.value.digestAlgorithmOids,
			digestAlgorithmNames: parsed.value.digestAlgorithmNames,
			encapsulatedContentTypeOid: parsed.value.encapsulatedContentTypeOid,
			certificates: parsed.value.certificates,
			signerInfos: parsed.value.signerInfos,
		};
		const result = await verifyPkcs7SignedData(noContent);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('content_missing');
	});

	it('verifyPkcs7SignedData rejects direct signature verification failure', async () => {
		// Use RSA keys since synthetic data hard-codes sha256WithRSAEncryption
		const rsaKeys = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'Direct Sig Signer' },
			keyPair: rsaKeys,
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const syntheticData = createSyntheticPkcs7SignedData(parsedSigner);
		const parsed = parsePkcs7SignedDataDer(syntheticData);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		// Synthetic data has fake signature — verification must fail
		const withContent = {
			...parsed.value,
			encapsulatedContent: new TextEncoder().encode('test'),
		};
		const result = await verifyPkcs7SignedData(withContent);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('signature_invalid');
	});

	// -----------------------------------------------------------------------
	// parsePkcs7SignedDataDer malformed paths
	// -----------------------------------------------------------------------

	it('parsePkcs7SignedDataDer rejects malformed SignedData inner structure', () => {
		// SignedData with only version, missing digestAlgorithms/encapContentInfo/signerInfos
		const signedData = sequence([integerFromNumber(1)]);
		const der = sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
		const result = parsePkcs7SignedDataDer(der);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePkcs7SignedDataDer rejects malformed EncapsulatedContentInfo', () => {
		// EncapsulatedContentInfo with no children at all
		const signedData = sequence([
			integerFromNumber(1),
			setOf([]),
			sequence([]), // empty encapContentInfo — no contentType
			setOf([]),
		]);
		const der = sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
		const result = parsePkcs7SignedDataDer(der);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePkcs7SignedDataDer handles SignedData without certificates', () => {
		// SignedData without optional certificates [0] IMPLICIT
		const signedData = sequence([
			integerFromNumber(1),
			setOf([sequence([objectIdentifier(OIDS.sha256)])]),
			sequence([objectIdentifier(OIDS.pkcs7Data)]),
			// no certificates
			setOf([]), // signerInfos
		]);
		const der = sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
		const result = parsePkcs7SignedDataDer(der);
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		expect(result.value.certificates).toHaveLength(0);
	});

	it('parsePkcs7SignedDataDer handles empty SignerIdentifier issuer/serial', async () => {
		// Build a SignerInfo with empty issuerAndSerialNumber (just empty SEQUENCE)
		const content = new Uint8Array([0x01, 0x02, 0x03]);
		const rsaKeys = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const cert = await createSelfSignedCertificate({
			subject: { commonName: 'EmptySID' },
			keyPair: rsaKeys,
		});
		const parsedSigner = parseCertificatePem(cert.certificate.pem);
		// SignerInfo with empty issuerAndSerialNumber SEQUENCE
		const signerInfo = sequence([
			integerFromNumber(1),
			sequence([]), // empty issuerAndSerialNumber — no children
			sequence([objectIdentifier(OIDS.sha256)]),
			sequence([objectIdentifier(OIDS.sha256WithRSAEncryption)]),
			octetString(new Uint8Array(64)),
		]);
		const signedData = sequence([
			integerFromNumber(1),
			setOf([sequence([objectIdentifier(OIDS.sha256)])]),
			sequence([objectIdentifier(OIDS.pkcs7Data), explicitContext(0, octetString(content))]),
			explicitContext(0, parsedSigner.der),
			setOf([signerInfo]),
		]);
		const der = sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
		const result = parsePkcs7SignedDataDer(der);
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		// SignerInfo should have undefined issuer/serialNumberHex
		expect(result.value.signerInfos[0]?.issuer).toBeUndefined();
		expect(result.value.signerInfos[0]?.serialNumberHex).toBeUndefined();
	});

	it('createPkcs7CertBagDer with DER certificate source', async () => {
		const { createPkcs7CertBagDer } = await import('#micro509');
		const cert = await createSelfSignedCertificate({
			subject: { commonName: 'DER source' },
		});
		// Pass Uint8Array (covers normalizeCertificateSource Uint8Array branch)
		const der = createPkcs7CertBagDer([cert.certificate.der]);
		const result = parsePkcs7SignedDataDer(der);
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		expect(result.value.certificates).toHaveLength(1);
	});

	it('verifyPkcs7SignedData rejects invalid PEM input', async () => {
		const result = await verifyPkcs7SignedData('not a PEM');
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('verifyPkcs7SignedData rejects malformed DER input', async () => {
		const result = await verifyPkcs7SignedData(Uint8Array.of(0xff, 0xff));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePkcs7SignedDataDer rejects malformed SignerInfo (missing signature)', () => {
		// SignerInfo with version, sid, digestAlg but missing signatureAlg and signature
		const badSignerInfo = sequence([
			integerFromNumber(1),
			sequence([]), // sid
			sequence([objectIdentifier(OIDS.sha256), nullValue()]),
			// missing signatureAlgorithm and signature
		]);
		const signedData = sequence([
			integerFromNumber(1),
			setOf([sequence([objectIdentifier(OIDS.sha256)])]),
			sequence([objectIdentifier(OIDS.pkcs7Data)]),
			setOf([badSignerInfo]),
		]);
		const der = sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
		const result = parsePkcs7SignedDataDer(der);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePkcs7SignedDataDer rejects malformed encapsulated content tag', () => {
		// EncapsulatedContentInfo with content that has wrong tag (not [0])
		const signedData = sequence([
			integerFromNumber(1),
			setOf([]),
			sequence([
				objectIdentifier(OIDS.pkcs7Data),
				// Use SEQUENCE (0x30) instead of EXPLICIT [0] (0xa0)
				sequence([octetString(Uint8Array.of(0x01))]),
			]),
			setOf([]),
		]);
		const der = sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
		const result = parsePkcs7SignedDataDer(der);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('verifies signedData with SHA-512 signed attrs', async () => {
		const rsaKeys = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
			hash: 'SHA-512',
		});
		const signer = await createSelfSignedCertificate({
			subject: { commonName: 'SHA512 CMS Signer' },
			keyPair: rsaKeys,
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const content = new TextEncoder().encode('SHA-512 signed data');
		const contentDigest = createHash('sha512').update(content).digest();
		const signedAttrsContent = concatBytes([
			sequence([objectIdentifier(OIDS.cmsContentType), setOf([objectIdentifier(OIDS.pkcs7Data)])]),
			sequence([
				objectIdentifier(OIDS.cmsMessageDigest),
				setOf([octetString(new Uint8Array(contentDigest))]),
			]),
		]);
		const signedAttrsForSigning = tlv(0x31, signedAttrsContent);
		const signedAttrsImplicit = tlv(0xa0, signedAttrsContent);
		const sigAlgorithm = getSignatureAlgorithm(rsaKeys.privateKey);
		const sig = await signBytes(rsaKeys.privateKey, sigAlgorithm, signedAttrsForSigning);
		const signerInfo = sequence([
			integerFromNumber(1),
			sequence([
				hexToBytes(parsedSigner.issuer.derHex),
				tlv(0x02, hexToBytes(parsedSigner.serialNumberHex)),
			]),
			sequence([objectIdentifier(OIDS.sha512), nullValue()]),
			signedAttrsImplicit,
			sequence([
				objectIdentifier(sigAlgorithm.algorithmOid),
				...(sigAlgorithm.parameters !== undefined ? [sigAlgorithm.parameters] : []),
			]),
			octetString(sig),
		]);
		const signedData = sequence([
			integerFromNumber(1),
			setOf([sequence([objectIdentifier(OIDS.sha512), nullValue()])]),
			sequence([objectIdentifier(OIDS.pkcs7Data), explicitContext(0, octetString(content))]),
			explicitContext(0, parsedSigner.der),
			setOf([signerInfo]),
		]);
		const der = sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
		const result = await verifyPkcs7SignedData(der);
		expect(result.ok).toBe(true);
	});
});

describe('pkcs7: coverage — error paths', () => {
	it('verifyPkcs7SignedData returns signature_invalid for wrong signature without signed attrs', async () => {
		// Build a valid-looking SignedData with a bad signature (no signed attrs path → line 299)
		const rsaKeys = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'PKCS7 Bad Sig CA' },
			keyPair: rsaKeys,
		});
		const parsedSigner = parseCertificatePem(ca.certificate.pem);
		const content = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
		const { getSignatureAlgorithm: getSigAlgo, signBytes: signB } = await import(
			'#micro509/internal/crypto/signing.ts'
		);
		const sigAlgorithm = getSigAlgo(rsaKeys.privateKey);
		// Sign real content but put DIFFERENT content in encapsulated data
		const badSig = await signB(rsaKeys.privateKey, sigAlgorithm, new Uint8Array([0xff]));
		const signerInfo = sequence([
			integerFromNumber(1),
			sequence([
				hexToBytes(parsedSigner.issuer.derHex),
				tlv(0x02, hexToBytes(parsedSigner.serialNumberHex)),
			]),
			sequence([objectIdentifier(OIDS.sha256), nullValue()]),
			// NO signedAttrs — so it takes the direct verify path
			sequence([
				objectIdentifier(sigAlgorithm.algorithmOid),
				...(sigAlgorithm.parameters !== undefined ? [sigAlgorithm.parameters] : []),
			]),
			octetString(badSig),
		]);
		const signedData = sequence([
			integerFromNumber(1),
			setOf([sequence([objectIdentifier(OIDS.sha256), nullValue()])]),
			sequence([objectIdentifier(OIDS.pkcs7Data), explicitContext(0, octetString(content))]),
			explicitContext(0, parsedSigner.der),
			setOf([signerInfo]),
		]);
		const der = sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
		const result = await verifyPkcs7SignedData(der);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('signature_invalid');
	});

	it('verifySignedAttrs returns message_digest_mismatch for wrong-length digest (constantTimeEqual)', async () => {
		// Build CMS with signed attrs but embed a messageDigest of wrong length → line 555
		const rsaKeys = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'PKCS7 Bad Digest CA' },
			keyPair: rsaKeys,
		});
		const parsedSigner = parseCertificatePem(ca.certificate.pem);
		const content = new Uint8Array([0x41, 0x42, 0x43]);
		const { getSignatureAlgorithm: getSigAlgo, signBytes: signB } = await import(
			'#micro509/internal/crypto/signing.ts'
		);
		const sigAlgorithm = getSigAlgo(rsaKeys.privateKey);
		// Build signedAttrs with a WRONG-LENGTH messageDigest (16 bytes instead of 32)
		const wrongDigest = new Uint8Array(16); // SHA-256 should be 32 bytes
		const signedAttrsContent = concatBytes([
			sequence([objectIdentifier(OIDS.cmsContentType), setOf([objectIdentifier(OIDS.pkcs7Data)])]),
			sequence([objectIdentifier(OIDS.cmsMessageDigest), setOf([octetString(wrongDigest)])]),
		]);
		const signedAttrsForSigning = tlv(0x31, signedAttrsContent);
		const signedAttrsImplicit = tlv(0xa0, signedAttrsContent);
		const sig = await signB(rsaKeys.privateKey, sigAlgorithm, signedAttrsForSigning);
		const signerInfo = sequence([
			integerFromNumber(1),
			sequence([
				hexToBytes(parsedSigner.issuer.derHex),
				tlv(0x02, hexToBytes(parsedSigner.serialNumberHex)),
			]),
			sequence([objectIdentifier(OIDS.sha256), nullValue()]),
			signedAttrsImplicit,
			sequence([
				objectIdentifier(sigAlgorithm.algorithmOid),
				...(sigAlgorithm.parameters !== undefined ? [sigAlgorithm.parameters] : []),
			]),
			octetString(sig),
		]);
		const signedData = sequence([
			integerFromNumber(1),
			setOf([sequence([objectIdentifier(OIDS.sha256), nullValue()])]),
			sequence([objectIdentifier(OIDS.pkcs7Data), explicitContext(0, octetString(content))]),
			explicitContext(0, parsedSigner.der),
			setOf([signerInfo]),
		]);
		const der = sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
		const result = await verifyPkcs7SignedData(der);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('message_digest_mismatch');
	});

	it('parsePkcs7SignedDataDer returns malformed when encapsulated content inner tag is not OCTET STRING', () => {
		// Build SignedData where the encapsulated content context [0] contains a non-OCTET-STRING → line 455
		const signedData = sequence([
			integerFromNumber(1),
			setOf([sequence([objectIdentifier(OIDS.sha256), nullValue()])]),
			// EncapsulatedContentInfo: data OID + [0] containing INTEGER instead of OCTET STRING
			sequence([
				objectIdentifier(OIDS.pkcs7Data),
				explicitContext(0, integerFromNumber(99)), // not OCTET STRING
			]),
			setOf([]),
		]);
		const der = sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
		const result = parsePkcs7SignedDataDer(der);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('verifyPkcs7SignedData returns malformed for unsupported digest OID', async () => {
		// Build CMS with signed attrs using MD5 digest OID → line 512-514
		const rsaKeys = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'PKCS7 Bad OID CA' },
			keyPair: rsaKeys,
		});
		const parsedSigner = parseCertificatePem(ca.certificate.pem);
		const content = new Uint8Array([0x01]);
		const { getSignatureAlgorithm: getSigAlgo, signBytes: signB } = await import(
			'#micro509/internal/crypto/signing.ts'
		);
		const sigAlgorithm = getSigAlgo(rsaKeys.privateKey);
		// Use MD5 OID (1.2.840.113549.2.5) as digest algorithm — unsupported
		const md5Oid = '1.2.840.113549.2.5';
		const digest = new Uint8Array(16);
		const signedAttrsContent = concatBytes([
			sequence([objectIdentifier(OIDS.cmsContentType), setOf([objectIdentifier(OIDS.pkcs7Data)])]),
			sequence([objectIdentifier(OIDS.cmsMessageDigest), setOf([octetString(digest)])]),
		]);
		const signedAttrsForSigning = tlv(0x31, signedAttrsContent);
		const signedAttrsImplicit = tlv(0xa0, signedAttrsContent);
		const sig = await signB(rsaKeys.privateKey, sigAlgorithm, signedAttrsForSigning);
		const signerInfo = sequence([
			integerFromNumber(1),
			sequence([
				hexToBytes(parsedSigner.issuer.derHex),
				tlv(0x02, hexToBytes(parsedSigner.serialNumberHex)),
			]),
			// Use MD5 as digest algorithm
			sequence([objectIdentifier(md5Oid), nullValue()]),
			signedAttrsImplicit,
			sequence([
				objectIdentifier(sigAlgorithm.algorithmOid),
				...(sigAlgorithm.parameters !== undefined ? [sigAlgorithm.parameters] : []),
			]),
			octetString(sig),
		]);
		const signedData = sequence([
			integerFromNumber(1),
			setOf([sequence([objectIdentifier(md5Oid), nullValue()])]),
			sequence([objectIdentifier(OIDS.pkcs7Data), explicitContext(0, octetString(content))]),
			explicitContext(0, parsedSigner.der),
			setOf([signerInfo]),
		]);
		const der = sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
		const result = await verifyPkcs7SignedData(der);
		expect(result).toMatchObject({ ok: false, code: 'malformed' });
		if (!result.ok) {
			expect(result.error.code).toBe('malformed');
		}
	});

	it('extractMessageDigest returns undefined when digest tag is not OCTET STRING', async () => {
		// Build CMS with signed attrs where messageDigest value is INTEGER instead of OCTET STRING → line 538
		const rsaKeys = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'PKCS7 Bad Tag CA' },
			keyPair: rsaKeys,
		});
		const parsedSigner = parseCertificatePem(ca.certificate.pem);
		const content = new Uint8Array([0x01]);
		const { getSignatureAlgorithm: getSigAlgo, signBytes: signB } = await import(
			'#micro509/internal/crypto/signing.ts'
		);
		const sigAlgorithm = getSigAlgo(rsaKeys.privateKey);
		// messageDigest attribute with INTEGER value instead of OCTET STRING
		const signedAttrsContent = concatBytes([
			sequence([objectIdentifier(OIDS.cmsContentType), setOf([objectIdentifier(OIDS.pkcs7Data)])]),
			sequence([
				objectIdentifier(OIDS.cmsMessageDigest),
				setOf([integerFromNumber(42)]), // INTEGER, not OCTET STRING
			]),
		]);
		const signedAttrsForSigning = tlv(0x31, signedAttrsContent);
		const signedAttrsImplicit = tlv(0xa0, signedAttrsContent);
		const sig = await signB(rsaKeys.privateKey, sigAlgorithm, signedAttrsForSigning);
		const signerInfo = sequence([
			integerFromNumber(1),
			sequence([
				hexToBytes(parsedSigner.issuer.derHex),
				tlv(0x02, hexToBytes(parsedSigner.serialNumberHex)),
			]),
			sequence([objectIdentifier(OIDS.sha256), nullValue()]),
			signedAttrsImplicit,
			sequence([
				objectIdentifier(sigAlgorithm.algorithmOid),
				...(sigAlgorithm.parameters !== undefined ? [sigAlgorithm.parameters] : []),
			]),
			octetString(sig),
		]);
		const signedData = sequence([
			integerFromNumber(1),
			setOf([sequence([objectIdentifier(OIDS.sha256), nullValue()])]),
			sequence([objectIdentifier(OIDS.pkcs7Data), explicitContext(0, octetString(content))]),
			explicitContext(0, parsedSigner.der),
			setOf([signerInfo]),
		]);
		const der = sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
		const result = await verifyPkcs7SignedData(der);
		expect(result.ok).toBe(false);
		// extractMessageDigest returns undefined → "Missing messageDigest attribute"
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('returns malformed when [0] content wrapper is empty (childAt throw)', () => {
		// ContentInfo: signedData OID + empty [0] EXPLICIT wrapper
		// childAt(der, content, 0, "signedData") → while loop never enters → throws
		const der = sequence([
			objectIdentifier(OIDS.pkcs7SignedData),
			tlv(0xa0, new Uint8Array(0)), // empty [0] CONSTRUCTED CONTEXT
		]);
		const result = parsePkcs7SignedDataDer(der);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});
});
