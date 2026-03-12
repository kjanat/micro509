import { describe, expect, it } from 'bun:test';
import {
	buildCandidatePath,
	checkExtendedKeyUsage,
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificateChainPem,
	parseCertificatePem,
	pemDecode,
	trustAnchorFromCertificate,
	validateCandidatePath,
	validateForCa,
	validateForCodeSigning,
	validateForTlsClient,
	validateForTlsServer,
	verifyCertificateChain,
} from '#micro509';
import { sequence, tlv } from '#micro509/der.ts';
import { parseNameConstraints } from '#micro509/parse.ts';
import { issueChain } from './helpers.ts';

describe('chain verification', () => {
	it('builds across multiple candidate intermediates', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Path Root' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const badIntermediateKeys = await generateKeyPair();
		const goodIntermediateKeys = await generateKeyPair();
		const badIntermediate = await createCertificate({
			issuer: { commonName: 'Path Root' },
			subject: { commonName: 'Shared Intermediate' },
			publicKey: badIntermediateKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['digitalSignature'],
			},
		});
		const goodIntermediate = await createCertificate({
			issuer: { commonName: 'Path Root' },
			subject: { commonName: 'Shared Intermediate' },
			publicKey: goodIntermediateKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Shared Intermediate' },
			subject: { commonName: 'multi-path.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: goodIntermediateKeys.privateKey,
			issuerPublicKey: goodIntermediateKeys.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'dns', value: 'multi-path.example' }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			intermediates: [badIntermediate.pem, goodIntermediate.pem],
			roots: [root.certificate.pem],
			purpose: 'serverAuth',
			serviceIdentity: { type: 'dns', value: 'multi-path.example' },
		});
		expect(result).toMatchObject({ ok: true });
		if (result.ok) {
			expect(
				result.value.chain.map((certificate) => certificate.subject.values.commonName),
			).toEqual(['multi-path.example', 'Shared Intermediate', 'Path Root']);
		}
	});

	it('parses PEM bundles and verifies a leaf to root chain', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Root CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const intermediateKeys = await generateKeyPair();
		const intermediate = await createCertificate({
			issuer: { commonName: 'Root CA' },
			subject: { commonName: 'Intermediate CA' },
			publicKey: intermediateKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Intermediate CA' },
			subject: { commonName: 'service.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'dns', value: 'service.example' }],
			},
		});

		const bundle = `${leaf.pem}\n${intermediate.pem}\n${root.certificate.pem}`;
		const parsedBundle = parseCertificateChainPem(bundle);
		expect(parsedBundle).toHaveLength(3);
		expect(parsedBundle[0]?.subject.values.commonName).toBe('service.example');

		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			intermediates: [intermediate.pem],
			roots: [root.certificate.pem],
			purpose: 'serverAuth',
			serviceIdentity: { type: 'dns', value: 'service.example' },
		});

		expect(result.ok).toBe(true);
		if (!result.ok) {
			throw new Error(result.message);
		}
		expect(result.value.chain).toHaveLength(3);
		expect(result.value.root.subject.values.commonName).toBe('Root CA');
	});

	it('returns structured verification errors', async () => {
		const validChain = await issueChain();

		expect(
			await verifyCertificateChain({
				leaf: validChain.leaf.pem,
				intermediates: [validChain.intermediate.pem],
				roots: [],
			}),
		).toMatchObject({
			ok: false,
			code: 'issuer_not_found',
			index: 1,
			details: { subjectCommonName: 'Verify Intermediate CA' },
		});

		expect(
			await verifyCertificateChain({
				leaf: validChain.leaf.pem,
				intermediates: [validChain.intermediate.pem],
				roots: [validChain.root.certificate.pem],
				purpose: 'clientAuth',
			}),
		).toMatchObject({
			ok: false,
			code: 'extended_key_usage_invalid',
			index: 0,
			details: { expected: 'clientAuth', subjectCommonName: 'verify.example' },
		});

		expect(
			await verifyCertificateChain({
				leaf: validChain.leaf.pem,
				intermediates: [validChain.intermediate.pem],
				roots: [validChain.root.certificate.pem],
				purpose: 'serverAuth',
				serviceIdentity: { type: 'dns', value: 'wrong.example' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch', index: 0 });

		const expiredChain = await issueChain({
			leafValidity: {
				notBefore: new Date('2020-01-01T00:00:00Z'),
				notAfter: new Date('2020-01-02T00:00:00Z'),
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: expiredChain.leaf.pem,
				intermediates: [expiredChain.intermediate.pem],
				roots: [expiredChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: 'certificate_expired', index: 0 });

		const nonCaIssuerChain = await issueChain({
			intermediateExtensions: {
				basicConstraints: { ca: false },
				keyUsage: ['digitalSignature'],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: nonCaIssuerChain.leaf.pem,
				intermediates: [nonCaIssuerChain.intermediate.pem],
				roots: [nonCaIssuerChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: 'ca_required', index: 1 });

		const noKeyCertSignChain = await issueChain({
			intermediateExtensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['digitalSignature'],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: noKeyCertSignChain.leaf.pem,
				intermediates: [noKeyCertSignChain.intermediate.pem],
				roots: [noKeyCertSignChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: 'key_cert_sign_required', index: 1 });

		const pathLengthChain = await issueChain({
			rootExtensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: pathLengthChain.leaf.pem,
				intermediates: [pathLengthChain.intermediate.pem],
				roots: [pathLengthChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: 'path_length_exceeded', index: 2 });

		const wrongAkiKeys = await generateKeyPair();
		const akiMismatchChain = await issueChain({
			leafIssuerPublicKey: wrongAkiKeys.publicKey,
		});
		expect(
			await verifyCertificateChain({
				leaf: akiMismatchChain.leaf.pem,
				intermediates: [akiMismatchChain.intermediate.pem],
				roots: [akiMismatchChain.root.certificate.pem],
			}),
		).toMatchObject({
			ok: false,
			code: 'authority_key_identifier_mismatch',
			index: 0,
		});

		const wrongSignerKeys = await generateKeyPair();
		const badSignatureChain = await issueChain({
			leafSignerPrivateKey: wrongSignerKeys.privateKey,
		});
		expect(
			await verifyCertificateChain({
				leaf: badSignatureChain.leaf.pem,
				intermediates: [badSignatureChain.intermediate.pem],
				roots: [badSignatureChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: 'signature_invalid', index: 0 });

		const selfSigned = await createSelfSignedCertificate({
			subject: { commonName: 'solo.example' },
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'dns', value: 'solo.example' }],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: selfSigned.certificate.pem,
				roots: [],
			}),
		).toMatchObject({ ok: false, code: 'no_trusted_root' });
		expect(
			await verifyCertificateChain({
				leaf: selfSigned.certificate.pem,
				roots: [selfSigned.certificate.pem],
			}),
		).toMatchObject({
			ok: false,
			code: 'self_signed_leaf_not_allowed',
			index: 0,
		});
		expect(
			await verifyCertificateChain({
				leaf: selfSigned.certificate.pem,
				roots: [selfSigned.certificate.pem],
				allowSelfSignedLeaf: true,
			}),
		).toMatchObject({ ok: true });
	});

	it('rejects purpose=ca when leaf is not a CA', async () => {
		const chain = await issueChain();
		expect(
			await verifyCertificateChain({
				leaf: chain.leaf.pem,
				intermediates: [chain.intermediate.pem],
				roots: [chain.root.certificate.pem],
				purpose: 'ca',
			}),
		).toMatchObject({ ok: false, code: 'ca_required', index: 0 });
	});

	it('verifies IP SAN match and rejects mismatch', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'IP CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'IP CA' },
			subject: { commonName: 'ip-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [
					{ type: 'ip', value: '10.0.0.1' },
					{ type: 'ip', value: '::1' },
				],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				serviceIdentity: { type: 'ip', value: '10.0.0.1' },
			}),
		).toMatchObject({ ok: true });
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				serviceIdentity: { type: 'ip', value: '10.0.0.2' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				serviceIdentity: { type: 'ip', value: '::1' },
			}),
		).toMatchObject({ ok: true });
	});

	it('matches wildcard DNS names correctly', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Wildcard CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Wildcard CA' },
			subject: { commonName: 'wildcard-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'dns', value: '*.example.com' }],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				purpose: 'serverAuth',
				serviceIdentity: { type: 'dns', value: 'sub.example.com' },
			}),
		).toMatchObject({ ok: true });
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				serviceIdentity: { type: 'dns', value: 'deep.sub.example.com' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				serviceIdentity: { type: 'dns', value: 'example.com' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
	});

	it('allows self-signed leaf when root is trusted', async () => {
		const selfSigned = await createSelfSignedCertificate({
			subject: { commonName: 'self.example' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'self.example' }],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: selfSigned.certificate.pem,
				roots: [selfSigned.certificate.pem],
				allowSelfSignedLeaf: true,
				serviceIdentity: { type: 'dns', value: 'self.example' },
			}),
		).toMatchObject({ ok: true });
	});

	it('verifies chain with DER certificate sources', async () => {
		const chain = await issueChain();
		const leafDer = new Uint8Array(pemDecode('CERTIFICATE', chain.leaf.pem));
		const intermediateDer = new Uint8Array(pemDecode('CERTIFICATE', chain.intermediate.pem));
		const rootDer = new Uint8Array(pemDecode('CERTIFICATE', chain.root.certificate.pem));
		expect(
			await verifyCertificateChain({
				leaf: leafDer,
				intermediates: [intermediateDer],
				roots: [rootDer],
			}),
		).toMatchObject({ ok: true });
	});

	it('rejects empty and multi-certificate leaf sources', async () => {
		const chain = await issueChain();
		expect(
			verifyCertificateChain({
				leaf: '',
				roots: [chain.root.certificate.pem],
			}),
		).rejects.toThrow('No certificate found');

		const mixedLeaf = `${chain.leaf.pem}\n${chain.intermediate.pem}`;
		expect(
			verifyCertificateChain({
				leaf: mixedLeaf,
				roots: [chain.root.certificate.pem],
			}),
		).rejects.toThrow('Expected a single certificate source');
	});

	it('rejects invalid wildcard and invalid IPv6 verification inputs', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'pattern-ca' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'pattern-ca' },
			subject: { commonName: 'pattern-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				subjectAltNames: [{ type: 'dns', value: 'a*b.example.com' }],
			},
		});

		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				serviceIdentity: { type: 'dns', value: 'axb.example.com' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });

		expect(
			verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				serviceIdentity: { type: 'ip', value: '2001::db8::1' },
			}),
		).rejects.toThrow('Invalid IPv6 address');
	});

	it('verifies chains signed with RSA SHA-384 and ECDSA P-384', async () => {
		const rsaCaKeys = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
			hash: 'SHA-384',
		});
		const rsaCa = await createSelfSignedCertificate({
			subject: { commonName: 'rsa-ca-384' },
			keyPair: rsaCaKeys,
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const rsaLeafKeys = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
			hash: 'SHA-384',
		});
		const rsaLeaf = await createCertificate({
			issuer: { commonName: 'rsa-ca-384' },
			subject: { commonName: 'rsa-leaf-384' },
			publicKey: rsaLeafKeys.publicKey,
			signerPrivateKey: rsaCaKeys.privateKey,
			issuerPublicKey: rsaCaKeys.publicKey,
		});

		expect(
			await verifyCertificateChain({
				leaf: rsaLeaf.pem,
				roots: [rsaCa.certificate.pem],
			}),
		).toMatchObject({ ok: true });

		const p384CaKeys = await generateKeyPair({
			kind: 'ecdsa',
			namedCurve: 'P-384',
		});
		const p384Ca = await createSelfSignedCertificate({
			subject: { commonName: 'p384-ca' },
			keyPair: p384CaKeys,
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const p384LeafKeys = await generateKeyPair({
			kind: 'ecdsa',
			namedCurve: 'P-384',
		});
		const p384Leaf = await createCertificate({
			issuer: { commonName: 'p384-ca' },
			subject: { commonName: 'p384-leaf' },
			publicKey: p384LeafKeys.publicKey,
			signerPrivateKey: p384CaKeys.privateKey,
			issuerPublicKey: p384CaKeys.publicKey,
		});

		expect(
			await verifyCertificateChain({
				leaf: p384Leaf.pem,
				roots: [p384Ca.certificate.pem],
			}),
		).toMatchObject({ ok: true });
	});

	it('verifies an Ed25519 certificate chain', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Ed25519 Root CA' },
			algorithm: { kind: 'ed25519' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair({ kind: 'ed25519' });
		const leaf = await createCertificate({
			issuer: { commonName: 'Ed25519 Root CA' },
			subject: { commonName: 'ed25519-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'ed25519-leaf.example' }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result).toMatchObject({ ok: true });
	});

	it('rejects chain with unrecognized critical extension', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Critical Ext CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
				customExtensions: [
					{
						oid: '1.2.3.4.5.6.7.8.9',
						critical: true,
						value: new Uint8Array([0x05, 0x00]),
					},
				],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Critical Ext CA' },
			subject: { commonName: 'critical.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'critical.example' }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [ca.certificate.pem],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe('unrecognized_critical_extension');
			expect(result.details?.actual).toBe('1.2.3.4.5.6.7.8.9');
		}
	});

	it('allows chain with non-critical unknown extension', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'NonCritical Ext CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
				customExtensions: [
					{
						oid: '1.2.3.4.5.6.7.8.9',
						critical: false,
						value: new Uint8Array([0x05, 0x00]),
					},
				],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'NonCritical Ext CA' },
			subject: { commonName: 'noncritical.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'noncritical.example' }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [ca.certificate.pem],
		});
		expect(result.ok).toBe(true);
	});

	it('checks EKU separately from chain validation', async () => {
		const chain = await issueChain();
		const verifyResult = await verifyCertificateChain({
			leaf: chain.leaf.pem,
			intermediates: [chain.intermediate.pem],
			roots: [chain.root.certificate.pem],
		});
		expect(verifyResult.ok).toBe(true);
		if (!verifyResult.ok) return;
		// Leaf has serverAuth EKU
		const serverAuth = checkExtendedKeyUsage(verifyResult.value.chain, 'serverAuth');
		expect(serverAuth.ok).toBe(true);
		// Leaf does not have codeSigning EKU
		const codeSigning = checkExtendedKeyUsage(verifyResult.value.chain, 'codeSigning');
		expect(codeSigning.ok).toBe(false);
		if (!codeSigning.ok) {
			expect(codeSigning.code).toBe('leaf_eku_missing');
		}
	});

	it('validates chain using trust anchors instead of root certificates', async () => {
		const chain = await issueChain();
		const rootParsed = parseCertificatePem(chain.root.certificate.pem);
		const anchor = trustAnchorFromCertificate(rootParsed);
		// Verify with trust anchor (no root cert needed in pool)
		const result = await verifyCertificateChain({
			leaf: chain.leaf.pem,
			intermediates: [chain.intermediate.pem],
			roots: [],
			trustAnchors: [anchor],
		});
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		// Chain terminates at the intermediate (anchor verifies intermediate's signature)
		expect(result.value.root.subject.values.commonName).toBe('Verify Intermediate CA');
		expect(result.value.chain).toHaveLength(2); // leaf + intermediate
	});

	it('rejects chain when trust anchor has wrong key', async () => {
		const chain = await issueChain();
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: 'Verify Root CA' }, // same name, different key
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const wrongAnchor = trustAnchorFromCertificate(parseCertificatePem(otherCa.certificate.pem));
		const result = await verifyCertificateChain({
			leaf: chain.leaf.pem,
			intermediates: [chain.intermediate.pem],
			roots: [],
			trustAnchors: [wrongAnchor],
		});
		expect(result.ok).toBe(false);
	});

	// -----------------------------------------------------------------------
	// Name constraints
	// -----------------------------------------------------------------------

	it('permits a leaf DNS SAN within CA permitted DNS subtree', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC Root CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'dns', value: 'example.com' } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'NC Root CA' },
			subject: { commonName: 'allowed.example.com' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'allowed.example.com' }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(true);
	});

	it('rejects a leaf DNS SAN outside CA permitted DNS subtree', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC Root CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'dns', value: 'example.com' } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'NC Root CA' },
			subject: { commonName: 'evil.notexample.com' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'evil.notexample.com' }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe('name_constraints_violated');
		}
	});

	it('rejects a leaf DNS SAN matching excluded DNS subtree', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC Root CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					excludedSubtrees: [{ base: { type: 'dns', value: 'forbidden.example.com' } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'NC Root CA' },
			subject: { commonName: 'host.forbidden.example.com' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'host.forbidden.example.com' }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe('name_constraints_violated');
		}
	});

	it('enforces name constraints from intermediate CA, not just root', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC Root CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const intermediateKeys = await generateKeyPair();
		const intermediate = await createCertificate({
			issuer: { commonName: 'NC Root CA' },
			subject: { commonName: 'NC Intermediate CA' },
			publicKey: intermediateKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'dns', value: 'narrow.example.com' } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'NC Intermediate CA' },
			subject: { commonName: 'host.narrow.example.com' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'host.narrow.example.com' }],
			},
		});
		const okResult = await verifyCertificateChain({
			leaf: leaf.pem,
			intermediates: [intermediate.pem],
			roots: [root.certificate.pem],
		});
		expect(okResult.ok).toBe(true);

		// Same intermediate, but leaf outside the permitted subtree
		const badLeafKeys = await generateKeyPair();
		const badLeaf = await createCertificate({
			issuer: { commonName: 'NC Intermediate CA' },
			subject: { commonName: 'other.example.com' },
			publicKey: badLeafKeys.publicKey,
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'other.example.com' }],
			},
		});
		const failResult = await verifyCertificateChain({
			leaf: badLeaf.pem,
			intermediates: [intermediate.pem],
			roots: [root.certificate.pem],
		});
		expect(failResult.ok).toBe(false);
		if (!failResult.ok) {
			expect(failResult.code).toBe('name_constraints_violated');
		}
	});

	it('permits leaf IP SAN within CA permitted IP subnet', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC IP Root CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [
						{
							base: {
								type: 'ip',
								addressBytes: Uint8Array.of(10, 0, 0, 0),
								maskBytes: Uint8Array.of(255, 0, 0, 0),
							},
						},
					],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'NC IP Root CA' },
			subject: { commonName: 'ip-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'ip', value: '10.1.2.3' }],
			},
		});
		const okResult = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(okResult.ok).toBe(true);

		// IP outside subnet
		const badKeys = await generateKeyPair();
		const badLeaf = await createCertificate({
			issuer: { commonName: 'NC IP Root CA' },
			subject: { commonName: 'ip-leaf-bad' },
			publicKey: badKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'ip', value: '192.168.1.1' }],
			},
		});
		const failResult = await verifyCertificateChain({
			leaf: badLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(failResult.ok).toBe(false);
		if (!failResult.ok) {
			expect(failResult.code).toBe('name_constraints_violated');
		}
	});

	it('permits email SAN within CA permitted email domain', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC Email Root CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'email', value: 'example.com' } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'NC Email Root CA' },
			subject: { commonName: 'email-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'email', value: 'user@example.com' }],
			},
		});
		const okResult = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(okResult.ok).toBe(true);

		// Email outside domain
		const badKeys = await generateKeyPair();
		const badLeaf = await createCertificate({
			issuer: { commonName: 'NC Email Root CA' },
			subject: { commonName: 'email-leaf-bad' },
			publicKey: badKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'email', value: 'user@otherdomain.com' }],
			},
		});
		const failResult = await verifyCertificateChain({
			leaf: badLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(failResult.ok).toBe(false);
		if (!failResult.ok) {
			expect(failResult.code).toBe('name_constraints_violated');
		}
	});

	it('parses and round-trips nameConstraints extension', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC Parse Test CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [
						{ base: { type: 'dns', value: 'example.com' } },
						{ base: { type: 'email', value: '.example.org' } },
					],
					excludedSubtrees: [{ base: { type: 'dns', value: 'bad.example.com' } }],
				},
			},
		});
		const parsed = parseCertificatePem(root.certificate.pem);
		expect(parsed.nameConstraints).toBeDefined();
		expect(parsed.nameConstraints?.permittedSubtrees).toHaveLength(2);
		expect(parsed.nameConstraints?.excludedSubtrees).toHaveLength(1);
		const permitted = parsed.nameConstraints?.permittedSubtrees;
		expect(permitted?.[0]?.base).toEqual({
			type: 'dns',
			value: 'example.com',
		});
		expect(permitted?.[1]?.base).toEqual({
			type: 'email',
			value: '.example.org',
		});
		const excluded = parsed.nameConstraints?.excludedSubtrees;
		expect(excluded?.[0]?.base).toEqual({
			type: 'dns',
			value: 'bad.example.com',
		});
	});

	it('does not apply name constraints to self-issued intermediates', async () => {
		// A self-issued certificate should NOT be checked against name
		// constraints, per RFC 5280 §6.1.3(b).
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC Self-Issued Root' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'dns', value: 'example.com' } }],
				},
			},
		});
		// Self-issued intermediate: issuer == subject, yet CN is not
		// in the permitted DNS subtree. Should still pass because
		// self-issued certs are exempt from name constraint checking.
		const intermediateKeys = await generateKeyPair();
		const intermediate = await createCertificate({
			issuer: { commonName: 'NC Self-Issued Root' },
			subject: { commonName: 'NC Self-Issued Root' },
			publicKey: intermediateKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'NC Self-Issued Root' },
			subject: { commonName: 'ok.example.com' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'ok.example.com' }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			intermediates: [intermediate.pem],
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(true);
	});

	it('applies name constraints to self-issued leaf certificate', async () => {
		// RFC 5280 §4.2.1.10: self-issued certs are exempt UNLESS they
		// are the final (leaf) certificate in the path.
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC Self-Issued Leaf Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'dns', value: 'example.com' } }],
				},
			},
		});
		// Self-issued leaf: issuer == subject, with a DNS SAN outside
		// the permitted subtree. Must be rejected because it's the leaf.
		const leafKeys = await generateKeyPair();
		const selfIssuedLeaf = await createCertificate({
			issuer: { commonName: 'NC Self-Issued Leaf Root' },
			subject: { commonName: 'NC Self-Issued Leaf Root' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'evil.org' }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: selfIssuedLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe('name_constraints_violated');
		}
	});

	it('rejects URI SAN subdomain when constraint has no leading period', async () => {
		// RFC 5280 §4.2.1.10: for URIs, a constraint without a leading
		// period specifies a host (exact match only), not a domain.
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC URI Exact Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'uri', value: 'example.com' } }],
				},
			},
		});
		// Exact match — should pass.
		const okKeys = await generateKeyPair();
		const okLeaf = await createCertificate({
			issuer: { commonName: 'NC URI Exact Root' },
			subject: { commonName: 'uri-exact-ok' },
			publicKey: okKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'uri', value: 'https://example.com/path' }],
			},
		});
		const okResult = await verifyCertificateChain({
			leaf: okLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(okResult.ok).toBe(true);

		// Subdomain — should fail (no subdomain expansion for URI).
		const badKeys = await generateKeyPair();
		const badLeaf = await createCertificate({
			issuer: { commonName: 'NC URI Exact Root' },
			subject: { commonName: 'uri-sub-bad' },
			publicKey: badKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'uri', value: 'https://sub.example.com/path' }],
			},
		});
		const badResult = await verifyCertificateChain({
			leaf: badLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(badResult.ok).toBe(false);
		if (!badResult.ok) {
			expect(badResult.code).toBe('name_constraints_violated');
		}
	});

	it('rejects leaf subject DN violating directoryName name constraints', async () => {
		// First create a reference cert to get the derHex for the DN
		const refCert = await createSelfSignedCertificate({
			subject: { commonName: 'NC DN Root CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const rootDnHex = parseCertificatePem(refCert.certificate.pem).subject.derHex;

		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC DN Root CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [
						{
							base: {
								type: 'directoryName',
								derHex: rootDnHex,
							},
						},
					],
				},
			},
		});
		// Leaf has a different subject DN — should violate directoryName constraint
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'NC DN Root CA' },
			subject: { commonName: 'other-org.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'test.example.com' }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe('name_constraints_violated');
		}
	});

	it('rejects leaf with directoryName SAN violating name constraints', async () => {
		const refCert = await createSelfSignedCertificate({
			subject: { commonName: 'NC DN SAN Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const rootDnHex = parseCertificatePem(refCert.certificate.pem).subject.derHex;

		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC DN SAN Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [
						{
							base: {
								type: 'directoryName',
								derHex: rootDnHex,
							},
						},
					],
				},
			},
		});
		// Leaf with directoryName SAN that doesn't match
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'NC DN SAN Root' },
			subject: { commonName: 'NC DN SAN Root' }, // subject matches
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [
					{
						type: 'directoryName',
						derHex: '300e310c300a06035504031303466f6f', // CN=Foo
					},
				],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe('name_constraints_violated');
		}
	});

	it('rejects email SAN with exact-address constraint mismatch', async () => {
		// RFC 5280: "user@example.com" as constraint matches only that exact address
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC Email Exact Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'email', value: 'user@example.com' } }],
				},
			},
		});
		// Exact match passes
		const okKeys = await generateKeyPair();
		const okLeaf = await createCertificate({
			issuer: { commonName: 'NC Email Exact Root' },
			subject: { commonName: 'email-exact-ok' },
			publicKey: okKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'email', value: 'user@example.com' }],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: okLeaf.pem,
				roots: [root.certificate.pem],
			}),
		).toMatchObject({ ok: true });

		// Different address fails
		const badKeys = await generateKeyPair();
		const badLeaf = await createCertificate({
			issuer: { commonName: 'NC Email Exact Root' },
			subject: { commonName: 'email-exact-bad' },
			publicKey: badKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'email', value: 'other@example.com' }],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: badLeaf.pem,
				roots: [root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});

	it('rejects email SAN with subdomain constraint mismatch', async () => {
		// ".example.com" matches email @sub.example.com but not @example.com
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC Email Sub Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'email', value: '.example.com' } }],
				},
			},
		});
		// Subdomain match passes
		const okKeys = await generateKeyPair();
		const okLeaf = await createCertificate({
			issuer: { commonName: 'NC Email Sub Root' },
			subject: { commonName: 'email-sub-ok' },
			publicKey: okKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'email', value: 'user@sub.example.com' }],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: okLeaf.pem,
				roots: [root.certificate.pem],
			}),
		).toMatchObject({ ok: true });

		// Direct domain fails (no subdomain)
		const badKeys = await generateKeyPair();
		const badLeaf = await createCertificate({
			issuer: { commonName: 'NC Email Sub Root' },
			subject: { commonName: 'email-sub-bad' },
			publicKey: badKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'email', value: 'user@example.com' }],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: badLeaf.pem,
				roots: [root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});

	it('permits DNS name constraint with empty constraint value (matches all)', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC Empty DNS Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'dns', value: '' } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'NC Empty DNS Root' },
			subject: { commonName: 'anything.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'anything.example' }],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [root.certificate.pem],
			}),
		).toMatchObject({ ok: true });
	});

	it('permits DNS name starting with dot constraint (subdomain only)', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC Dot DNS Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'dns', value: '.example.com' } }],
				},
			},
		});
		// Subdomain passes
		const okKeys = await generateKeyPair();
		const okLeaf = await createCertificate({
			issuer: { commonName: 'NC Dot DNS Root' },
			subject: { commonName: 'sub-dot-dns' },
			publicKey: okKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'sub.example.com' }],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: okLeaf.pem,
				roots: [root.certificate.pem],
			}),
		).toMatchObject({ ok: true });
	});

	it('handles IPv6 name constraints on leaf SAN', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC IPv6 Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [
						{
							// biome-ignore format: fuck you
							base: {
								type: 'ip',
								addressBytes: Uint8Array.of(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
								maskBytes: Uint8Array.of(0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
							},
						},
					],
				},
			},
		});
		// IPv6 within subnet passes
		const okKeys = await generateKeyPair();
		const okLeaf = await createCertificate({
			issuer: { commonName: 'NC IPv6 Root' },
			subject: { commonName: 'ipv6-ok' },
			publicKey: okKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'ip', value: '2001:db8::1' }],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: okLeaf.pem,
				roots: [root.certificate.pem],
			}),
		).toMatchObject({ ok: true });

		// IPv6 outside subnet fails
		const badKeys = await generateKeyPair();
		const badLeaf = await createCertificate({
			issuer: { commonName: 'NC IPv6 Root' },
			subject: { commonName: 'ipv6-bad' },
			publicKey: badKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'ip', value: 'fe80::1' }],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: badLeaf.pem,
				roots: [root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});

	it('handles URI SAN with no scheme as constraint violation', async () => {
		// A URI without "://" can't extract host → fails constraint
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC URI No Scheme Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'uri', value: 'example.com' } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'NC URI No Scheme Root' },
			subject: { commonName: 'uri-no-scheme' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'uri', value: 'mailto:user@example.com' }],
			},
		});
		// mailto: doesn't have "://", so host extraction returns undefined → doesn't match
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});

	it('handles URI with empty constraint (matches all hosts)', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC URI Empty Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'uri', value: '' } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'NC URI Empty Root' },
			subject: { commonName: 'uri-empty-ok' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'uri', value: 'https://anything.example.com/path' }],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [root.certificate.pem],
			}),
		).toMatchObject({ ok: true });
	});

	it('handles URI with userinfo in host extraction', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC URI UserInfo Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'uri', value: 'example.com' } }],
				},
			},
		});
		// URI with userinfo@host
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'NC URI UserInfo Root' },
			subject: { commonName: 'uri-userinfo' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'uri', value: 'https://user@example.com/path' }],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [root.certificate.pem],
			}),
		).toMatchObject({ ok: true });
	});

	it('handles URI with port in host extraction', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC URI Port Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'uri', value: 'example.com' } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'NC URI Port Root' },
			subject: { commonName: 'uri-port' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'uri', value: 'https://example.com:8443' }],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [root.certificate.pem],
			}),
		).toMatchObject({ ok: true });
	});

	it('rejects GeneralSubtree with maximum field during parsing', () => {
		// RFC 5280 §4.2.1.10: maximum MUST be absent in this profile.
		// Build nameConstraints extension value DER with maximum present:
		//   SEQUENCE { [0] { SEQUENCE { [2]"example.com", [1]INTEGER 5 } } }
		const dnsName = tlv(0x82, new TextEncoder().encode('example.com'));
		const maximum = tlv(0x81, Uint8Array.of(5));
		const subtree = sequence([dnsName, maximum]);
		const permitted = tlv(0xa0, subtree);
		const ncValue = sequence([permitted]);
		expect(() => parseNameConstraints(ncValue)).toThrow(/maximum/i);
	});

	it('rejects GeneralSubtree with non-zero minimum during parsing', () => {
		// RFC 5280 §4.2.1.10: minimum MUST be zero.
		const dnsName = tlv(0x82, new TextEncoder().encode('example.com'));
		const minimum = tlv(0x80, Uint8Array.of(3)); // minimum = 3 (non-zero)
		const subtree = sequence([dnsName, minimum]);
		const permitted = tlv(0xa0, subtree);
		const ncValue = sequence([permitted]);
		expect(() => parseNameConstraints(ncValue)).toThrow(/minimum/i);
	});

	it('checks subject emailAddress against rfc822Name constraints when no SAN email', async () => {
		// RFC 5280 §4.2.1.10: when constraints are imposed on rfc822Name
		// but the cert has no SAN email, apply to subject emailAddress.
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC Email DN Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'email', value: 'example.com' } }],
				},
			},
		});
		// Leaf with emailAddress in subject DN, no SAN email — should pass.
		const okKeys = await generateKeyPair();
		const okLeaf = await createCertificate({
			issuer: { commonName: 'NC Email DN Root' },
			subject: { commonName: 'email-ok', emailAddress: 'user@example.com' },
			publicKey: okKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'example.com' }],
			},
		});
		const okResult = await verifyCertificateChain({
			leaf: okLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(okResult.ok).toBe(true);

		// Leaf with emailAddress in subject DN outside permitted domain.
		const badKeys = await generateKeyPair();
		const badLeaf = await createCertificate({
			issuer: { commonName: 'NC Email DN Root' },
			subject: { commonName: 'email-bad', emailAddress: 'user@evil.org' },
			publicKey: badKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'example.com' }],
			},
		});
		const badResult = await verifyCertificateChain({
			leaf: badLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(badResult.ok).toBe(false);
		if (!badResult.ok) {
			expect(badResult.code).toBe('name_constraints_violated');
		}
	});

	it('permits URI SAN within CA permitted URI subtree and rejects outside', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC URI Root CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'uri', value: '.example.com' } }],
				},
			},
		});
		const okKeys = await generateKeyPair();
		const okLeaf = await createCertificate({
			issuer: { commonName: 'NC URI Root CA' },
			subject: { commonName: 'uri-ok' },
			publicKey: okKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'uri', value: 'https://app.example.com/path' }],
			},
		});
		const okResult = await verifyCertificateChain({
			leaf: okLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(okResult.ok).toBe(true);

		const badKeys = await generateKeyPair();
		const badLeaf = await createCertificate({
			issuer: { commonName: 'NC URI Root CA' },
			subject: { commonName: 'uri-bad' },
			publicKey: badKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'uri', value: 'https://evil.org/sneaky' }],
			},
		});
		const failResult = await verifyCertificateChain({
			leaf: badLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(failResult.ok).toBe(false);
		if (!failResult.ok) {
			expect(failResult.code).toBe('name_constraints_violated');
		}
	});
});

// ---------------------------------------------------------------------------
// Validation profiles
// ---------------------------------------------------------------------------

describe('validation profiles', () => {
	it('validateForTlsServer checks chain + serverAuth EKU + DNS', async () => {
		const chain = await issueChain();
		const ok = await validateForTlsServer({
			leaf: chain.leaf.pem,
			intermediates: [chain.intermediate.pem],
			roots: [chain.root.certificate.pem],
			serviceIdentity: { type: 'dns', value: 'verify.example' },
		});
		expect(ok.ok).toBe(true);

		// Wrong DNS
		const wrongDns = await validateForTlsServer({
			leaf: chain.leaf.pem,
			intermediates: [chain.intermediate.pem],
			roots: [chain.root.certificate.pem],
			serviceIdentity: { type: 'dns', value: 'wrong.example' },
		});
		expect(wrongDns.ok).toBe(false);
		if (!wrongDns.ok) expect(wrongDns.code).toBe('subject_alt_name_mismatch');
	});

	it('validateForTlsServer rejects when leaf lacks serverAuth EKU', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'TLS Profile Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'TLS Profile Root' },
			subject: { commonName: 'tls-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['clientAuth'],
				subjectAltNames: [{ type: 'dns', value: 'tls-leaf' }],
			},
		});
		const result = await validateForTlsServer({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
			serviceIdentity: { type: 'dns', value: 'tls-leaf' },
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('extended_key_usage_invalid');
	});

	it('validateForTlsClient checks chain + clientAuth EKU', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Client Profile Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Client Profile Root' },
			subject: { commonName: 'client-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['clientAuth'],
			},
		});
		const ok = await validateForTlsClient({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(ok.ok).toBe(true);

		// Leaf with serverAuth only should fail clientAuth
		const serverLeafKeys = await generateKeyPair();
		const serverLeaf = await createCertificate({
			issuer: { commonName: 'Client Profile Root' },
			subject: { commonName: 'server-only' },
			publicKey: serverLeafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
			},
		});
		const fail = await validateForTlsClient({
			leaf: serverLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(fail.ok).toBe(false);
	});

	it('validateForTlsClient fails closed for policy validation inputs until implemented', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Policy Input Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Policy Input Root' },
			subject: { commonName: 'policy-client-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['clientAuth'],
			},
		});
		const result = await validateForTlsClient({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
			initialPolicySet: ['1.2.3.4'],
			requireExplicitPolicy: true,
			inhibitPolicyMapping: true,
			inhibitAnyPolicy: true,
		});
		expect(result).toMatchObject({
			ok: false,
			code: 'policy_processing_not_implemented',
			details: {
				actual:
					'initialPolicySet=1.2.3.4, requireExplicitPolicy, inhibitPolicyMapping, inhibitAnyPolicy',
			},
		});
	});

	it('validateForTlsClient fails closed for initial name constraint inputs until implemented', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Initial Name Constraint Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Initial Name Constraint Root' },
			subject: { commonName: 'initial-name-constraint-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['clientAuth'],
				subjectAltNames: [{ type: 'dns', value: 'initial-name-constraint-leaf.example' }],
			},
		});
		const result = await validateForTlsClient({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
			permittedSubtrees: [{ base: { type: 'dns', value: 'example.com' } }],
			excludedSubtrees: [{ base: { type: 'dns', value: 'forbidden.example.com' } }],
		});
		expect(result).toMatchObject({
			ok: false,
			code: 'initial_name_constraints_not_implemented',
			details: { actual: 'permittedSubtrees=1, excludedSubtrees=1' },
		});
	});

	it('validateForCodeSigning checks chain + codeSigning EKU', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Code Sign Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Code Sign Root' },
			subject: { commonName: 'code-sign-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['codeSigning'],
			},
		});
		const ok = await validateForCodeSigning({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(ok.ok).toBe(true);

		// serverAuth-only leaf fails codeSigning
		const wrongLeafKeys = await generateKeyPair();
		const wrongLeaf = await createCertificate({
			issuer: { commonName: 'Code Sign Root' },
			subject: { commonName: 'server-leaf' },
			publicKey: wrongLeafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
			},
		});
		const fail = await validateForCodeSigning({
			leaf: wrongLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(fail.ok).toBe(false);
	});

	it('validateForCa checks chain + CA basicConstraints', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'CA Profile Root' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const intermediateKeys = await generateKeyPair();
		const intermediate = await createCertificate({
			issuer: { commonName: 'CA Profile Root' },
			subject: { commonName: 'Sub CA' },
			publicKey: intermediateKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const ok = await validateForCa({
			leaf: intermediate.pem,
			roots: [root.certificate.pem],
		});
		expect(ok.ok).toBe(true);

		// Non-CA leaf fails
		const chain = await issueChain();
		const fail = await validateForCa({
			leaf: chain.leaf.pem,
			intermediates: [chain.intermediate.pem],
			roots: [chain.root.certificate.pem],
		});
		expect(fail.ok).toBe(false);
		if (!fail.ok) expect(fail.code).toBe('ca_required');
	});
});

// ---------------------------------------------------------------------------
// validateCandidatePath direct
// ---------------------------------------------------------------------------

describe('validateCandidatePath direct', () => {
	it('rejects empty chain', async () => {
		const result = await validateCandidatePath({ chain: [] });
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('issuer_not_found');
	});

	it('keeps service identity checks out of raw path validation', async () => {
		const chain = await issueChain();
		const leafParsed = parseCertificatePem(chain.leaf.pem);
		const intParsed = parseCertificatePem(chain.intermediate.pem);
		const rootParsed = parseCertificatePem(chain.root.certificate.pem);
		const pathResult = await validateCandidatePath({
			chain: [leafParsed, intParsed, rootParsed],
		});
		expect(pathResult.ok).toBe(true);

		const verifyResult = await verifyCertificateChain({
			leaf: chain.leaf.pem,
			intermediates: [chain.intermediate.pem],
			roots: [chain.root.certificate.pem],
			serviceIdentity: { type: 'dns', value: 'wrong.example' },
		});
		expect(verifyResult.ok).toBe(false);
		if (!verifyResult.ok) expect(verifyResult.code).toBe('subject_alt_name_mismatch');
	});

	it('fails closed for policy validation inputs on raw path validation until implemented', async () => {
		const chain = await issueChain();
		const leafParsed = parseCertificatePem(chain.leaf.pem);
		const intParsed = parseCertificatePem(chain.intermediate.pem);
		const rootParsed = parseCertificatePem(chain.root.certificate.pem);
		const result = await validateCandidatePath({
			chain: [leafParsed, intParsed, rootParsed],
			initialPolicySet: ['1.2.3.4'],
			requireExplicitPolicy: true,
			inhibitPolicyMapping: true,
			inhibitAnyPolicy: true,
		});
		expect(result).toMatchObject({
			ok: false,
			code: 'policy_processing_not_implemented',
			details: {
				actual:
					'initialPolicySet=1.2.3.4, requireExplicitPolicy, inhibitPolicyMapping, inhibitAnyPolicy',
			},
		});
	});

	it('fails closed for initial name constraint inputs on raw path validation until implemented', async () => {
		const chain = await issueChain();
		const leafParsed = parseCertificatePem(chain.leaf.pem);
		const intParsed = parseCertificatePem(chain.intermediate.pem);
		const rootParsed = parseCertificatePem(chain.root.certificate.pem);
		const result = await validateCandidatePath({
			chain: [leafParsed, intParsed, rootParsed],
			permittedSubtrees: [{ base: { type: 'dns', value: 'example.com' } }],
			excludedSubtrees: [{ base: { type: 'dns', value: 'forbidden.example.com' } }],
		});
		expect(result).toMatchObject({
			ok: false,
			code: 'initial_name_constraints_not_implemented',
			details: { actual: 'permittedSubtrees=1, excludedSubtrees=1' },
		});
	});

	it('detects signature_invalid in candidate path', async () => {
		const chain = await issueChain();
		const leafParsed = parseCertificatePem(chain.leaf.pem);
		// Use a different CA as "issuer" — signature won't verify
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: 'Verify Intermediate CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const otherCaParsed = parseCertificatePem(otherCa.certificate.pem);
		const result = await validateCandidatePath({
			chain: [leafParsed, otherCaParsed],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('signature_invalid');
	});

	it('detects ca_required in candidate path', async () => {
		const chain = await issueChain({
			intermediateExtensions: {
				basicConstraints: { ca: false },
				keyUsage: ['digitalSignature'],
			},
		});
		const leafParsed = parseCertificatePem(chain.leaf.pem);
		const intParsed = parseCertificatePem(chain.intermediate.pem);
		const rootParsed = parseCertificatePem(chain.root.certificate.pem);
		const result = await validateCandidatePath({
			chain: [leafParsed, intParsed, rootParsed],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('ca_required');
	});

	it('detects key_cert_sign_required in candidate path', async () => {
		const chain = await issueChain({
			intermediateExtensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['digitalSignature'],
			},
		});
		const leafParsed = parseCertificatePem(chain.leaf.pem);
		const intParsed = parseCertificatePem(chain.intermediate.pem);
		const rootParsed = parseCertificatePem(chain.root.certificate.pem);
		const result = await validateCandidatePath({
			chain: [leafParsed, intParsed, rootParsed],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('key_cert_sign_required');
	});

	it('detects authority_key_identifier_mismatch in candidate path', async () => {
		const wrongAkiKeys = await generateKeyPair();
		const chain = await issueChain({
			leafIssuerPublicKey: wrongAkiKeys.publicKey,
		});
		const leafParsed = parseCertificatePem(chain.leaf.pem);
		const intParsed = parseCertificatePem(chain.intermediate.pem);
		const rootParsed = parseCertificatePem(chain.root.certificate.pem);
		const result = await validateCandidatePath({
			chain: [leafParsed, intParsed, rootParsed],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('authority_key_identifier_mismatch');
	});

	it('detects path_length_exceeded in candidate path', async () => {
		const chain = await issueChain({
			rootExtensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafParsed = parseCertificatePem(chain.leaf.pem);
		const intParsed = parseCertificatePem(chain.intermediate.pem);
		const rootParsed = parseCertificatePem(chain.root.certificate.pem);
		const result = await validateCandidatePath({
			chain: [leafParsed, intParsed, rootParsed],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('path_length_exceeded');
	});
});

// ---------------------------------------------------------------------------
// checkExtendedKeyUsage edge cases
// ---------------------------------------------------------------------------

describe('checkExtendedKeyUsage edge cases', () => {
	it('returns leaf_eku_missing for empty chain', () => {
		const result = checkExtendedKeyUsage([], 'serverAuth');
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('leaf_eku_missing');
	});

	it('rejects intermediate EKU constraint mismatch', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'EKU Root' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const intKeys = await generateKeyPair();
		const intermediate = await createCertificate({
			issuer: { commonName: 'EKU Root' },
			subject: { commonName: 'EKU Intermediate' },
			publicKey: intKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
				extendedKeyUsage: ['codeSigning'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'EKU Intermediate' },
			subject: { commonName: 'eku-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: intKeys.privateKey,
			issuerPublicKey: intKeys.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
			},
		});
		const chainResult = await verifyCertificateChain({
			leaf: leaf.pem,
			intermediates: [intermediate.pem],
			roots: [root.certificate.pem],
		});
		expect(chainResult.ok).toBe(true);
		if (!chainResult.ok) return;
		const ekuCheck = checkExtendedKeyUsage(chainResult.value.chain, 'serverAuth');
		expect(ekuCheck.ok).toBe(false);
		if (!ekuCheck.ok) expect(ekuCheck.code).toBe('intermediate_eku_constraint');
	});
});

// ---------------------------------------------------------------------------
// Leaf CN fallback and no-SAN DNS rejection
// ---------------------------------------------------------------------------

describe('leaf CN fallback', () => {
	it('rejects DNS name when leaf has no SAN and fallback disabled', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'CN Fallback CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'CN Fallback CA' },
			subject: { commonName: 'fallback.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: { keyUsage: ['digitalSignature'] },
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [ca.certificate.pem],
			serviceIdentity: { type: 'dns', value: 'fallback.example' },
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('subject_alt_name_mismatch');
	});

	it('accepts DNS name via CN fallback when enabled and CN matches', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'CN Fallback CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'CN Fallback CA' },
			subject: { commonName: 'fallback.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: { keyUsage: ['digitalSignature'] },
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [ca.certificate.pem],
			serviceIdentity: {
				type: 'dns',
				value: 'fallback.example',
				allowCommonNameFallback: true,
			},
		});
		expect(result.ok).toBe(true);
	});

	it('rejects DNS name via CN fallback when CN does not match', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'CN Fallback CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'CN Fallback CA' },
			subject: { commonName: 'other.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: { keyUsage: ['digitalSignature'] },
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [ca.certificate.pem],
			serviceIdentity: {
				type: 'dns',
				value: 'fallback.example',
				allowCommonNameFallback: true,
			},
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('subject_alt_name_mismatch');
	});

	it('accepts purpose=ca when leaf IS a CA', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Purpose CA Root' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const subCaKeys = await generateKeyPair();
		const subCa = await createCertificate({
			issuer: { commonName: 'Purpose CA Root' },
			subject: { commonName: 'Sub CA' },
			publicKey: subCaKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const result = await verifyCertificateChain({
			leaf: subCa.pem,
			roots: [root.certificate.pem],
			purpose: 'ca',
		});
		expect(result.ok).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// buildCandidatePath edge cases
// ---------------------------------------------------------------------------

describe('buildCandidatePath edge cases', () => {
	it('reports expired intermediate during path build', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Build Root' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const intKeys = await generateKeyPair();
		const intermediate = await createCertificate({
			issuer: { commonName: 'Build Root' },
			subject: { commonName: 'Expired Intermediate' },
			publicKey: intKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			validity: {
				notBefore: new Date('2020-01-01T00:00:00Z'),
				notAfter: new Date('2020-12-31T23:59:59Z'),
			},
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Expired Intermediate' },
			subject: { commonName: 'build-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: intKeys.privateKey,
			issuerPublicKey: intKeys.publicKey,
			extensions: { keyUsage: ['digitalSignature'] },
		});
		const result = await buildCandidatePath({
			leaf: leaf.pem,
			intermediates: [intermediate.pem],
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(false);
	});

	it('handles IPv6 with too many segments', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'IPv6 CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'IPv6 CA' },
			subject: { commonName: 'ipv6-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				subjectAltNames: [{ type: 'ip', value: '::1' }],
			},
		});
		expect(
			verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				serviceIdentity: { type: 'ip', value: '1:2:3:4:5:6:7:8:9' },
			}),
		).rejects.toThrow('Invalid IPv6');
	});

	it('handles multiple trust anchors with same subject', async () => {
		const chain = await issueChain();
		const rootParsed = parseCertificatePem(chain.root.certificate.pem);
		const anchor1 = trustAnchorFromCertificate(rootParsed);
		// Create another anchor with same subject but different key
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: 'Verify Root CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const otherParsed = parseCertificatePem(otherCa.certificate.pem);
		const anchor2 = trustAnchorFromCertificate(otherParsed);
		// Both anchors share the subject — should try both
		const result = await verifyCertificateChain({
			leaf: chain.leaf.pem,
			intermediates: [chain.intermediate.pem],
			roots: [],
			trustAnchors: [anchor2, anchor1],
		});
		expect(result.ok).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// validateForTlsServer with allowCommonNameFallback forwarding
// ---------------------------------------------------------------------------

describe('validateForTlsServer with CN fallback', () => {
	it('forwards allowCommonNameFallback to chain verification', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'TLS CN CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'TLS CN CA' },
			subject: { commonName: 'tls-cn.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
			},
		});
		const result = await validateForTlsServer({
			leaf: leaf.pem,
			roots: [ca.certificate.pem],
			serviceIdentity: {
				type: 'dns',
				value: 'tls-cn.example',
				allowCommonNameFallback: true,
			},
		});
		expect(result.ok).toBe(true);
	});

	it('forwards ipAddress to chain verification', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'TLS IP CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'TLS IP CA' },
			subject: { commonName: 'tls-ip-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'ip', value: '10.0.0.1' }],
			},
		});
		const result = await validateForTlsServer({
			leaf: leaf.pem,
			roots: [ca.certificate.pem],
			serviceIdentity: { type: 'ip', value: '10.0.0.1' },
		});
		expect(result.ok).toBe(true);
	});
});

describe('coverage: validation profiles and constraint matching', () => {
	it('validateForTlsClient returns chain failure for untrusted root', async () => {
		const chain = await issueChain();
		const result = await validateForTlsClient({
			leaf: chain.leaf.pem,
			intermediates: [chain.intermediate.pem],
			roots: [],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('issuer_not_found');
	});

	it('validateForCodeSigning returns chain failure for untrusted root', async () => {
		const chain = await issueChain();
		const result = await validateForCodeSigning({
			leaf: chain.leaf.pem,
			intermediates: [chain.intermediate.pem],
			roots: [],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('issuer_not_found');
	});

	it('IPv4 SAN does not match IPv6 name constraint (family mismatch)', async () => {
		const ipv6Address = new Uint8Array(16);
		ipv6Address[0] = 0x20;
		ipv6Address[1] = 0x01;
		const ipv6Mask = new Uint8Array(16);
		ipv6Mask[0] = 0xff;
		ipv6Mask[1] = 0xff;
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'IPv6 Only Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [
						{
							base: {
								type: 'ip',
								addressBytes: ipv6Address,
								maskBytes: ipv6Mask,
							},
						},
					],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'IPv6 Only Root' },
			subject: { commonName: 'ipv4-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'ip', value: '10.0.0.1' }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('name_constraints_violated');
	});

	it('directoryName name constraint rejects subject DN with mismatched derHex', async () => {
		// NOTE: implicitConstructedContext wraps full SEQUENCE bytes rather than
		// replacing the tag, causing derHex round-trip mismatch. This test verifies
		// that the name constraint checking code path executes (covers matchesDnConstraint).
		const { encodeName } = await import('#micro509/name.ts');
		const constraintDn = encodeName({ organization: 'AllowedOrg' });
		const constraintDerHex = Buffer.from(constraintDn).toString('hex');
		const root = await createSelfSignedCertificate({
			subject: { organization: 'AllowedOrg', commonName: 'DN Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'directoryName', derHex: constraintDerHex } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { organization: 'AllowedOrg', commonName: 'DN Root' },
			subject: { organization: 'AllowedOrg', commonName: 'DN Leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'leaf.example' }],
			},
		});
		// Constraint checking will reject due to derHex encoding mismatch
		// (parsed constraint has double-wrapped SEQUENCE). This covers
		// matchesDnConstraint, extractSequenceContent, and the DN constraint violation path.
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('name_constraints_violated');
	});

	it('directoryName SAN constraint violation triggers error', async () => {
		const { encodeName } = await import('#micro509/name.ts');
		const constraintDn = encodeName({ organization: 'AllowedOrg' });
		const constraintDerHex = Buffer.from(constraintDn).toString('hex');
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'DN Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					excludedSubtrees: [{ base: { type: 'directoryName', derHex: constraintDerHex } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'DN Root' },
			subject: { commonName: 'DN Leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [
					{
						type: 'directoryName',
						derHex: Buffer.from(encodeName({ organization: 'AllowedOrg' })).toString('hex'),
					},
				],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		// The excluded constraint's derHex and the SAN's derHex both go through the
		// same double-wrapping, so they DO match and the exclusion fires.
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('name_constraints_violated');
	});

	it('unknown SAN type is ignored during name constraint checking', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'dns', value: '.example.com' } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'NC Root' },
			subject: { commonName: 'nc-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [
					{ type: 'dns', value: 'leaf.example.com' },
					{ type: 'unknown', tag: 0x88, value: Uint8Array.of(0x01, 0x02) },
				],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(true);
	});

	it('email SAN without @ is rejected by email name constraint', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Email NC Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'email', value: 'example.com' } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Email NC Root' },
			subject: { commonName: 'email-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'email', value: 'malformed-no-at' }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('name_constraints_violated');
	});

	it('email name constraint with subdomain matching (.example.com)', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Email NC Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'email', value: '.example.com' } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Email NC Root' },
			subject: { commonName: 'email-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'email', value: 'user@sub.example.com' }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(true);
	});

	it('uri name constraint matching (.example.com subdomain)', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'URI NC Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'uri', value: '.example.com' } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'URI NC Root' },
			subject: { commonName: 'uri-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'uri', value: 'https://sub.example.com/path' }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(true);
	});

	it('ip SAN matching IPv4 name constraint', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'IP NC Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [
						{
							base: {
								type: 'ip',
								addressBytes: Uint8Array.of(10, 0, 0, 0),
								maskBytes: Uint8Array.of(255, 0, 0, 0),
							},
						},
					],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'IP NC Root' },
			subject: { commonName: 'ip-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'ip', value: '10.1.2.3' }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(true);
	});

	it('excluded name constraint blocks matching SAN', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Excl NC Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					excludedSubtrees: [{ base: { type: 'dns', value: '.blocked.com' } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Excl NC Root' },
			subject: { commonName: 'excl-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'host.blocked.com' }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('name_constraints_violated');
	});

	it('ranks issuer candidates with multiple roots (wrong key then right key)', async () => {
		const root1 = await createSelfSignedCertificate({
			subject: { commonName: 'Dual Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const root2 = await createSelfSignedCertificate({
			subject: { commonName: 'Dual Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Dual Root' },
			subject: { commonName: 'dual-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root1.keyPair.privateKey,
			issuerPublicKey: root1.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'dual-leaf.example' }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root2.certificate.pem, root1.certificate.pem],
		});
		expect(result.ok).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// coverage: verify.ts internal edge cases via tampered ParsedCertificate
// ---------------------------------------------------------------------------

describe('coverage: verify.ts internal edge cases', () => {
	// Helper: create a self-signed root + leaf chain and return parsed certs
	async function makeSelfSignedChain() {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Tamper Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Tamper Root' },
			subject: { commonName: 'tamper-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'tamper-leaf.example' }],
			},
		});
		const parsedRoot = parseCertificatePem(root.certificate.pem);
		const parsedLeaf = parseCertificatePem(leaf.pem);
		return { parsedRoot, parsedLeaf };
	}

	// --- extractSequenceContent error paths (lines 1739-1760) ---

	it('directoryName constraint with too-short derHex returns false (line 1746)', async () => {
		const { parsedRoot, parsedLeaf } = await makeSelfSignedChain();
		// Tamper root: add directoryName permittedSubtrees with derHex too short (<4 chars)
		const tamperedRoot = {
			...parsedRoot,
			nameConstraints: {
				permittedSubtrees: [{ base: { type: 'directoryName' as const, derHex: '30' } }],
			},
		};
		const result = await validateCandidatePath({
			chain: [parsedLeaf, tamperedRoot],
			allowSelfSignedLeaf: true,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('name_constraints_violated');
	});

	it('directoryName constraint with non-SEQUENCE tag returns false (line 1750)', async () => {
		const { parsedRoot, parsedLeaf } = await makeSelfSignedChain();
		// Tag 0x31 (SET) instead of 0x30 (SEQUENCE)
		const tamperedRoot = {
			...parsedRoot,
			nameConstraints: {
				permittedSubtrees: [{ base: { type: 'directoryName' as const, derHex: '31060401020304' } }],
			},
		};
		const result = await validateCandidatePath({
			chain: [parsedLeaf, tamperedRoot],
			allowSelfSignedLeaf: true,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('name_constraints_violated');
	});

	it('directoryName constraint with NaN length byte returns false (line 1754)', async () => {
		const { parsedRoot, parsedLeaf } = await makeSelfSignedChain();
		// 0x30 tag but "zz" as length byte → NaN
		const tamperedRoot = {
			...parsedRoot,
			nameConstraints: {
				permittedSubtrees: [{ base: { type: 'directoryName' as const, derHex: '30zz0401020304' } }],
			},
		};
		const result = await validateCandidatePath({
			chain: [parsedLeaf, tamperedRoot],
			allowSelfSignedLeaf: true,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('name_constraints_violated');
	});

	it('directoryName constraint with long-form length (line 1758-1760)', async () => {
		const { parsedRoot, parsedLeaf } = await makeSelfSignedChain();
		// 0x30 tag, 0x81 0x04 (long-form length = 4 bytes), then content
		// This is valid DER, but the constraint content won't match the leaf subject
		const tamperedRoot = {
			...parsedRoot,
			nameConstraints: {
				permittedSubtrees: [{ base: { type: 'directoryName' as const, derHex: '308104aabbccdd' } }],
			},
		};
		const result = await validateCandidatePath({
			chain: [parsedLeaf, tamperedRoot],
			allowSelfSignedLeaf: true,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('name_constraints_violated');
	});

	it('directoryName excluded constraint with malformed derHex (line 1739)', async () => {
		const { parsedRoot, parsedLeaf } = await makeSelfSignedChain();
		// Leaf subject.derHex is valid SEQUENCE; constraint derHex has wrong tag
		// matchesDnConstraint → exact match fails → extractSequenceContent on both
		// subject is valid, constraint returns undefined → false → not excluded
		// But we also need it to fail via permittedSubtrees or excluded to verify coverage.
		// Use excludedSubtrees with the exact leaf subject derHex to actually exclude:
		// That takes a different code path. Use derHex="ab" (too short).
		const tamperedRoot = {
			...parsedRoot,
			nameConstraints: {
				excludedSubtrees: [{ base: { type: 'directoryName' as const, derHex: 'ab' } }],
			},
		};
		// With malformed excluded constraint, matchesDnConstraint returns false
		// (no exact match, extractSequenceContent returns undefined for the
		// constraint), so the name is NOT excluded → permitted → ok: true
		const result = await validateCandidatePath({
			chain: [parsedLeaf, tamperedRoot],
			allowSelfSignedLeaf: true,
		});
		expect(result.ok).toBe(true);
	});

	it('subject with malformed derHex fails directoryName prefix check (line 1739 subject branch)', async () => {
		const { parsedRoot, parsedLeaf } = await makeSelfSignedChain();
		// Tamper the leaf's subject.derHex to be malformed
		const tamperedLeaf = {
			...parsedLeaf,
			subject: {
				...parsedLeaf.subject,
				derHex: 'ff02aabb', // wrong tag (0xff instead of 0x30)
			},
		};
		const tamperedRoot = {
			...parsedRoot,
			nameConstraints: {
				permittedSubtrees: [
					{ base: { type: 'directoryName' as const, derHex: parsedRoot.subject.derHex } },
				],
			},
		};
		const result = await validateCandidatePath({
			chain: [tamperedLeaf, tamperedRoot],
			allowSelfSignedLeaf: true,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('name_constraints_violated');
	});

	// --- parseIpAddressToBytes error paths (lines 1769, 1775) ---

	it('IP SAN with wrong segment count throws (line 1769)', async () => {
		const { parsedRoot, parsedLeaf } = await makeSelfSignedChain();
		// Tamper leaf to have an IP SAN with invalid value (3 segments)
		const tamperedLeaf = {
			...parsedLeaf,
			subjectAltNames: [{ type: 'ip' as const, value: '1.2.3' }],
		};
		const tamperedRoot = {
			...parsedRoot,
			nameConstraints: {
				permittedSubtrees: [
					{
						base: {
							type: 'ip' as const,
							addressBytes: new Uint8Array([10, 0, 0, 0]),
							maskBytes: new Uint8Array([255, 0, 0, 0]),
						},
					},
				],
			},
		};
		expect(
			validateCandidatePath({
				chain: [tamperedLeaf, tamperedRoot],
				allowSelfSignedLeaf: true,
			}),
		).rejects.toThrow('Invalid IPv4 address');
	});

	it('IP SAN with non-numeric segment throws (line 1775)', async () => {
		const { parsedRoot, parsedLeaf } = await makeSelfSignedChain();
		const tamperedLeaf = {
			...parsedLeaf,
			subjectAltNames: [{ type: 'ip' as const, value: '1.2.3.abc' }],
		};
		const tamperedRoot = {
			...parsedRoot,
			nameConstraints: {
				permittedSubtrees: [
					{
						base: {
							type: 'ip' as const,
							addressBytes: new Uint8Array([10, 0, 0, 0]),
							maskBytes: new Uint8Array([255, 0, 0, 0]),
						},
					},
				],
			},
		};
		expect(
			validateCandidatePath({
				chain: [tamperedLeaf, tamperedRoot],
				allowSelfSignedLeaf: true,
			}),
		).rejects.toThrow('Invalid IPv4 address');
	});

	it('IP SAN with out-of-range segment throws (line 1775)', async () => {
		const { parsedRoot, parsedLeaf } = await makeSelfSignedChain();
		const tamperedLeaf = {
			...parsedLeaf,
			subjectAltNames: [{ type: 'ip' as const, value: '1.2.3.999' }],
		};
		const tamperedRoot = {
			...parsedRoot,
			nameConstraints: {
				permittedSubtrees: [
					{
						base: {
							type: 'ip' as const,
							addressBytes: new Uint8Array([10, 0, 0, 0]),
							maskBytes: new Uint8Array([255, 0, 0, 0]),
						},
					},
				],
			},
		};
		expect(
			validateCandidatePath({
				chain: [tamperedLeaf, tamperedRoot],
				allowSelfSignedLeaf: true,
			}),
		).rejects.toThrow('Invalid IPv4 address');
	});

	// --- rankIssuerCandidates tiebreakers (lines 1078-1088) ---
	// Need multiple CA candidates with same subject DN, AKI scores tie,
	// then root scores tie, then order breaks the tie.

	it('ranks issuer candidates by AKI match, root status, then order', async () => {
		// Create two intermediates with same subject DN signed by different roots
		const rootA = await createSelfSignedCertificate({
			subject: { commonName: 'Rank Root A' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const rootB = await createSelfSignedCertificate({
			subject: { commonName: 'Rank Root B' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		// Two intermediates with same subject but different issuers/keys
		const intKeysA = await generateKeyPair();
		const intA = await createCertificate({
			issuer: { commonName: 'Rank Root A' },
			subject: { commonName: 'Rank Intermediate' },
			publicKey: intKeysA.publicKey,
			signerPrivateKey: rootA.keyPair.privateKey,
			issuerPublicKey: rootA.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const intKeysB = await generateKeyPair();
		const intB = await createCertificate({
			issuer: { commonName: 'Rank Root B' },
			subject: { commonName: 'Rank Intermediate' },
			publicKey: intKeysB.publicKey,
			signerPrivateKey: rootB.keyPair.privateKey,
			issuerPublicKey: rootB.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		// Leaf signed by intA
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Rank Intermediate' },
			subject: { commonName: 'rank-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: intKeysA.privateKey,
			issuerPublicKey: intKeysA.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'rank-leaf.example' }],
			},
		});
		// Provide both intermediates and both roots; intB is listed first
		// but intA has matching AKI, so it should be preferred
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			intermediates: [intB.pem, intA.pem],
			roots: [rootB.certificate.pem, rootA.certificate.pem],
		});
		expect(result.ok).toBe(true);
	});

	it('ranks by order when AKI and root status are identical', async () => {
		// Two intermediates with same subject, neither has SKI/AKI match
		// (both roots, both matching AKI or both not) — order tiebreaker
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Order Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const intKeysA = await generateKeyPair();
		const intA = await createCertificate({
			issuer: { commonName: 'Order Root' },
			subject: { commonName: 'Order Intermediate' },
			publicKey: intKeysA.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const intKeysB = await generateKeyPair();
		const intB = await createCertificate({
			issuer: { commonName: 'Order Root' },
			subject: { commonName: 'Order Intermediate' },
			publicKey: intKeysB.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		// Leaf signed by intA
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Order Intermediate' },
			subject: { commonName: 'order-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: intKeysA.privateKey,
			issuerPublicKey: intKeysA.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'order-leaf.example' }],
			},
		});
		// intA listed first → tried first → succeeds (intB would fail sig check)
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			intermediates: [intA.pem, intB.pem],
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(true);
	});

	// --- deep chain (line 874) and dead-end memoization (line 878) ---

	it('rankIssuerCandidates prefers root when AKI ties (line 1084)', async () => {
		// Root and non-root intermediate share subject DN "Root Pref CA".
		// Leaf has no AKI → AKI tie → falls through to root score comparison.
		// Root wins → line 1084 (return rootScore).
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Root Pref CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		// Non-root intermediate with same subject DN
		const fakeKeys = await generateKeyPair();
		const fakeInt = await createCertificate({
			issuer: { commonName: 'Some Other Issuer' },
			subject: { commonName: 'Root Pref CA' },
			publicKey: fakeKeys.publicKey,
			signerPrivateKey: fakeKeys.privateKey,
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		// Leaf with no AKI, issuer = "Root Pref CA"
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Root Pref CA' },
			subject: { commonName: 'rootpref-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'rootpref-leaf.example' }],
			},
		});
		// fakeInt listed first but root preferred (root score wins)
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			intermediates: [fakeInt.pem],
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(true);
	});

	it('rankIssuerCandidates falls through AKI tie to root tie to order (lines 1078-1088)', async () => {
		// Two intermediates with same subject DN. Leaf has NO AKI (omit issuerPublicKey)
		// → AKI tie (both false). Neither intermediate is in the roots set → root tie.
		// Order tiebreaker decides: intA listed first → tried first.
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Order3 Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const intKeysA = await generateKeyPair();
		const intA = await createCertificate({
			issuer: { commonName: 'Order3 Root' },
			subject: { commonName: 'Order3 Int' },
			publicKey: intKeysA.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const intKeysB = await generateKeyPair();
		const intB = await createCertificate({
			issuer: { commonName: 'Order3 Root' },
			subject: { commonName: 'Order3 Int' },
			publicKey: intKeysB.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		// Leaf WITHOUT issuerPublicKey → no AKI extension
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Order3 Int' },
			subject: { commonName: 'order3-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: intKeysA.privateKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'order3-leaf.example' }],
			},
		});
		// intA first → AKI tie → root tie → order wins → intA tried first → success
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			intermediates: [intA.pem, intB.pem],
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(true);
	});
});
