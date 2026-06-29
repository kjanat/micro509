import { describe, expect, it } from 'bun:test';
import {
	checkCertificateRevocationAgainstCrl,
	createCertificate,
	createCertificateRevocationList,
	createSelfSignedCertificate,
	exportPkcs8Pem,
	generateKeyPair,
	matchServiceIdentity,
	parseCertificatePem,
	parseCertificateRevocationListPem,
	parseOcspResponseDer,
	validateOcspResponse,
	verifyCertificateChain,
} from '#micro509';
import { hexToBytes, issueChain } from './helpers.ts';
import {
	checkIdentityWithOpenSsl,
	checkRevocationWithOpenSsl,
	issueAndValidateOcspResponseWithOpenSsl,
	probeOpenSsl,
	verifyChainWithOpenSsl,
} from './oracles/openssl.ts';

// The OpenSSL oracle is version-sensitive (name formatting `CN=` vs `CN =`, and
// verdict drift across releases), so it runs locally as a gap-discovery tool but
// is skipped in CI, where a moving system `openssl` would be a flaky publish
// gate. Run it against your local OpenSSL with `bun run test:differential`.
const differential =
	(await probeOpenSsl()) && process.env.CI === undefined ? describe : describe.skip;
differential('OpenSSL differential harness', () => {
	it('matches OpenSSL path verdicts for valid and path-length-exceeded chains', async () => {
		const validChain = await issueChain();
		const validMicro = await verifyCertificateChain({
			leaf: validChain.leaf.der,
			intermediates: [validChain.intermediate.der],
			roots: [validChain.root.certificate.der],
		});
		const validOpenSsl = await verifyChainWithOpenSsl({
			leafPem: validChain.leaf.pem,
			intermediatePems: [validChain.intermediate.pem],
			rootPem: validChain.root.certificate.pem,
		});
		expect(validMicro.ok).toBe(true);
		expect(validOpenSsl.valid).toBe(validMicro.ok);

		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Diff Root CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 2 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const intermediateKeys = await generateKeyPair();
		const intermediate = await createCertificate({
			issuer: { commonName: 'Diff Root CA' },
			subject: { commonName: 'Diff Intermediate CA' },
			publicKey: intermediateKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const subCaKeys = await generateKeyPair();
		const subCa = await createCertificate({
			issuer: { commonName: 'Diff Intermediate CA' },
			subject: { commonName: 'Diff Sub CA' },
			publicKey: subCaKeys.publicKey,
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Diff Sub CA' },
			subject: { commonName: 'diff.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: subCaKeys.privateKey,
			issuerPublicKey: subCaKeys.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'dns', value: 'diff.example' }],
			},
		});

		const invalidMicro = await verifyCertificateChain({
			leaf: leaf.der,
			intermediates: [subCa.der, intermediate.der],
			roots: [root.certificate.der],
		});
		const invalidOpenSsl = await verifyChainWithOpenSsl({
			leafPem: leaf.pem,
			intermediatePems: [subCa.pem, intermediate.pem],
			rootPem: root.certificate.pem,
		});
		expect(invalidMicro).toMatchObject({ ok: false, code: 'path_length_exceeded' });
		expect(invalidOpenSsl.valid).toBe(false);
		expect(invalidOpenSsl.failureClass).toBe('path_length');
	});

	it('matches OpenSSL direct CRL metadata and revocation verdicts', async () => {
		const now = new Date();
		const nextUpdate = new Date(now.getTime() + 86_400_000);
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Diff CRL CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Diff CRL CA' },
			subject: { commonName: 'crl.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const parsedLeaf = parseCertificatePem(leaf.pem);
		const goodCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Diff CRL CA' },
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			crlNumber: 7,
			thisUpdate: now,
			nextUpdate: nextUpdate,
		});
		const revokedCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Diff CRL CA' },
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			crlNumber: 8,
			thisUpdate: now,
			nextUpdate: nextUpdate,
			revokedCertificates: [{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) }],
		});

		const goodMicro = await checkCertificateRevocationAgainstCrl({
			certificate: leaf.pem,
			issuerCertificate: issuer.certificate.pem,
			crl: goodCrl.pem,
		});
		const goodOpenSsl = await checkRevocationWithOpenSsl({
			certificatePem: leaf.pem,
			issuerCertificatePem: issuer.certificate.pem,
			crlPem: goodCrl.pem,
		});
		expect(goodMicro).toMatchObject({ ok: true, value: { status: 'good' } });
		expect(goodOpenSsl.status).toBe('good');
		expect(goodOpenSsl.crlNumber).toBe(parseCertificateRevocationListPem(goodCrl.pem).crlNumber);
		expect(goodOpenSsl.issuer).toContain('CN=Diff CRL CA');

		const revokedMicro = await checkCertificateRevocationAgainstCrl({
			certificate: leaf.pem,
			issuerCertificate: issuer.certificate.pem,
			crl: revokedCrl.pem,
		});
		const revokedOpenSsl = await checkRevocationWithOpenSsl({
			certificatePem: leaf.pem,
			issuerCertificatePem: issuer.certificate.pem,
			crlPem: revokedCrl.pem,
		});
		expect(revokedMicro).toMatchObject({ ok: true, value: { status: 'revoked' } });
		expect(revokedOpenSsl.status).toBe('revoked');
	});

	it('matches OpenSSL path verdicts for RSA-PSS and P-521 chains', async () => {
		const rsaPssRoot = await createSelfSignedCertificate({
			subject: { commonName: 'Diff RSA-PSS Root CA' },
			algorithm: {
				kind: 'rsa',
				modulusLength: 2048,
				hash: 'SHA-256',
				scheme: 'pss',
			},
			signature: { kind: 'rsa-pss' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const rsaPssLeafKeys = await generateKeyPair();
		const rsaPssLeaf = await createCertificate({
			issuer: { commonName: 'Diff RSA-PSS Root CA' },
			subject: { commonName: 'diff-rsa-pss.example' },
			publicKey: rsaPssLeafKeys.publicKey,
			signerPrivateKey: rsaPssRoot.keyPair.privateKey,
			issuerPublicKey: rsaPssRoot.keyPair.publicKey,
			signature: { kind: 'rsa-pss' },
			extensions: {
				subjectAltNames: [{ type: 'dns', value: 'diff-rsa-pss.example' }],
			},
		});
		const rsaPssMicro = await verifyCertificateChain({
			leaf: rsaPssLeaf.pem,
			roots: [rsaPssRoot.certificate.pem],
		});
		const rsaPssOpenSsl = await verifyChainWithOpenSsl({
			leafPem: rsaPssLeaf.pem,
			rootPem: rsaPssRoot.certificate.pem,
		});
		expect(rsaPssMicro.ok).toBe(true);
		expect(rsaPssOpenSsl.valid).toBe(true);

		const p521Root = await createSelfSignedCertificate({
			subject: { commonName: 'Diff P-521 Root CA' },
			algorithm: { kind: 'ecdsa', curve: 'P-521' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const p521LeafKeys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-521' });
		const p521Leaf = await createCertificate({
			issuer: { commonName: 'Diff P-521 Root CA' },
			subject: { commonName: 'diff-p521.example' },
			publicKey: p521LeafKeys.publicKey,
			signerPrivateKey: p521Root.keyPair.privateKey,
			issuerPublicKey: p521Root.keyPair.publicKey,
			extensions: {
				subjectAltNames: [{ type: 'dns', value: 'diff-p521.example' }],
			},
		});
		const p521Micro = await verifyCertificateChain({
			leaf: p521Leaf.pem,
			roots: [p521Root.certificate.pem],
		});
		const p521OpenSsl = await verifyChainWithOpenSsl({
			leafPem: p521Leaf.pem,
			rootPem: p521Root.certificate.pem,
		});
		expect(p521Micro.ok).toBe(true);
		expect(p521OpenSsl.valid).toBe(true);
	});

	it('matches OpenSSL issuer-signed OCSP status for good and revoked responses', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Diff OCSP CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign', 'digitalSignature'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Diff OCSP CA' },
			subject: { commonName: 'ocsp.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const issuerPrivateKeyPem = await exportPkcs8Pem(issuer.keyPair.privateKey);

		for (const status of ['good', 'revoked'] as const) {
			const openSsl = await issueAndValidateOcspResponseWithOpenSsl({
				issuerCertificatePem: issuer.certificate.pem,
				issuerPrivateKeyPem,
				certificatePem: leaf.pem,
				certificateStatus: status,
				revocationTime: new Date('2026-03-12T01:02:03Z'),
			});
			const micro = await validateOcspResponse({
				response: openSsl.responseDer,
				issuerCertificate: issuer.certificate.pem,
			});
			const parsed = parseOcspResponseDer(openSsl.responseDer);
			expect(openSsl.accepted).toBe(true);
			expect(micro.ok).toBe(openSsl.accepted);
			expect(parsed.responses?.[0]?.certStatus).toBe(openSsl.status);
		}
	});

	it('matches OpenSSL DNS and IP identity verdicts', async () => {
		const dnsCertificate = await createSelfSignedCertificate({
			subject: { commonName: 'ignored.example' },
			extensions: {
				subjectAltNames: [
					{ type: 'dns', value: 'api.example.com' },
					{ type: 'dns', value: '*.wild.example.com' },
				],
			},
		});
		const parsedDns = parseCertificatePem(dnsCertificate.certificate.pem);
		for (const dnsCase of [
			{ value: 'api.example.com', expected: true },
			{ value: 'service.wild.example.com', expected: true },
			{ value: 'mismatch.example.com', expected: false },
		] as const) {
			const micro = matchServiceIdentity({
				certificate: parsedDns,
				serviceIdentity: { type: 'dns', value: dnsCase.value },
			});
			const openSsl = await checkIdentityWithOpenSsl({
				certificatePem: dnsCertificate.certificate.pem,
				kind: 'dns',
				value: dnsCase.value,
			});
			expect(micro.ok).toBe(dnsCase.expected);
			expect(openSsl.matches).toBe(dnsCase.expected);
			expect(micro.ok).toBe(openSsl.matches);
		}

		const ipCertificate = await createSelfSignedCertificate({
			subject: { commonName: 'ignored-ip.example' },
			extensions: {
				subjectAltNames: [{ type: 'ip', value: '2001:db8::1' }],
			},
		});
		const parsedIp = parseCertificatePem(ipCertificate.certificate.pem);
		const ipMicro = matchServiceIdentity({
			certificate: parsedIp,
			serviceIdentity: { type: 'ip', value: '2001:0db8:0:0:0:0:0:1' },
		});
		const ipOpenSsl = await checkIdentityWithOpenSsl({
			certificatePem: ipCertificate.certificate.pem,
			kind: 'ip',
			value: '2001:0db8:0:0:0:0:0:1',
		});
		expect(ipMicro.ok).toBe(true);
		expect(ipOpenSsl.matches).toBe(true);
		expect(ipMicro.ok).toBe(ipOpenSsl.matches);
	});
});
