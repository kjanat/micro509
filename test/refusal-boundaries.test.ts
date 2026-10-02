import { describe, expect, it } from 'bun:test';
import {
	checkCertificateRevocation,
	checkCertificateRevocationAgainstCrl,
	createCertificate,
	createCertificateRevocationList,
	createCertificateSigningRequest,
	createOcspResponse,
	createPkcs7CertBag,
	createPkcs7SignedData,
	createSelfSignedCertificate,
	generateKeyPair,
	matchCertificatePrivateKey,
	parseCertificateDer,
	parseCertificatePem,
	parseCertificateRevocationListDer,
	parseCertificateSigningRequestDer,
	validateCertificateRevocationList,
	validateOcspResponse,
	verifyCertificateChain,
	verifyCertificateRevocationListSignature,
	verifyCertificateSigningRequest,
	verifyOcspResponseSignature,
} from '#micro509';
import { verifySignature } from '#micro509/crypto';
import { toHex } from '#micro509/internal/asn1/asn1';
import {
	explicitContext,
	nullValue,
	objectIdentifier,
	octetString,
	readSequenceChildren,
	sequence,
	setOf,
	tlv,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import {
	appendCertificateExtensions,
	FAR_FUTURE_NEXT_UPDATE,
	issueChain,
	replaceCsrSignatureAlgorithm,
	rewriteCertificateSubject,
	sliceElement,
} from '#test/helpers';

const teletexSubject = sequence([
	setOf([sequence([objectIdentifier(OIDS.commonName), tlv(0x14, Uint8Array.of(0xc1, 0x41))])]),
]);

async function fixture() {
	const chain = await issueChain();
	const crl = await createCertificateRevocationList({
		crlNumber: 1,
		issuer: { commonName: 'Verify Intermediate CA' },
		signerPrivateKey: chain.intermediateKeys.privateKey,
		issuerCertificate: chain.intermediate.der,
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
			issuerCertificate: intermediate.der,
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
			crlNumber: 1,
			issuer: { commonName: 'Verify Intermediate CA' },
			signerPrivateKey: intermediateKeys.privateKey,
			issuerCertificate: intermediate.der,
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

describe('decode refusals in the PKCS#7 builders', () => {
	it('createPkcs7CertBag reports an undecodable certificate as unsupported', async () => {
		const { leaf, unsupportedLeaf } = await fixture();
		expect(createPkcs7CertBag([leaf.pem, unsupportedLeaf])).toMatchObject(unsupported);
	});

	it('createPkcs7SignedData reports an undecodable signer or additional certificate as unsupported', async () => {
		const { leaf, leafKeys, unsupportedIssuer, unsupportedLeaf } = await fixture();
		const content = new TextEncoder().encode('hello');
		expect(
			await createPkcs7SignedData({
				content,
				signers: [{ certificate: unsupportedLeaf, privateKey: leafKeys.privateKey }],
			}),
		).toMatchObject(unsupported);
		expect(
			await createPkcs7SignedData({
				content,
				signers: [{ certificate: leaf.pem, privateKey: leafKeys.privateKey }],
				additionalCertificates: [unsupportedIssuer],
			}),
		).toMatchObject(unsupported);
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

describe('decode refusals in RSA-PSS signature parameters', () => {
	const overlongArc = Uint8Array.of(0x2a, ...new Array<number>(64).fill(0xff), 0x7f);
	const overlongHashParameters = sequence([
		explicitContext(0, sequence([tlv(0x06, overlongArc), nullValue()])),
	]);
	const limitExceeded = { ok: false, code: 'limit_exceeded' };

	it('reports a CSR whose RSA-PSS hash OID is over a decoding limit as limit_exceeded', async () => {
		const keyPair = await generateKeyPair();
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'pss-limit.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
		});
		const refused = replaceCsrSignatureAlgorithm(
			csr.der,
			sequence([objectIdentifier(OIDS.rsassaPss), overlongHashParameters]),
		);
		expect(parseCertificateSigningRequestDer(refused)).toMatchObject(limitExceeded);
		expect(await verifyCertificateSigningRequest(refused)).toMatchObject(limitExceeded);
	});

	it('reports a certificate or CRL whose RSA-PSS hash OID is over a decoding limit as limit_exceeded', async () => {
		const algorithm = sequence([objectIdentifier(OIDS.rsassaPss), overlongHashParameters]);
		const withAlgorithm = (der: Uint8Array): Uint8Array => {
			const [tbs, , signatureValue] = readSequenceChildren(der);
			if (tbs === undefined || signatureValue === undefined) throw new Error('fixture shape');
			const tbsDer = sliceElement(der, tbs);
			const children = readSequenceChildren(tbsDer);
			const signatureIndex = children.findIndex((child) => child.tag === 0x30);
			return sequence([
				sequence(
					children.map((child, index) =>
						index === signatureIndex ? algorithm : sliceElement(tbsDer, child),
					),
				),
				algorithm,
				sliceElement(der, signatureValue),
			]);
		};
		const { certificate, keyPair } = await createSelfSignedCertificate({
			subject: { commonName: 'pss-limit-issuer.example' },
		});
		const crl = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: 'pss-limit-issuer.example' },
			signerPrivateKey: keyPair.privateKey,
			issuerCertificate: certificate.der,
			nextUpdate: FAR_FUTURE_NEXT_UPDATE,
		});
		expect(parseCertificateDer(withAlgorithm(certificate.der))).toMatchObject(limitExceeded);
		expect(parseCertificateRevocationListDer(withAlgorithm(crl.der))).toMatchObject(limitExceeded);
	});

	it('verifySignature reports RSA-PSS parameters over a decoding limit as limit_exceeded', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: 'pss-limit-signer.example' },
		});
		const parsed = parseCertificatePem(certificate.pem);
		if (!parsed.ok) throw new Error('fixture certificate does not parse');
		expect(
			await verifySignature({
				signerSpkiDer: parsed.value.subjectPublicKeyInfoDer,
				signatureAlgorithm: { oid: OIDS.rsassaPss, parametersDer: overlongHashParameters },
				publicKeyAlgorithm: {
					oid: parsed.value.publicKeyAlgorithmOid,
					parametersOid: parsed.value.publicKeyParametersOid,
				},
				signature: new Uint8Array(64),
				data: new Uint8Array(1),
			}),
		).toMatchObject(limitExceeded);
	});
});

describe('decode refusals inside signature verification', () => {
	const overlongArc = Uint8Array.of(0x2a, ...new Array<number>(64).fill(0xff), 0x7f);
	const overlongSpki = sequence([
		sequence([tlv(0x06, overlongArc), objectIdentifier(OIDS.prime256v1)]),
		tlv(0x03, Uint8Array.of(0x00, 0x04)),
	]);
	const limitExceeded = { ok: false, code: 'limit_exceeded' };

	it('verifySignature reports PKCS #1 parameters with a tag number over the limit as limit_exceeded', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: 'tag-limit-signer.example' },
			algorithm: { kind: 'rsa', modulusLength: 2048, hash: 'SHA-256' },
		});
		const parsed = parseCertificatePem(certificate.pem);
		if (!parsed.ok) throw new Error('fixture certificate does not parse');
		expect(
			await verifySignature({
				signerSpkiDer: parsed.value.subjectPublicKeyInfoDer,
				signatureAlgorithm: {
					oid: OIDS.sha256WithRSAEncryption,
					parametersDer: Uint8Array.of(0x1f, 0x90, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, 0x00),
				},
				publicKeyAlgorithm: { oid: parsed.value.publicKeyAlgorithmOid },
				signature: new Uint8Array(256),
				data: new Uint8Array(1),
			}),
		).toMatchObject(limitExceeded);
	});

	it('verifySignature reports a signer SPKI with an OID over the limit as limit_exceeded', async () => {
		expect(
			await verifySignature({
				signerSpkiDer: overlongSpki,
				signatureAlgorithm: { oid: OIDS.ecdsaWithSHA256 },
				publicKeyAlgorithm: { oid: OIDS.ecPublicKey, parametersOid: OIDS.prime256v1 },
				signature: new Uint8Array(64),
				data: new Uint8Array(1),
			}),
		).toMatchObject(limitExceeded);
	});

	it('reports a trust anchor whose SPKI holds an OID over the limit as limit_exceeded', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: 'anchor-limit.example' },
		});
		const parsed = parseCertificatePem(certificate.pem);
		if (!parsed.ok) throw new Error('fixture certificate does not parse');
		expect(
			await verifyCertificateChain({
				leaf: certificate.pem,
				roots: [],
				trustAnchors: [
					{
						subject: parsed.value.subject,
						subjectPublicKeyInfoDer: overlongSpki,
						publicKeyAlgorithmOid: OIDS.ecPublicKey,
						publicKeyParametersOid: OIDS.prime256v1,
					},
				],
			}),
		).toMatchObject(limitExceeded);
	});
});
