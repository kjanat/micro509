import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createCertificateRevocationList,
	createOcspRequest,
	createOcspResponse,
	createSelfSignedCertificate,
	generateKeyPair,
	hasOcspNoCheckExtension,
	parseCertificatePem,
	parseOcspRequestPemOrThrow,
	parseOcspResponseDerOrThrow,
	validateOcspResponse,
	unwrap,
} from '#micro509';
import { childrenOf } from '#micro509/internal/asn1/asn1.ts';
import {
	bitString,
	explicitContext,
	generalizedTime,
	implicitPrimitiveContext,
	objectIdentifier,
	octetString,
	readElement,
	sequence,
	tlv,
} from '#micro509/internal/asn1/der.ts';
import { OIDS } from '#micro509/internal/asn1/oids.ts';
import { sha1 } from '#micro509/internal/crypto/hash.ts';
import {
	encodeAlgorithmIdentifier,
	getSignatureAlgorithm,
	signBytes,
} from '#micro509/internal/crypto/signing.ts';
import { hexToBytes } from './helpers.ts';

interface FixtureResponderInput {
	readonly commonName: string;
	readonly organization?: string;
	readonly issuerCommonName?: string;
	readonly signerPrivateKey?: CryptoKey;
	readonly issuerPublicKey?: CryptoKey;
	readonly extendedKeyUsage?: readonly ('ocspSigning' | 'serverAuth')[];
}

type FixtureResponderIdInput =
	| {
			readonly type: 'byName';
			readonly nameDer: Uint8Array;
	  }
	| {
			readonly type: 'byKeyHash';
			readonly keyHash: Uint8Array;
	  };

async function issueOcspFixtureAuthority(commonName: string) {
	const issuer = await createSelfSignedCertificate({
		subject: { commonName },
		extensions: {
			basicConstraints: { ca: true, pathLength: 2 },
			keyUsage: ['keyCertSign', 'cRLSign'],
		},
	});

	async function issueLeaf(leafCommonName: string) {
		const leafKeys = await generateKeyPair();
		return await createCertificate({
			issuer: { commonName },
			subject: { commonName: leafCommonName },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
	}

	async function issueResponder(options: FixtureResponderInput) {
		const responderKeys = await generateKeyPair();
		const responder = await createCertificate({
			issuer: { commonName: options.issuerCommonName ?? commonName },
			subject: {
				commonName: options.commonName,
				...(options.organization === undefined ? {} : { organization: options.organization }),
			},
			publicKey: responderKeys.publicKey,
			signerPrivateKey: options.signerPrivateKey ?? issuer.keyPair.privateKey,
			issuerPublicKey: options.issuerPublicKey ?? issuer.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				...(options.extendedKeyUsage === undefined
					? {}
					: { extendedKeyUsage: options.extendedKeyUsage }),
			},
		});
		return { responder, responderKeys };
	}

	return { issuer, issueLeaf, issueResponder };
}

async function createSignedOcspFixtureResponse(input: {
	readonly signerPrivateKey: CryptoKey;
	readonly certificatePem: string;
	readonly issuerCertificatePem: string;
	readonly responderId: FixtureResponderIdInput;
	readonly producedAt?: Date;
	readonly thisUpdate?: Date;
}): Promise<Uint8Array> {
	const issuer = unwrap(parseCertificatePem(input.issuerCertificatePem));
	const certificate = unwrap(parseCertificatePem(input.certificatePem));
	const issuerNameHash = new Uint8Array(sha1(hexToBytes(issuer.subject.derHex)));
	const issuerKeyHash = new Uint8Array(
		sha1(extractSubjectPublicKeyBytes(issuer.subjectPublicKeyInfoDer)),
	);
	const certId = sequence([
		sequence([objectIdentifier(OIDS.sha1), Uint8Array.of(0x05, 0x00)]),
		octetString(issuerNameHash),
		octetString(issuerKeyHash),
		tlv(0x02, hexToBytes(certificate.serialNumberHex)),
	]);
	const singleResponse = sequence([
		certId,
		tlv(0x80, new Uint8Array(0)),
		generalizedTime(input.thisUpdate ?? new Date('2024-01-01T00:00:00Z')),
	]);
	const responderId =
		input.responderId.type === 'byName'
			? explicitContext(1, input.responderId.nameDer)
			: implicitPrimitiveContext(2, input.responderId.keyHash);
	const responseData = sequence([
		responderId,
		generalizedTime(input.producedAt ?? new Date('2024-01-01T00:00:00Z')),
		sequence([singleResponse]),
	]);
	const signatureAlgorithm = getSignatureAlgorithm(input.signerPrivateKey);
	const signature = await signBytes(input.signerPrivateKey, signatureAlgorithm, responseData);
	const basicResponse = sequence([
		responseData,
		encodeAlgorithmIdentifier(signatureAlgorithm),
		bitString(signature),
	]);
	return sequence([
		tlv(0x0a, Uint8Array.of(0x00)),
		explicitContext(
			0,
			sequence([objectIdentifier(OIDS.ocspBasicResponse), octetString(basicResponse)]),
		),
	]);
}

function extractSubjectPublicKeyBytes(spkiDer: Uint8Array): Uint8Array {
	const top = childrenOf(spkiDer, readElement(spkiDer));
	const bitStringElement = top[1];
	if (bitStringElement === undefined) {
		throw new Error('SPKI missing subjectPublicKey BIT STRING');
	}
	return bitStringElement.value.slice(1);
}

describe('ocsp fixtures', () => {
	it('covers responderID binding fixtures for same-subject different-key responders', async () => {
		const { issuer, issueLeaf, issueResponder } = await issueOcspFixtureAuthority(
			'OCSP Fixture ResponderID CA',
		);
		const leaf = await issueLeaf('ocsp-fixture-responderid.example');
		const responderSubject = {
			commonName: 'Shared Fixture Responder',
			organization: 'Fixture Org',
		};
		const { responder: responderA, responderKeys: responderAKeys } = await issueResponder({
			...responderSubject,
			extendedKeyUsage: ['ocspSigning'],
		});
		const { responder: responderB } = await issueResponder({
			...responderSubject,
			extendedKeyUsage: ['ocspSigning'],
		});
		const responderBParsed = unwrap(parseCertificatePem(responderB.pem));
		const response = await createSignedOcspFixtureResponse({
			signerPrivateKey: responderAKeys.privateKey,
			certificatePem: leaf.pem,
			issuerCertificatePem: issuer.certificate.pem,
			responderId: {
				type: 'byKeyHash',
				keyHash: new Uint8Array(
					sha1(extractSubjectPublicKeyBytes(responderBParsed.subjectPublicKeyInfoDer)),
				),
			},
		});

		expect(
			await validateOcspResponse({
				response,
				issuerCertificate: issuer.certificate.pem,
				responderCertificate: responderA.pem,
			}),
		).toMatchObject({ ok: false, code: 'responder_id_mismatch' });
	});

	it('covers delegated responder authorization fixtures', async () => {
		const { issuer, issueLeaf, issueResponder } = await issueOcspFixtureAuthority(
			'OCSP Fixture Delegated CA',
		);
		const leaf = await issueLeaf('ocsp-fixture-delegated.example');
		const { responder: allowedResponder, responderKeys: allowedResponderKeys } =
			await issueResponder({
				commonName: 'Allowed Delegated Responder',
				extendedKeyUsage: ['ocspSigning'],
			});
		const allowedResponse = await createOcspResponse({
			signerPrivateKey: allowedResponderKeys.privateKey,
			signerCertificate: allowedResponder.pem,
			includedCertificates: [allowedResponder.pem],
			responses: [
				{ certificate: leaf.pem, issuerCertificate: issuer.certificate.pem, certStatus: 'good' },
			],
		});
		expect(
			await validateOcspResponse({
				response: allowedResponse.der,
				issuerCertificate: issuer.certificate.pem,
			}),
		).toMatchObject({ ok: true });

		const { responder: blockedResponder, responderKeys: blockedResponderKeys } =
			await issueResponder({
				commonName: 'Blocked Delegated Responder',
				extendedKeyUsage: ['serverAuth'],
			});
		const blockedResponse = await createOcspResponse({
			signerPrivateKey: blockedResponderKeys.privateKey,
			signerCertificate: blockedResponder.pem,
			includedCertificates: [blockedResponder.pem],
			responses: [
				{ certificate: leaf.pem, issuerCertificate: issuer.certificate.pem, certStatus: 'good' },
			],
		});
		expect(
			await validateOcspResponse({
				response: blockedResponse.der,
				issuerCertificate: issuer.certificate.pem,
			}),
		).toMatchObject({ ok: false, code: 'ocsp_signing_missing' });
	});

	it('covers producedAt freshness fixtures', async () => {
		const { issuer, issueLeaf } = await issueOcspFixtureAuthority('OCSP Fixture Freshness CA');
		const leaf = await issueLeaf('ocsp-fixture-freshness.example');
		const at = new Date('2024-01-01T00:00:00Z');
		const futureProducedAt = await createSignedOcspFixtureResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			certificatePem: leaf.pem,
			issuerCertificatePem: issuer.certificate.pem,
			responderId: {
				type: 'byKeyHash',
				keyHash: new Uint8Array(
					sha1(
						extractSubjectPublicKeyBytes(
							unwrap(parseCertificatePem(issuer.certificate.pem)).subjectPublicKeyInfoDer,
						),
					),
				),
			},
			thisUpdate: new Date('2023-12-31T23:59:00Z'),
			producedAt: new Date('2024-01-01T00:00:10Z'),
		});

		expect(
			await validateOcspResponse({
				response: futureProducedAt,
				issuerCertificate: issuer.certificate.pem,
				at,
			}),
		).toMatchObject({ ok: false, code: 'stale_response' });
		expect(
			await validateOcspResponse({
				response: futureProducedAt,
				issuerCertificate: issuer.certificate.pem,
				at,
				clockSkewMs: 15_000,
			}),
		).toMatchObject({ ok: true });

		const nextUpdateMismatch = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			producedAt: new Date('2024-01-01T00:00:20Z'),
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
					thisUpdate: new Date('2024-01-01T00:00:00Z'),
					nextUpdate: new Date('2024-01-01T00:00:10Z'),
				},
			],
		});
		expect(
			await validateOcspResponse({
				response: nextUpdateMismatch.der,
				issuerCertificate: issuer.certificate.pem,
				at: new Date('2024-01-01T00:00:05Z'),
			}),
		).toMatchObject({ ok: false, code: 'stale_response' });
	});

	it('covers full request coverage fixtures', async () => {
		const { issuer, issueLeaf } = await issueOcspFixtureAuthority('OCSP Fixture Coverage CA');
		const firstLeaf = await issueLeaf('ocsp-fixture-coverage-a.example');
		const secondLeaf = await issueLeaf('ocsp-fixture-coverage-b.example');
		const request = await createOcspRequest({
			requests: [
				{ certificate: firstLeaf.pem, issuerCertificate: issuer.certificate.pem },
				{ certificate: secondLeaf.pem, issuerCertificate: issuer.certificate.pem },
			],
		});

		const incompleteResponse = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			responses: [
				{
					certificate: firstLeaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
		});
		expect(
			await validateOcspResponse({
				response: incompleteResponse.der,
				issuerCertificate: issuer.certificate.pem,
				request: request.der,
			}),
		).toMatchObject({ ok: false, code: 'request_mismatch' });

		const completeResponse = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			responses: [
				{
					certificate: secondLeaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
				{
					certificate: firstLeaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
		});
		expect(
			await validateOcspResponse({
				response: completeResponse.der,
				issuerCertificate: issuer.certificate.pem,
				request: request.der,
			}),
		).toMatchObject({ ok: true });
	});

	it('covers normalized DER, PEM, and parsed input fixtures', async () => {
		const { issuer, issueLeaf, issueResponder } =
			await issueOcspFixtureAuthority('OCSP Fixture Input CA');
		const leaf = await issueLeaf('ocsp-fixture-inputs.example');
		const { responder, responderKeys } = await issueResponder({
			commonName: 'Fixture Parsed Responder',
			extendedKeyUsage: ['ocspSigning'],
		});
		const request = await createOcspRequest({
			requests: [{ certificate: leaf.pem, issuerCertificate: issuer.certificate.pem }],
		});
		const response = await createOcspResponse({
			signerPrivateKey: responderKeys.privateKey,
			signerCertificate: responder.pem,
			includedCertificates: [responder.pem],
			responses: [
				{ certificate: leaf.pem, issuerCertificate: issuer.certificate.pem, certStatus: 'good' },
			],
		});

		expect(
			await validateOcspResponse({
				response: response.pem,
				issuerCertificate: issuer.certificate.pem,
				request: request.der,
				responderCertificate: responder.pem,
			}),
		).toMatchObject({ ok: true });
		expect(
			await validateOcspResponse({
				response: parseOcspResponseDerOrThrow(response.der),
				issuerCertificate: unwrap(parseCertificatePem(issuer.certificate.pem)),
				request: parseOcspRequestPemOrThrow(request.pem),
				responderCertificate: unwrap(parseCertificatePem(responder.pem)),
			}),
		).toMatchObject({ ok: true });
	});
});

describe('ocsp responder authorization (RFC 6960 §4.2.2.2)', () => {
	const HOUR_MS = 60 * 60 * 1000;
	const OCSP_NOCHECK_OID = '1.3.6.1.5.5.7.48.1.5';
	const DER_NULL = Uint8Array.of(0x05, 0x00);

	async function issueAuthority(
		commonName: string,
		validity?: { notBefore: Date; notAfter: Date },
	) {
		const ca = await createSelfSignedCertificate({
			subject: { commonName },
			...(validity !== undefined ? { validity } : {}),
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName },
			subject: { commonName: `${commonName} leaf` },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		return { commonName, ca, leaf };
	}

	async function issueDelegatedResponder(
		authority: Awaited<ReturnType<typeof issueAuthority>>,
		options?: {
			readonly noCheck?: boolean;
			readonly validity?: { notBefore: Date; notAfter: Date };
		},
	) {
		const keys = await generateKeyPair();
		const certificate = await createCertificate({
			issuer: { commonName: authority.commonName },
			subject: { commonName: `${authority.commonName} responder` },
			publicKey: keys.publicKey,
			signerPrivateKey: authority.ca.keyPair.privateKey,
			issuerPublicKey: authority.ca.keyPair.publicKey,
			...(options?.validity !== undefined ? { validity: options.validity } : {}),
			extensions: {
				extendedKeyUsage: ['ocspSigning'],
				...(options?.noCheck === true
					? { customExtensions: [{ oid: OCSP_NOCHECK_OID, value: DER_NULL }] }
					: {}),
			},
		});
		return { keys, certificate };
	}

	function goodResponse(
		authority: Awaited<ReturnType<typeof issueAuthority>>,
		signerPrivateKey: CryptoKey,
		signerCertificate: string,
		embed: boolean,
	) {
		return createOcspResponse({
			signerPrivateKey,
			signerCertificate,
			...(embed ? { includedCertificates: [signerCertificate] } : {}),
			responses: [
				{
					certificate: authority.leaf.pem,
					issuerCertificate: authority.ca.certificate.pem,
					certStatus: 'good',
				},
			],
		});
	}

	it('accepts a locally trusted responder that fails delegated rules (criterion 1)', async () => {
		const authority = await issueAuthority('Criterion1 CA');
		// Responder issued by an unrelated CA — delegated issuance rules reject it
		const unrelated = await issueAuthority('Unrelated CA');
		const rogueKeys = await generateKeyPair();
		const responder = await createCertificate({
			issuer: { commonName: 'Unrelated CA' },
			subject: { commonName: 'Externally Trusted Responder' },
			publicKey: rogueKeys.publicKey,
			signerPrivateKey: unrelated.ca.keyPair.privateKey,
			issuerPublicKey: unrelated.ca.keyPair.publicKey,
		});
		const response = await goodResponse(authority, rogueKeys.privateKey, responder.pem, true);

		const withoutTrust = await validateOcspResponse({
			response: response.der,
			issuerCertificate: authority.ca.certificate.pem,
		});
		expect(withoutTrust).toMatchObject({ ok: false, code: 'responder_chain_invalid' });

		const withTrust = await validateOcspResponse({
			response: response.der,
			issuerCertificate: authority.ca.certificate.pem,
			trustedOcspResponders: [responder.pem],
		});
		expect(withTrust).toMatchObject({ ok: true });
	});

	it('discovers a trusted responder when the response embeds no certificates', async () => {
		const authority = await issueAuthority('Discovery CA');
		const responder = await issueDelegatedResponder(authority);

		const response = await goodResponse(
			authority,
			responder.keys.privateKey,
			responder.certificate.pem,
			false, // nothing embedded — discovery must use the trusted list
		);

		const blind = await validateOcspResponse({
			response: response.der,
			issuerCertificate: authority.ca.certificate.pem,
		});
		expect(blind).toMatchObject({ ok: false, code: 'signature_invalid' });

		const discovered = await validateOcspResponse({
			response: response.der,
			issuerCertificate: authority.ca.certificate.pem,
			trustedOcspResponders: [responder.certificate.pem],
		});
		expect(discovered).toMatchObject({ ok: true });
	});

	it('honors id-pkix-ocsp-nocheck: revoked responder still accepted', async () => {
		const authority = await issueAuthority('NoCheck CA');
		const responder = await issueDelegatedResponder(authority, { noCheck: true });
		expect(hasOcspNoCheckExtension(responder.certificate.pem)).toBe(true);

		const responderSerial = unwrap(parseCertificatePem(responder.certificate.pem)).serialNumberHex;
		const crl = await createCertificateRevocationList({
			issuer: { commonName: authority.commonName },
			signerPrivateKey: authority.ca.keyPair.privateKey,
			issuerPublicKey: authority.ca.keyPair.publicKey,
			revokedCertificates: [{ serialNumber: hexToBytes(responderSerial) }],
		});
		const response = await goodResponse(
			authority,
			responder.keys.privateKey,
			responder.certificate.pem,
			true,
		);

		const result = await validateOcspResponse({
			response: response.der,
			issuerCertificate: authority.ca.certificate.pem,
			responderRevocationCrls: [crl.pem],
		});
		expect(result).toMatchObject({ ok: true });
	});

	it('rejects a revoked responder without nocheck under honor-nocheck', async () => {
		const authority = await issueAuthority('Revoked Responder CA');
		const responder = await issueDelegatedResponder(authority);
		expect(hasOcspNoCheckExtension(responder.certificate.pem)).toBe(false);

		const responderSerial = unwrap(parseCertificatePem(responder.certificate.pem)).serialNumberHex;
		const crl = await createCertificateRevocationList({
			issuer: { commonName: authority.commonName },
			signerPrivateKey: authority.ca.keyPair.privateKey,
			issuerPublicKey: authority.ca.keyPair.publicKey,
			revokedCertificates: [{ serialNumber: hexToBytes(responderSerial) }],
		});
		const response = await goodResponse(
			authority,
			responder.keys.privateKey,
			responder.certificate.pem,
			true,
		);

		const result = await validateOcspResponse({
			response: response.der,
			issuerCertificate: authority.ca.certificate.pem,
			responderRevocationCrls: [crl.pem],
		});
		expect(result).toMatchObject({ ok: false, code: 'responder_revoked' });
	});

	it('require-evidence: rejects without evidence, ignores nocheck, accepts with good CRL', async () => {
		const authority = await issueAuthority('Evidence CA');
		const withNoCheck = await issueDelegatedResponder(authority, { noCheck: true });
		const response = await goodResponse(
			authority,
			withNoCheck.keys.privateKey,
			withNoCheck.certificate.pem,
			true,
		);

		// No evidence — rejected even though nocheck is present
		expect(
			await validateOcspResponse({
				response: response.der,
				issuerCertificate: authority.ca.certificate.pem,
				responderRevocationPolicy: 'require-evidence',
			}),
		).toMatchObject({ ok: false, code: 'responder_revocation_unknown' });

		// Empty CRL proves 'good' — accepted
		const emptyCrl = await createCertificateRevocationList({
			issuer: { commonName: authority.commonName },
			signerPrivateKey: authority.ca.keyPair.privateKey,
			issuerPublicKey: authority.ca.keyPair.publicKey,
		});
		expect(
			await validateOcspResponse({
				response: response.der,
				issuerCertificate: authority.ca.certificate.pem,
				responderRevocationPolicy: 'require-evidence',
				responderRevocationCrls: [emptyCrl.pem],
			}),
		).toMatchObject({ ok: true });
	});

	it('validates delegated responder chain at the caller-supplied time', async () => {
		const now = Date.now();
		// CA validity must span the historical window too
		const authority = await issueAuthority('Historical CA', {
			notBefore: new Date(now - 30 * 24 * HOUR_MS),
			notAfter: new Date(now + 30 * 24 * HOUR_MS),
		});
		// Responder valid only in a past window
		const responder = await issueDelegatedResponder(authority, {
			validity: {
				notBefore: new Date(now - 10 * 24 * HOUR_MS),
				notAfter: new Date(now - 5 * 24 * HOUR_MS),
			},
		});
		const historicalAt = new Date(now - 7 * 24 * HOUR_MS);
		const response = await createOcspResponse({
			signerPrivateKey: responder.keys.privateKey,
			signerCertificate: responder.certificate.pem,
			includedCertificates: [responder.certificate.pem],
			producedAt: historicalAt,
			responses: [
				{
					certificate: authority.leaf.pem,
					issuerCertificate: authority.ca.certificate.pem,
					certStatus: 'good',
					thisUpdate: historicalAt,
				},
			],
		});

		// At the historical time the responder chain is valid
		expect(
			await validateOcspResponse({
				response: response.der,
				issuerCertificate: authority.ca.certificate.pem,
				at: historicalAt,
			}),
		).toMatchObject({ ok: true });

		// Now the responder certificate is expired — chain must fail
		expect(
			await validateOcspResponse({
				response: response.der,
				issuerCertificate: authority.ca.certificate.pem,
			}),
		).toMatchObject({ ok: false, code: 'responder_chain_invalid' });
	});
});
