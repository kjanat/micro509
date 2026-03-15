import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createOcspRequest,
	createOcspResponse,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificatePem,
	parseOcspRequestPem,
	parseOcspResponseDer,
	validateOcspResponse,
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
import { sha1 } from '#micro509/internal/crypto/hash.ts';
import { OIDS } from '#micro509/internal/asn1/oids.ts';
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
	const issuer = parseCertificatePem(input.issuerCertificatePem);
	const certificate = parseCertificatePem(input.certificatePem);
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
		const responderBParsed = parseCertificatePem(responderB.pem);
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
							parseCertificatePem(issuer.certificate.pem).subjectPublicKeyInfoDer,
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
				response: parseOcspResponseDer(response.der),
				issuerCertificate: parseCertificatePem(issuer.certificate.pem),
				request: parseOcspRequestPem(request.pem),
				responderCertificate: parseCertificatePem(responder.pem),
			}),
		).toMatchObject({ ok: true });
	});
});
