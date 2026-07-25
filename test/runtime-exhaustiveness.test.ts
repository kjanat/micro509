import { describe, expect, it } from 'bun:test';
import {
	createCertificateRevocationList,
	createOcspResponse,
	createSelfSignedCertificate,
	exportPkcs8Der,
	exportPrivateJwk,
	exportPublicJwk,
	exportSpkiDer,
	generateKeyPair,
	importPkcs8DerOrThrow,
	importPrivateJwkOrThrow,
	importPublicJwkOrThrow,
	importSpkiDerOrThrow,
	subjectAltNameLabel,
	subjectAltNameToString,
} from '#micro509';
import { encodePbes2AlgorithmIdentifier } from '#micro509/internal/crypto/pbes2';
import { encodeRsaPssParameters, rsaPssParametersForHash } from '#micro509/internal/crypto/rsa-pss';
import { encodeCrlDistributionPoints } from '#micro509/x509/extensions';

interface RuntimeGuardCase {
	readonly name: string;
	readonly expectedMessage: string;
	readonly run: () => unknown;
}

interface AsyncRuntimeGuardCase {
	readonly name: string;
	readonly expectedMessage: string;
	readonly run: () => Promise<unknown>;
}

interface KeyFixtures {
	readonly spki: Uint8Array;
	readonly pkcs8: Uint8Array;
	readonly publicJwk: JsonWebKey;
	readonly privateJwk: JsonWebKey;
}

async function expectRejectedMessage(
	run: () => Promise<unknown>,
	expectedMessage: string,
): Promise<void> {
	try {
		await run();
	} catch (error) {
		expect(error).toBeInstanceOf(Error);
		if (!(error instanceof Error)) throw new Error('unreachable');
		expect(error.message).toContain(expectedMessage);
		return;
	}
	throw new Error(`Expected rejection containing: ${expectedMessage}`);
}

let keyFixturesPromise: Promise<KeyFixtures> | undefined;

function getKeyFixtures(): Promise<KeyFixtures> {
	keyFixturesPromise ??= (async () => {
		const keyPair = await generateKeyPair();
		return {
			spki: await exportSpkiDer(keyPair.publicKey),
			pkcs8: await exportPkcs8Der(keyPair.privateKey),
			publicJwk: await exportPublicJwk(keyPair.publicKey),
			privateJwk: await exportPrivateJwk(keyPair.privateKey),
		};
	})();
	return keyFixturesPromise;
}

type SignerFixture = Awaited<ReturnType<typeof createSelfSignedCertificate>>;

let signerFixturePromise: Promise<SignerFixture> | undefined;

function getSignerFixture(): Promise<SignerFixture> {
	signerFixturePromise ??= createSelfSignedCertificate({
		subject: { commonName: 'Runtime Guard Signer' },
		extensions: {
			basicConstraints: { ca: true, pathLength: 0 },
			keyUsage: ['keyCertSign', 'cRLSign'],
		},
	});
	return signerFixturePromise;
}

describe('runtime exhaustiveness guards', () => {
	const synchronousCases = [
		{
			name: 'RSA-PSS profile hash',
			expectedMessage: 'Unhandled RsaPssHash',
			run: () => Reflect.apply(rsaPssParametersForHash, undefined, ['SHA-999']),
		},
		{
			name: 'RSA-PSS encoder hash',
			expectedMessage: 'Unhandled RsaPssHash',
			run: () =>
				Reflect.apply(encodeRsaPssParameters, undefined, [
					{
						hash: 'SHA-999',
						mgfHash: 'SHA-999',
						saltLength: 32,
						trailerField: 1,
					},
				]),
		},
		{
			name: 'PBES2 PRF',
			expectedMessage: 'Unhandled Pbes2Prf',
			run: () =>
				Reflect.apply(encodePbes2AlgorithmIdentifier, undefined, [
					{
						iterations: 1,
						salt: Uint8Array.of(1),
						iv: new Uint8Array(16),
						cipher: 'AES-128-CBC',
						prf: 'HMAC-SHA-999',
					},
				]),
		},
		{
			name: 'subjectAltNameLabel variant',
			expectedMessage: 'Unhandled SubjectAltName type',
			run: () => Reflect.apply(subjectAltNameLabel, undefined, [{ type: 'unsupported' }]),
		},
		{
			name: 'subjectAltNameToString variant',
			expectedMessage: 'Unhandled SubjectAltName type',
			run: () => Reflect.apply(subjectAltNameToString, undefined, [{ type: 'unsupported' }]),
		},
		{
			name: 'CRL distribution-point variant',
			expectedMessage: 'Unhandled DistributionPointName type',
			run: () =>
				Reflect.apply(encodeCrlDistributionPoints, undefined, [
					[{ distributionPoint: { type: 'unsupported' } }],
				]),
		},
		{
			name: 'late empty CRL fullName',
			expectedMessage: 'DistributionPointName fullName must not be empty',
			run: () => {
				let reads = 0;
				const distributionPoint = {
					type: 'fullName',
					get fullName() {
						reads += 1;
						return reads === 1 ? [{ type: 'dns', value: 'crl.example' }] : [];
					},
				};
				return Reflect.apply(encodeCrlDistributionPoints, undefined, [[{ distributionPoint }]]);
			},
		},
	] satisfies RuntimeGuardCase[];

	it.each(synchronousCases)('throws for an unhandled $name', ({ run, expectedMessage }) => {
		expect(run).toThrow(expectedMessage);
	});

	const asynchronousCases = [
		{
			name: 'key generation',
			expectedMessage: 'Unhandled KeyAlgorithmInput kind',
			run: () => Reflect.apply(generateKeyPair, undefined, [{ kind: 'unsupported' }]),
		},
		{
			name: 'SPKI algorithm assertion',
			expectedMessage: 'Unhandled PublicKeyImportInput kind',
			run: async () => {
				const { spki } = await getKeyFixtures();
				return Reflect.apply(importSpkiDerOrThrow, undefined, [spki, { kind: 'unsupported' }]);
			},
		},
		{
			name: 'PKCS#8 algorithm assertion',
			expectedMessage: 'Unhandled PrivateKeyImportInput kind',
			run: async () => {
				const { pkcs8 } = await getKeyFixtures();
				return Reflect.apply(importPkcs8DerOrThrow, undefined, [pkcs8, { kind: 'unsupported' }]);
			},
		},
		{
			name: 'public JWK algorithm assertion',
			expectedMessage: 'Unhandled PublicKeyImportInput kind',
			run: async () => {
				const { publicJwk } = await getKeyFixtures();
				return Reflect.apply(importPublicJwkOrThrow, undefined, [
					publicJwk,
					{ kind: 'unsupported' },
				]);
			},
		},
		{
			name: 'private JWK algorithm assertion',
			expectedMessage: 'Unhandled PrivateKeyImportInput kind',
			run: async () => {
				const { privateJwk } = await getKeyFixtures();
				return Reflect.apply(importPrivateJwkOrThrow, undefined, [
					privateJwk,
					{ kind: 'unsupported' },
				]);
			},
		},
		{
			name: 'WebCrypto import algorithm mapping',
			expectedMessage: 'Malformed SubjectPublicKeyInfo',
			run: async () => {
				const { spki } = await getKeyFixtures();
				let reads = 0;
				const algorithm = {
					curve: 'P-256',
					get kind() {
						reads += 1;
						return reads === 1 ? 'ecdsa' : 'unsupported';
					},
				};
				return Reflect.apply(importSpkiDerOrThrow, undefined, [spki, algorithm]);
			},
		},
		{
			name: 'CRL distribution-point variant',
			expectedMessage: 'Unhandled DistributionPointName type',
			run: async () => {
				const signer = await getSignerFixture();
				return Reflect.apply(createCertificateRevocationList, undefined, [
					{
						issuer: { commonName: 'Runtime Guard Signer' },
						signerPrivateKey: signer.keyPair.privateKey,
						issuerPublicKey: signer.keyPair.publicKey,
						issuingDistributionPoint: {
							distributionPoint: { type: 'unsupported' },
						},
					},
				]);
			},
		},
		{
			name: 'OCSP certificate status variant',
			expectedMessage: 'Unhandled CertStatus type',
			run: async () => {
				const signer = await getSignerFixture();
				return Reflect.apply(createOcspResponse, undefined, [
					{
						signerPrivateKey: signer.keyPair.privateKey,
						signerCertificate: signer.certificate.pem,
						responses: [
							{
								certificate: signer.certificate.pem,
								issuerCertificate: signer.certificate.pem,
								certStatus: 'unsupported',
							},
						],
					},
				]);
			},
		},
	] satisfies AsyncRuntimeGuardCase[];

	it.each(asynchronousCases)('rejects an unhandled $name', async ({ run, expectedMessage }) => {
		await expectRejectedMessage(run, expectedMessage);
	});
});
