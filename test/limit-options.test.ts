import { describe, it } from 'bun:test';
import {
	checkCertificateRevocation,
	checkCertificateRevocationAgainstCrl,
	checkChainRevocation,
	createSelfSignedCertificate,
	importEncryptedPkcs8Der,
	importEncryptedPkcs8DerOrThrow,
	importEncryptedPkcs8Pem,
	parsePfxDer,
	parsePfxPem,
	validateCertificateRevocationList,
	verifyCertificateChain,
} from '#micro509';
import { parsePkcs12MacData } from '#micro509/pkcs';
import { expectRejectedWith } from '#test/helpers';

const garbage = new Uint8Array([0x30, 0x03, 0x02]);

describe('an invalid maxKdfIterations throws before the input is decoded', () => {
	it('importEncryptedPkcs8Der', async () => {
		await expectRejectedWith(
			importEncryptedPkcs8Der(garbage, 'secret', undefined, { maxKdfIterations: 0 }),
			RangeError,
		);
	});

	it('importEncryptedPkcs8DerOrThrow', async () => {
		await expectRejectedWith(
			importEncryptedPkcs8DerOrThrow(garbage, 'secret', undefined, { maxKdfIterations: 0 }),
			RangeError,
		);
	});

	it('importEncryptedPkcs8Pem', async () => {
		await expectRejectedWith(
			importEncryptedPkcs8Pem('not pem', 'secret', undefined, { maxKdfIterations: 0 }),
			RangeError,
		);
	});

	it('parsePkcs12MacData', async () => {
		await expectRejectedWith(
			parsePkcs12MacData(garbage, new Uint8Array(), 'pw', { maxKdfIterations: 0 }),
			RangeError,
		);
		await expectRejectedWith(
			parsePkcs12MacData(garbage, new Uint8Array(), undefined, { maxKdfIterations: 1.5 }),
			RangeError,
		);
	});

	it('parsePfxDer', async () => {
		await expectRejectedWith(
			parsePfxDer(garbage, { password: 'pw', maxKdfIterations: 0 }),
			RangeError,
		);
	});

	it('parsePfxPem', async () => {
		await expectRejectedWith(
			parsePfxPem('not pem', { password: 'pw', maxKdfIterations: -1 }),
			RangeError,
		);
	});
});

describe('an invalid CRL maximum age throws before any evidence is read', () => {
	it('validateCertificateRevocationList', async () => {
		await expectRejectedWith(
			validateCertificateRevocationList({ crl: garbage, issuerCertificate: garbage, maxAgeMs: -1 }),
			RangeError,
		);
	});

	it('checkCertificateRevocationAgainstCrl', async () => {
		await expectRejectedWith(
			checkCertificateRevocationAgainstCrl({
				certificate: garbage,
				issuerCertificate: garbage,
				crl: garbage,
				maxAgeMs: Number.NaN,
			}),
			RangeError,
		);
	});

	it('checkCertificateRevocation', async () => {
		await expectRejectedWith(
			checkCertificateRevocation({
				certificate: garbage,
				issuerCertificate: garbage,
				evidence: [],
				crlMaxAgeMs: -1,
			}),
			RangeError,
		);
	});

	it('checkChainRevocation', async () => {
		await expectRejectedWith(
			checkChainRevocation({ chain: [], policy: { crlMaxAgeMs: -1 } }),
			RangeError,
		);
	});

	it('verifyCertificateChain', async () => {
		const leaf = await createSelfSignedCertificate({ subject: { commonName: 'leaf.example' } });
		const root = await createSelfSignedCertificate({ subject: { commonName: 'Unrelated Root' } });
		await expectRejectedWith(
			verifyCertificateChain({
				leaf: leaf.certificate.pem,
				roots: [root.certificate.pem],
				revocation: { policy: { crlMaxAgeMs: Number.POSITIVE_INFINITY } },
			}),
			RangeError,
		);
	});
});
