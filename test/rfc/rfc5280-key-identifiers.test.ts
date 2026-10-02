import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createCertificateRevocationList,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificateDer,
	parseCertificateRevocationListDerOrThrow,
	unwrap,
	validateCertificateRevocationList,
} from '#micro509';
import { toHex } from '#micro509/internal/asn1/asn1';
import {
	bitString,
	explicitContext,
	objectIdentifier,
	octetString,
	readSequenceChildren,
	sequence,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import {
	encodeAlgorithmIdentifier,
	getSignatureAlgorithm,
	signBytes,
} from '#micro509/internal/crypto/signing';
import { buildSubjectKeyIdentifier, encodeExtension } from '#micro509/x509/extensions';
import { childAt, constructedChildren, rfcDir, sliceElement } from '#test/helpers';

const rfc5280Lines = (await Bun.file(`${rfcDir}/rfc5280.txt`).text()).split('\n');

const printed = (from: number, to: number): string =>
	rfc5280Lines
		.slice(from - 1, to)
		.join(' ')
		.replace(/\s+/g, ' ')
		.trim();

const NEXT_UPDATE = new Date('2999-01-01T00:00:00Z');
const FOREIGN_KEY_IDENTIFIER = Uint8Array.from({ length: 20 }, (_, index) => index + 1);

function isSubjectKeyIdentifier(extension: Uint8Array): boolean {
	const [extnId] = constructedChildren(extension);
	return (
		extnId !== undefined && Bun.deepEquals(extnId, objectIdentifier(OIDS.subjectKeyIdentifier))
	);
}

async function reissueWithExtensions(
	certificateDer: Uint8Array,
	signerPrivateKey: CryptoKey,
	edit: (extensions: readonly Uint8Array[]) => readonly Uint8Array[],
): Promise<Uint8Array> {
	const tbsDer = childAt(certificateDer, 0);
	const rebuiltTbsDer = sequence(
		readSequenceChildren(tbsDer).map((child) => {
			const encoded = sliceElement(tbsDer, child);
			if (child.tag !== 0xa3) return encoded;
			const [list] = constructedChildren(encoded);
			return explicitContext(
				3,
				sequence([...edit(list === undefined ? [] : constructedChildren(list))]),
			);
		}),
	);
	const signatureAlgorithm = getSignatureAlgorithm(signerPrivateKey);
	const signatureValue = await signBytes(signerPrivateKey, signatureAlgorithm, rebuiltTbsDer);
	return sequence([
		rebuiltTbsDer,
		encodeAlgorithmIdentifier(signatureAlgorithm),
		bitString(signatureValue),
	]);
}

async function caWithSubjectKeyIdentifier(keyIdentifier: Uint8Array | undefined) {
	const ca = await createSelfSignedCertificate({
		subject: { commonName: 'Key Identifier CA' },
		extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
	});
	const der = await reissueWithExtensions(ca.certificate.der, ca.keyPair.privateKey, (extensions) =>
		extensions.flatMap((extension) => {
			if (!isSubjectKeyIdentifier(extension)) return [extension];
			return keyIdentifier === undefined
				? []
				: [encodeExtension(OIDS.subjectKeyIdentifier, octetString(keyIdentifier))];
		}),
	);
	return { keyPair: ca.keyPair, der, parsed: unwrap(parseCertificateDer(der)) };
}

async function leafOf(issuer: Awaited<ReturnType<typeof caWithSubjectKeyIdentifier>>) {
	const leafKeys = await generateKeyPair();
	const leaf = await createCertificate({
		issuer: { commonName: 'Key Identifier CA' },
		subject: { commonName: 'key-identifier-leaf.example' },
		publicKey: leafKeys.publicKey,
		signerPrivateKey: issuer.keyPair.privateKey,
		issuerCertificate: issuer.der,
	});
	return unwrap(parseCertificateDer(leaf.der));
}

async function crlOf(issuer: Awaited<ReturnType<typeof caWithSubjectKeyIdentifier>>) {
	return createCertificateRevocationList({
		issuer: { commonName: 'Key Identifier CA' },
		signerPrivateKey: issuer.keyPair.privateKey,
		issuerCertificate: issuer.der,
		crlNumber: 1,
		nextUpdate: NEXT_UPDATE,
	});
}

describe('RFC 5280', () => {
	it('prints the sentences this suite enforces', () => {
		expect(printed(1549, 1552)).toContain(
			'In conforming CA certificates, the value of the subject key identifier MUST be the value placed in the key identifier field of the authority key identifier extension (Section 4.2.1.1) of certificates issued by the subject of this certificate.',
		);
		expect(printed(3340, 3344)).toContain(
			"The identification can be based on either the key identifier (the subject key identifier in the CRL signer's certificate) or the issuer name and serial number.",
		);
		expect(printed(1499, 1507)).toContain(
			'In this case, the subject and authority key identifiers would be identical',
		);
	});

	describe('§4.2.1.2 L1549-1552: a certificate carries its issuer certificate subject key identifier as the authority key identifier', () => {
		it('copies an issuer subject key identifier that was not derived from the issuer key by method (1)', async () => {
			const issuer = await caWithSubjectKeyIdentifier(FOREIGN_KEY_IDENTIFIER);
			expect(issuer.parsed.subjectKeyIdentifier).toBe(toHex(FOREIGN_KEY_IDENTIFIER));
			expect((await leafOf(issuer)).authorityKeyIdentifier).toBe(toHex(FOREIGN_KEY_IDENTIFIER));
		});

		it('derives the key identifier from the issuer public key by method (1) when the issuer certificate has none', async () => {
			const issuer = await caWithSubjectKeyIdentifier(undefined);
			expect(issuer.parsed.subjectKeyIdentifier).toBeUndefined();
			expect((await leafOf(issuer)).authorityKeyIdentifier).toBe(
				toHex(buildSubjectKeyIdentifier(issuer.parsed.subjectPublicKeyInfoDer)),
			);
		});

		it('§4.2.1.1 L1499-1507: a self-signed certificate carries its own subject key identifier as the authority key identifier', async () => {
			const ca = await createSelfSignedCertificate({ subject: { commonName: 'Self-Signed CA' } });
			const parsed = unwrap(parseCertificateDer(ca.certificate.der));
			expect(parsed.subjectKeyIdentifier).toBeDefined();
			expect(parsed.authorityKeyIdentifier).toBe(parsed.subjectKeyIdentifier);
		});
	});

	describe('§5.2.1 L3340-3344: a CRL carries its signer certificate subject key identifier as the authority key identifier', () => {
		it('copies an issuer subject key identifier that was not derived from the issuer key by method (1), so the CRL validates against that issuer', async () => {
			const issuer = await caWithSubjectKeyIdentifier(FOREIGN_KEY_IDENTIFIER);
			const crl = await crlOf(issuer);
			expect(parseCertificateRevocationListDerOrThrow(crl.der).authorityKeyIdentifier).toBe(
				toHex(FOREIGN_KEY_IDENTIFIER),
			);
			expect(
				await validateCertificateRevocationList({ crl: crl.der, issuerCertificate: issuer.der }),
			).toMatchObject({ ok: true });
		});

		it('derives the key identifier from the issuer public key by method (1) when the issuer certificate has none', async () => {
			const issuer = await caWithSubjectKeyIdentifier(undefined);
			expect(
				parseCertificateRevocationListDerOrThrow((await crlOf(issuer)).der).authorityKeyIdentifier,
			).toBe(toHex(buildSubjectKeyIdentifier(issuer.parsed.subjectPublicKeyInfoDer)));
		});
	});
});
