import { describe, expect, it } from 'bun:test';
import type {
	BuildCandidatePathResult,
	CertificateExtensionsInput,
	CertificateMaterial,
	TrustAnchor,
} from '#micro509';
import {
	buildCandidatePath,
	createCertificate,
	createCertificateRevocationList,
	createCertificateSigningRequest,
	createOcspResponse,
	createPkcs7SignedData,
	createSelfSignedCertificate,
	derivePublicKey,
	exportPkcs8Der,
	exportSpkiDer,
	generateKeyPair,
	importPkcs8Der,
	importPkcs8DerOrThrow,
	importPkcs8Pem,
	importPkcs8PemOrThrow,
	importSpkiDer,
	importSpkiPemOrThrow,
	parseCertificateDer,
	parseCertificateDerOrThrow,
	parseCertificatePemOrThrow,
	parseCertificateRevocationListDerOrThrow,
	parseCertificateSigningRequestDerOrThrow,
	parseOcspResponseDerOrThrow,
	parsePkcs7SignedDataDer,
	pemDecodeOrThrow,
	pemEncode,
	verifyCertificateChain,
	verifyCertificateRevocationListSignature,
	verifyCertificateSigningRequest,
	verifyOcspResponseSignature,
	verifyPkcs7SignedData,
} from '#micro509';
import { decodeDerOidOrThrow } from '#micro509/der';
import { toArrayBuffer } from '#micro509/internal/asn1/asn1';
import type { DerElement } from '#micro509/internal/asn1/der';
import {
	bitString,
	explicitContext,
	implicitConstructedContext,
	implicitPrimitiveContext,
	integer,
	nullValue,
	objectIdentifier,
	octetString,
	printableString,
	readRootElement,
	readSequenceChildren,
	sequence,
	setOf,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import {
	describePublicKeyAlgorithm,
	describeSignatureAlgorithm,
} from '#micro509/internal/crypto/algorithm-names';
import { buildCertificateExtensions, encodeKeyUsage } from '#micro509/x509';
import {
	buildErrorCode,
	childAt,
	constructedChildren,
	expectBuildErrorCode,
	expectRejectedErrorCode,
	fieldAt,
	hexToBytes,
	littleEndianInteger,
	replaceCsrSignatureAlgorithm,
	rfcDir,
	sliceElement,
	withAlgorithmOid,
	withSignatureValue,
} from '#test/helpers';

const lines = (await Bun.file(`${rfcDir}/rfc8410.txt`).text()).split('\n');

/** The lines of RFC 5480, the normative reference section 13.1 carries the ECC key profile through. */
const rfc5480Lines = (await Bun.file(`${rfcDir}/rfc5480.txt`).text()).split('\n');

/** The lines of RFC 5280, whose Appendix A.1 bounds the name attributes a subject carries. */
const rfc5280Lines = (await Bun.file(`${rfcDir}/rfc5280.txt`).text()).split('\n');

/**
 * The text of RFC 5639, one of the documents the Acknowledgments draws from, joined.
 *
 * Its Section 4.1 wraps the root assignment across two lines and breaks
 * `signature-algorithm(3)` on the hyphen, so the lines are joined and the break
 * closed up before an assignment is read out of them.
 */
const rfc5639Text = (await Bun.file(`${rfcDir}/rfc5639.txt`).text())
	.replace(/-\s+/g, '-')
	.replace(/\s+/g, ' ');

/**
 * The block beginning at a 1-based line of the RFC, dedented.
 *
 * RFC 8410 prints eleven blocks and reuses the `PRIVATE KEY` label for seven of
 * them, so a fixture is identified by position rather than by label.
 */
function blockAt(startLine: number): string {
	const start = startLine - 1;
	const begin = lines[start]?.trim() ?? '';
	if (!begin.startsWith('-----BEGIN ')) {
		throw new Error(`rfc8410.txt:${startLine} is not a BEGIN line: ${begin}`);
	}
	const collected: string[] = [];
	for (let index = start; index < lines.length; index++) {
		const line = lines[index]?.trim() ?? '';
		collected.push(line);
		if (line.startsWith('-----END ')) return collected.join('\n');
	}
	throw new Error(`rfc8410.txt:${startLine} has no END line`);
}

const hex = (bytes: Uint8Array): string =>
	[...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');

const ED25519 = { kind: 'ed25519' } as const;

describe('RFC 8410: Safe Curves for X.509', () => {
	describe('1. Introduction', () => {
		const ID_ED25519_DER = Uint8Array.from([0x06, 0x03, 0x2b, 0x65, 0x70]);

		/**
		 * The certificate DER with the final arc of every id-Ed25519 OID replaced.
		 *
		 * The 10.2 certificate spells id-Ed25519 twice, in the tbsCertificate
		 * signature field and in the outer signatureAlgorithm; its subject key is
		 * id-X25519 and is left alone.
		 */
		function withSignatureAlgorithmArc(der: Uint8Array, arc: number): Uint8Array {
			const rewritten = new Uint8Array(der);
			let occurrences = 0;
			for (let index = 0; index + ID_ED25519_DER.length <= rewritten.length; index += 1) {
				if (ID_ED25519_DER.every((byte, offset) => rewritten[index + offset] === byte)) {
					rewritten[index + 4] = arc;
					occurrences += 1;
				}
			}
			expect(occurrences).toBe(2);
			return rewritten;
		}

		// "The convention used for identifying the algorithm/curve combinations is
		// to use "Ed25519" and "Ed448" for the PureEdDSA mode. This document does
		// not provide the conventions needed for the prehash versions of the
		// signature algorithm." The 10.2 certificate is signed with the 10.1 key in
		// PureEdDSA mode over an empty context, so it is a known-answer vector for
		// the mode id-Ed25519 names: prehashing the tbsCertificate, or signing it
		// under a context string, yields a different signature.
		it('verifies the RFC-supplied PureEdDSA signature with the RFC-supplied key', async () => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			const result = await buildCandidatePath({
				leaf: blockAt(717),
				roots: [],
				trustAnchors: [
					{
						subject: certificate.issuer,
						subjectPublicKeyInfoDer: pemDecodeOrThrow('PUBLIC KEY', blockAt(597)),
						publicKeyAlgorithmOid: OIDS.ed25519,
					},
				],
			});
			expect(result).toMatchObject({ ok: true });
		});

		// "A convention has developed that when these two curves are used with the
		// Diffie-Hellman operation, they are referred to as X25519 and X448", and
		// the EdDSA OIDs identify a signature instead. The 10.2 certificate holds
		// an X25519 key agreement key, so that key cannot verify the Ed25519
		// signature over it even though the certificate is self-issued.
		it('does not verify an Ed25519 signature with the X25519 key the certificate carries', async () => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			const result = await buildCandidatePath({
				leaf: blockAt(717),
				roots: [],
				trustAnchors: [
					{
						subject: certificate.issuer,
						subjectPublicKeyInfoDer: certificate.subjectPublicKeyInfoDer,
						publicKeyAlgorithmOid: certificate.publicKeyAlgorithmOid,
					},
				],
			});
			expect(result).toMatchObject({
				ok: false,
				code: 'unsupported_signature_algorithm_parameters',
			});
		});

		// "This document does not provide the conventions needed for the prehash
		// versions of the signature algorithm." Section 3 assigns 110 through 113
		// under 1.3.101 and nothing else, so 1.3.101.114 identifies no signature
		// algorithm this library may verify, and it must not be read as a variant
		// of the neighbouring id-Ed25519.
		it('does not verify a 1.3.101 arc this document leaves unassigned', async () => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			const rewritten = withSignatureAlgorithmArc(certificate.der, 114);
			expect(parseCertificateDerOrThrow(rewritten).signatureAlgorithmOid).toBe('1.3.101.114');
			const result = await buildCandidatePath({
				leaf: rewritten,
				roots: [],
				trustAnchors: [
					{
						subject: certificate.issuer,
						subjectPublicKeyInfoDer: pemDecodeOrThrow('PUBLIC KEY', blockAt(597)),
						publicKeyAlgorithmOid: OIDS.ed25519,
					},
				],
			});
			expect(result).toMatchObject({
				ok: false,
				code: 'unsupported_signature_algorithm_parameters',
			});
		});
	});

	describe('2. Requirements Terminology', () => {
		/** The same SEQUENCE, with the AlgorithmIdentifier child at `index` given a DER NULL. */
		function withNullParameters(der: Uint8Array, index: number): Uint8Array {
			return sequence(
				readSequenceChildren(der).map((child, position) =>
					position === index
						? sequence([objectIdentifier(OIDS.ed25519), nullValue()])
						: sliceElement(der, child),
				),
			);
		}

		/** A fresh self-signed Ed25519 certificate carrying `signatureAlgorithmDer` in both signature fields. */
		async function issueWithSignatureAlgorithm(
			signatureAlgorithmDer: Uint8Array,
		): Promise<Uint8Array> {
			const { certificate, keyPair } = await createSelfSignedCertificate({
				subject: { commonName: 'bcp14.example' },
				algorithm: ED25519,
			});
			const tbsDer = parseCertificatePemOrThrow(certificate.pem).tbsCertificateDer;
			const tbsChildren = readSequenceChildren(tbsDer);
			const signatureIndex = tbsChildren[0]?.tag === 0xa0 ? 2 : 1;
			const tbs = sequence(
				tbsChildren.map((child, index) =>
					index === signatureIndex ? signatureAlgorithmDer : sliceElement(tbsDer, child),
				),
			);
			const signature = new Uint8Array(
				await globalThis.crypto.subtle.sign(
					{ name: 'Ed25519' },
					keyPair.privateKey,
					toArrayBuffer(tbs),
				),
			);
			return sequence([tbs, signatureAlgorithmDer, bitString(signature)]);
		}

		async function verifyAgainstOwnKey(
			certificateDer: Uint8Array,
		): Promise<BuildCandidatePathResult> {
			const certificate = parseCertificateDerOrThrow(certificateDer);
			return buildCandidatePath({
				leaf: certificateDer,
				roots: [],
				trustAnchors: [
					{
						subject: certificate.issuer,
						subjectPublicKeyInfoDer: certificate.subjectPublicKeyInfoDer,
						publicKeyAlgorithmOid: certificate.publicKeyAlgorithmOid,
					},
				],
			});
		}

		// The key words are "to be interpreted as described in BCP 14 [RFC2119]
		// [RFC8174] when, and only when, they appear in all capitals". RFC 2119 1
		// makes MUST "an absolute requirement of the specification", so Section 3's
		// "For all of the OIDs, the parameters MUST be absent" binds the identifiers
		// this library reads as well as the ones it writes. The lowercase
		// "parameters, which are optional" six lines above it is not the BCP 14
		// OPTIONAL and licenses no DER NULL. Section 3 names three places the same
		// identifier appears, "a public key, a private key, and a signature", so
		// each is checked here. The unmodified RFC block is the control that shows
		// only the parameters make the difference.
		it('rejects a DER NULL in the public key AlgorithmIdentifier', async () => {
			const spki = pemDecodeOrThrow('PUBLIC KEY', blockAt(248));
			expect(await importSpkiDer(spki, ED25519)).toMatchObject({ ok: true });
			expect(await importSpkiDer(withNullParameters(spki, 0), ED25519)).toMatchObject({
				ok: false,
				code: 'malformed',
			});
		});

		it('rejects a DER NULL in the private key AlgorithmIdentifier', async () => {
			const pkcs8 = pemDecodeOrThrow('PRIVATE KEY', blockAt(402));
			expect(await importPkcs8Der(pkcs8, ED25519)).toMatchObject({ ok: true });
			expect(await importPkcs8Der(withNullParameters(pkcs8, 1), ED25519)).toMatchObject({
				ok: false,
				code: 'malformed',
			});
		});

		it('rejects a DER NULL in the signature AlgorithmIdentifier', async () => {
			const absent = await issueWithSignatureAlgorithm(sequence([objectIdentifier(OIDS.ed25519)]));
			expect(parseCertificateDerOrThrow(absent).signatureAlgorithmParametersDer).toBeUndefined();
			expect(await verifyAgainstOwnKey(absent)).toMatchObject({ ok: true });

			const present = await issueWithSignatureAlgorithm(
				sequence([objectIdentifier(OIDS.ed25519), nullValue()]),
			);
			expect(parseCertificateDerOrThrow(present).signatureAlgorithmParametersDer).toEqual(
				Uint8Array.from([0x05, 0x00]),
			);
			expect(await verifyAgainstOwnKey(present)).toMatchObject({
				ok: false,
				code: 'unsupported_signature_algorithm_parameters',
			});
		});
	});

	describe('3. Curve25519 and Curve448 Algorithm Identifiers', () => {
		const ID_X25519 = '1.3.101.110';
		const ID_X448 = '1.3.101.111';
		const ID_ED25519 = '1.3.101.112';
		const ID_ED448 = '1.3.101.113';

		/** The AlgorithmIdentifier child at `index` of a SEQUENCE, as its own DER element. */
		function algorithmIdentifierAt(der: Uint8Array, index: number): Uint8Array {
			const child = readSequenceChildren(der)[index];
			if (child === undefined) {
				throw new Error(`no child at index ${index}`);
			}
			return sliceElement(der, child);
		}

		function algorithmOidOf(algorithmIdentifierDer: Uint8Array): string {
			const children = readSequenceChildren(algorithmIdentifierDer);
			const oid = children[0];
			if (oid === undefined) {
				throw new Error('AlgorithmIdentifier carries no algorithm OID');
			}
			return decodeDerOidOrThrow(oid);
		}

		/** The same OCSP response, with a DER NULL added to the signature AlgorithmIdentifier. */
		function withNullSignatureParameters(responseDer: Uint8Array): Uint8Array {
			const [status, responseBytes] = readSequenceChildren(responseDer);
			if (status === undefined || responseBytes === undefined) {
				throw new Error('OCSPResponse carries no responseBytes');
			}
			const responseBytesDer = responseDer.slice(responseBytes.start, responseBytes.end);
			const [responseType, response] = readSequenceChildren(responseBytesDer);
			if (responseType === undefined || response === undefined) {
				throw new Error('ResponseBytes is malformed');
			}
			const basic = responseBytesDer.slice(response.start, response.end);
			const rebuiltBasic = sequence(
				readSequenceChildren(basic).map((child, index) =>
					index === 1
						? sequence([objectIdentifier(ID_ED25519), nullValue()])
						: sliceElement(basic, child),
				),
			);
			return sequence([
				sliceElement(responseDer, status),
				explicitContext(
					0,
					sequence([sliceElement(responseBytesDer, responseType), octetString(rebuiltBasic)]),
				),
			]);
		}

		// "In this document, we define four new OIDs for identifying the different
		// curve/algorithm pairs", listed as id-X25519 { 1 3 101 110 }, id-X448
		// { 1 3 101 111 }, id-Ed25519 { 1 3 101 112 }, and id-Ed448 { 1 3 101 113 }.
		it.each([
			[ID_X25519, '06032b656e'],
			[ID_X448, '06032b656f'],
			[ID_ED25519, '06032b6570'],
			[ID_ED448, '06032b6571'],
		])('encodes and decodes %s under the 1.3.101 arc', (dotted, expectedHex) => {
			const der = objectIdentifier(dotted);
			expect(hex(der)).toBe(expectedHex);
			expect(decodeDerOidOrThrow(readRootElement(der))).toBe(dotted);
		});

		it('names id-Ed25519, the one of the four it implements', () => {
			expect(OIDS.ed25519).toBe(ID_ED25519);
		});

		// "The same algorithm identifiers are used for identifying a public key, a
		// private key, and a signature (for the two EdDSA related OIDs)." The
		// Section 4 public key, the Section 7 private key, and the signature over the
		// Section 10.2 certificate all spell id-Ed25519.
		it('reads one identifier from a public key, a private key, and a signature', () => {
			const spki = pemDecodeOrThrow('PUBLIC KEY', blockAt(248));
			const pkcs8 = pemDecodeOrThrow('PRIVATE KEY', blockAt(402));
			expect(algorithmOidOf(algorithmIdentifierAt(spki, 0))).toBe(ID_ED25519);
			expect(algorithmOidOf(algorithmIdentifierAt(pkcs8, 1))).toBe(ID_ED25519);
			expect(parseCertificatePemOrThrow(blockAt(717)).signatureAlgorithmOid).toBe(ID_ED25519);
		});

		// "For all of the OIDs, the parameters MUST be absent." An absent parameters
		// field leaves the AlgorithmIdentifier SEQUENCE holding the algorithm OID and
		// nothing else, so each identifier the RFC prints encodes to exactly that.
		it.each([
			[
				'the Section 4 public key',
				() => pemDecodeOrThrow('PUBLIC KEY', blockAt(248)),
				0,
				ID_ED25519,
			],
			[
				'the Section 7 private key',
				() => pemDecodeOrThrow('PRIVATE KEY', blockAt(402)),
				1,
				ID_ED25519,
			],
			[
				'the Section 10.2 subject public key',
				() => parseCertificatePemOrThrow(blockAt(717)).subjectPublicKeyInfoDer,
				0,
				ID_X25519,
			],
		])('omits parameters in %s', (_label, load, index, oid) => {
			expect(algorithmIdentifierAt(load(), index)).toEqual(sequence([objectIdentifier(oid)]));
		});

		it('omits parameters in the Section 10.2 signature AlgorithmIdentifier', () => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			expect(certificate.signatureAlgorithmParametersDer).toBeUndefined();
			expect(algorithmIdentifierAt(certificate.der, 1)).toEqual(
				sequence([objectIdentifier(ID_ED25519)]),
			);
		});

		it('emits no parameters in a SubjectPublicKeyInfo this library generates', async () => {
			const keyPair = await generateKeyPair(ED25519);
			expect(algorithmIdentifierAt(await keyPair.exportSpkiDer(), 0)).toEqual(
				sequence([objectIdentifier(ID_ED25519)]),
			);
		});

		it('emits no parameters in either signature AlgorithmIdentifier it generates', async () => {
			const created = await createSelfSignedCertificate({
				subject: { commonName: 'ed25519-params.example' },
				algorithm: ED25519,
			});
			const parsed = parseCertificatePemOrThrow(created.certificate.pem);
			const absent = sequence([objectIdentifier(ID_ED25519)]);
			expect(parsed.signatureAlgorithmParametersDer).toBeUndefined();
			expect(algorithmIdentifierAt(parsed.der, 1)).toEqual(absent);
			const tbsChildren = readSequenceChildren(parsed.tbsCertificateDer);
			const signatureIndex = tbsChildren[0]?.tag === 0xa0 ? 2 : 1;
			expect(algorithmIdentifierAt(parsed.tbsCertificateDer, signatureIndex)).toEqual(absent);
		});

		// A signature identifier is the same identifier wherever it is carried, so
		// "the parameters MUST be absent" binds the OCSP and CRL signature fields as
		// much as the certificate one. Swapping only the AlgorithmIdentifier leaves
		// the signature valid over its unchanged signed payload, so a verdict of
		// verified would come from ignoring the parameters.
		it('does not verify an OCSP response whose Ed25519 identifier carries a NULL', async () => {
			const responder = await createSelfSignedCertificate({
				subject: { commonName: 'ed25519-ocsp.example' },
				algorithm: ED25519,
				extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
			});
			const subject = await createSelfSignedCertificate({
				subject: { commonName: 'ed25519-ocsp-subject.example' },
				algorithm: ED25519,
			});
			const response = await createOcspResponse({
				signerPrivateKey: responder.keyPair.privateKey,
				signerCertificate: responder.certificate.pem,
				responses: [
					{
						certificate: subject.certificate.pem,
						issuerCertificate: responder.certificate.pem,
						certStatus: 'good',
					},
				],
			});
			expect(
				parseOcspResponseDerOrThrow(response.der).signatureAlgorithmParametersDer,
			).toBeUndefined();
			expect(
				await verifyOcspResponseSignature(response.der, responder.certificate.pem),
			).toMatchObject({ ok: true });

			const mutated = withNullSignatureParameters(response.der);
			expect(parseOcspResponseDerOrThrow(mutated).signatureAlgorithmParametersDer).toEqual(
				Uint8Array.from([0x05, 0x00]),
			);
			expect(await verifyOcspResponseSignature(mutated, responder.certificate.pem)).toMatchObject({
				ok: false,
				code: 'signature_invalid',
			});
		});

		it('does not verify a CRL whose Ed25519 identifier carries a NULL', async () => {
			const issuer = await createSelfSignedCertificate({
				subject: { commonName: 'ed25519-crl.example' },
				algorithm: ED25519,
				extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
			});
			const crl = await createCertificateRevocationList({
				issuer: { commonName: 'ed25519-crl.example' },
				signerPrivateKey: issuer.keyPair.privateKey,
				issuerPublicKey: issuer.keyPair.publicKey,
				crlNumber: 1,
				revokedCertificates: [],
			});
			expect(
				await verifyCertificateRevocationListSignature(crl.der, issuer.certificate.pem),
			).toMatchObject({ ok: true });

			// RFC 5280 §5.1.1.2 binds the CertificateList signatureAlgorithm to the
			// signature field of the tbsCertList, so the NULL goes into both and the
			// CRL is signed again over the tbsCertList that carries it. The forbidden
			// parameters are then the only thing wrong with it.
			const ed25519WithNull = sequence([objectIdentifier(ID_ED25519), nullValue()]);
			const tbsCertListDer = sliceElement(
				crl.der,
				readSequenceChildren(crl.der)[0] ?? readRootElement(crl.der),
			);
			const mutatedTbs = sequence(
				readSequenceChildren(tbsCertListDer).map((child, index) =>
					index === 1 ? ed25519WithNull : sliceElement(tbsCertListDer, child),
				),
			);
			const signature = await crypto.subtle.sign(
				{ name: 'Ed25519' },
				issuer.keyPair.privateKey,
				toArrayBuffer(mutatedTbs),
			);
			const mutated = sequence([mutatedTbs, ed25519WithNull, bitString(new Uint8Array(signature))]);
			expect(
				parseCertificateRevocationListDerOrThrow(mutated).signatureAlgorithmParametersDer,
			).toEqual(Uint8Array.from([0x05, 0x00]));
			expect(
				await verifyCertificateRevocationListSignature(mutated, issuer.certificate.pem),
			).toMatchObject({ ok: false, code: 'signature_invalid' });
		});
	});

	describe('4. Subject Public Key Fields', () => {
		/** The 32-byte Ed25519 public key the Section 4 example carries. */
		const PUBLIC_KEY_HEX = '19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1';

		const section4Spki = (): Uint8Array => pemDecodeOrThrow('PUBLIC KEY', blockAt(248));

		/** The two fields of a SubjectPublicKeyInfo, rejecting any SEQUENCE that holds a different count. */
		function fieldsOf(der: Uint8Array): {
			readonly algorithm: DerElement;
			readonly subjectPublicKey: DerElement;
		} {
			const [algorithm, subjectPublicKey, ...rest] = readSequenceChildren(der);
			if (algorithm === undefined || subjectPublicKey === undefined || rest.length > 0) {
				throw new Error('SubjectPublicKeyInfo does not hold exactly two fields');
			}
			return { algorithm, subjectPublicKey };
		}

		/** The same SubjectPublicKeyInfo, with `subjectPublicKey` replaced. */
		function withSubjectPublicKey(der: Uint8Array, replacement: Uint8Array): Uint8Array {
			return sequence([sliceElement(der, fieldsOf(der).algorithm), replacement]);
		}

		/** The child at `index` of a SEQUENCE, as its own DER element. */

		/** The 32 octets the Section 7 private key wraps in its `CurvePrivateKey`. */
		function section7Scalar(): Uint8Array {
			const pkcs8 = pemDecodeOrThrow('PRIVATE KEY', blockAt(402));
			const privateKey = readSequenceChildren(pkcs8)[2];
			if (privateKey === undefined) {
				throw new Error('OneAsymmetricKey holds no privateKey field');
			}
			return readRootElement(privateKey.value).value;
		}

		/**
		 * The RFC 7748 public key of a 32-octet scalar, computed outside this
		 * library because it implements neither X25519 nor X448.
		 */
		async function rfc7748PublicKey(scalar: Uint8Array): Promise<Uint8Array> {
			const key = await globalThis.crypto.subtle.importKey(
				'pkcs8',
				toArrayBuffer(
					sequence([
						integer(Uint8Array.of(0)),
						sequence([objectIdentifier(OIDS.x25519)]),
						octetString(octetString(scalar)),
					]),
				),
				'X25519',
				true,
				['deriveBits'],
			);
			const { crv, kty, x } = await globalThis.crypto.subtle.exportKey('jwk', key);
			const publicKey = await globalThis.crypto.subtle.importKey(
				'jwk',
				{ crv, kty, x },
				'X25519',
				true,
				[],
			);
			const spki = new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', publicKey));
			return fieldsOf(spki).subjectPublicKey.value.slice(1);
		}

		/** The same key re-encoded as 255 bits, with its low bit dropped and declared unused. */
		function asTruncatedBitString(key: Uint8Array): Uint8Array {
			const truncated = new Uint8Array(key);
			const last = truncated[truncated.length - 1];
			if (last === undefined) {
				throw new Error('empty key');
			}
			truncated[truncated.length - 1] = last & 0xfe;
			return bitString(truncated, 1);
		}

		// "SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
		// subjectPublicKey BIT STRING }". Rebuilding the example from its two
		// fields reproduces it byte for byte, so the SEQUENCE holds those two
		// fields in that order and nothing else.
		it('encodes the example as an AlgorithmIdentifier and a BIT STRING, in that order', () => {
			const spki = section4Spki();
			const { algorithm, subjectPublicKey } = fieldsOf(spki);
			expect(algorithm.tag).toBe(0x30);
			expect(subjectPublicKey.tag).toBe(0x03);
			expect(
				sequence([sliceElement(spki, algorithm), sliceElement(spki, subjectPublicKey)]),
			).toEqual(spki);
		});

		// "subjectPublicKey contains the byte stream of the public key. The
		// algorithms defined in this document always encode the public key as an
		// exact multiple of 8 bits." The BIT STRING therefore declares no unused
		// bits, and its payload is the 32-octet string RFC 8032 5.1.5 defines.
		it('declares no unused bits and carries 32 whole octets', () => {
			const spki = section4Spki();
			const { subjectPublicKey } = fieldsOf(spki);
			expect(subjectPublicKey.value[0]).toBe(0);
			expect(hex(subjectPublicKey.value.slice(1))).toBe(PUBLIC_KEY_HEX);
		});

		it('imports the example and exports the same bytes back', async () => {
			const key = await importSpkiPemOrThrow(blockAt(248), ED25519);
			expect(key.algorithm.name).toBe('Ed25519');
			expect(key.type).toBe('public');
			expect(await exportSpkiDer(key)).toEqual(section4Spki());
		});

		// WebCrypto's raw form of the imported key is the same 32 octets, so the
		// BIT STRING payload is the public key value with nothing wrapped around it.
		it('carries the public key with no encoding of its own', async () => {
			const key = await importSpkiPemOrThrow(blockAt(248), ED25519);
			const raw = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', key));
			expect(hex(raw)).toBe(PUBLIC_KEY_HEX);
		});

		// "Both [RFC7748] and [RFC8032] define the public key value as being a
		// byte string." The Section 7 private key is the pair of this public key,
		// so the byte stream is the value RFC 8032 5.1.5 computes from it.
		it('holds the RFC 8032 public key of the Section 7 private key', async () => {
			const privateKey = await importPkcs8PemOrThrow(blockAt(402), ED25519);
			const publicKey = await derivePublicKey(privateKey);
			expect(await exportSpkiDer(publicKey)).toEqual(section4Spki());
		});

		// A key re-encoded as 255 bits is well-formed DER, its one unused bit
		// being zero, so the rejection comes from the "exact multiple of 8 bits"
		// rule alone.
		it('does not import a public key encoded as 255 bits', async () => {
			const spki = section4Spki();
			const truncated = withSubjectPublicKey(
				spki,
				asTruncatedBitString(fieldsOf(spki).subjectPublicKey.value.slice(1)),
			);
			expect(await importSpkiDer(truncated, ED25519)).toMatchObject({
				ok: false,
				code: 'malformed',
			});
		});

		// "In the X.509 certificate, the subjectPublicKeyInfo field has the
		// SubjectPublicKeyInfo type", so the same rule binds the field inside a
		// certificate. Only the subject key changes here; the Section 10.2
		// certificate is otherwise untouched.
		it('does not parse a certificate whose subjectPublicKey is not whole octets', () => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			const tbsDer = certificate.tbsCertificateDer;
			const tbsChildren = readSequenceChildren(tbsDer);
			const spkiIndex = tbsChildren[0]?.tag === 0xa0 ? 6 : 5;
			const spkiDer = childAt(tbsDer, spkiIndex);
			const truncated = withSubjectPublicKey(
				spkiDer,
				asTruncatedBitString(fieldsOf(spkiDer).subjectPublicKey.value.slice(1)),
			);
			const mutated = sequence([
				sequence(
					tbsChildren.map((child, index) =>
						index === spkiIndex ? truncated : sliceElement(tbsDer, child),
					),
				),
				childAt(certificate.der, 1),
				childAt(certificate.der, 2),
			]);
			expect(parseCertificateDer(mutated)).toMatchObject({ ok: false, code: 'malformed' });
		});

		// The type admits two fields, so a SEQUENCE carrying a third, or carrying
		// the key as an OCTET STRING, is not a SubjectPublicKeyInfo. "algorithm
		// AlgorithmIdentifier" names the SEQUENCE of Section 3, so an OID sitting
		// where that SEQUENCE belongs is not one either.
		it.each([
			[
				'a third field',
				(spki: Uint8Array) =>
					sequence([...readSequenceChildren(spki).map((c) => sliceElement(spki, c)), nullValue()]),
			],
			[
				'the key in an OCTET STRING',
				(spki: Uint8Array) =>
					withSubjectPublicKey(spki, octetString(fieldsOf(spki).subjectPublicKey.value.slice(1))),
			],
			[
				'the algorithm OID outside an AlgorithmIdentifier',
				(spki: Uint8Array) =>
					sequence([
						objectIdentifier(OIDS.ed25519),
						sliceElement(spki, fieldsOf(spki).subjectPublicKey),
					]),
			],
		])('does not import a SubjectPublicKeyInfo with %s', async (_label, mutate) => {
			expect(await importSpkiDer(mutate(section4Spki()), ED25519)).toMatchObject({
				ok: false,
				code: 'malformed',
			});
		});

		// RFC 8032 5.1.5 makes an Ed25519 public key "a string of 32 octets", so a
		// byte stream of any other length is not one, however well-formed the
		// BIT STRING around it is.
		it('does not import a 33-octet Ed25519 byte stream', async () => {
			const spki = section4Spki();
			const padded = new Uint8Array([...fieldsOf(spki).subjectPublicKey.value.slice(1), 0x00]);
			expect(
				await importSpkiDer(withSubjectPublicKey(spki, bitString(padded)), ED25519),
			).toMatchObject({ ok: false, code: 'malformed' });
		});

		// "the public key is computed differently for each of these documents;
		// thus, the same private key will not produce the same public key". The
		// algorithm identifier is what says which document computed the byte
		// stream, so the X25519 key of the Section 10.2 certificate is no Ed25519
		// key, while the same 32 octets relabelled id-Ed25519 are.
		it('reads the key algorithm from the algorithm identifier', async () => {
			const spki = parseCertificatePemOrThrow(blockAt(717)).subjectPublicKeyInfoDer;
			const bytes = fieldsOf(spki).subjectPublicKey.value.slice(1);
			expect(await importSpkiDer(spki, ED25519)).toMatchObject({ ok: false, code: 'malformed' });
			expect(await importSpkiDer(spki)).toMatchObject({ ok: false, code: 'malformed' });
			const relabelled = sequence([sequence([objectIdentifier(OIDS.ed25519)]), bitString(bytes)]);
			expect(await importSpkiDer(relabelled, ED25519)).toMatchObject({ ok: true });
		});

		it('emits whole octets in a SubjectPublicKeyInfo it generates', async () => {
			const keyPair = await generateKeyPair(ED25519);
			const spki = await keyPair.exportSpkiDer();
			const { subjectPublicKey } = fieldsOf(spki);
			expect(subjectPublicKey.tag).toBe(0x03);
			expect(subjectPublicKey.value[0]).toBe(0);
			const raw = new Uint8Array(
				await globalThis.crypto.subtle.exportKey('raw', keyPair.publicKey),
			);
			expect(subjectPublicKey.value.slice(1)).toEqual(raw);
			expect(raw).toHaveLength(32);
		});

		// "In the X.509 certificate, the subjectPublicKeyInfo field has the
		// SubjectPublicKeyInfo type". The Section 10.2 certificate carries an
		// id-X25519 key, so the same two-field shape and the same "exact multiple
		// of 8 bits" rule bind a second of the four algorithms, and the field the
		// parse surfaces is the certificate's own bytes rather than a re-encoding.
		it('reads the Section 10.2 X25519 subject key as whole octets of the certificate', () => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			const spki = certificate.subjectPublicKeyInfoDer;
			expect(hex(certificate.der)).toContain(hex(spki));
			expect(certificate.publicKeyAlgorithmOid).toBe(OIDS.x25519);
			const { subjectPublicKey } = fieldsOf(spki);
			expect(subjectPublicKey.tag).toBe(0x03);
			expect(subjectPublicKey.value[0]).toBe(0);
			expect(subjectPublicKey.value.slice(1)).toHaveLength(32);
		});

		// "the public key is computed differently for each of these documents;
		// thus, the same private key will not produce the same public key". The
		// CurvePrivateKey of the Section 7 key, read as an RFC 7748 scalar instead
		// of an RFC 8032 one, yields a different byte stream, so the key this
		// library derives is the RFC 8032 one and only that.
		it('derives the RFC 8032 public key, not the RFC 7748 one, from the same private key', async () => {
			const privateKey = await importPkcs8PemOrThrow(blockAt(402), ED25519);
			const edwards = fieldsOf(
				await exportSpkiDer(await derivePublicKey(privateKey)),
			).subjectPublicKey.value.slice(1);
			const montgomery = await rfc7748PublicKey(section7Scalar());
			expect(hex(edwards)).toBe(PUBLIC_KEY_HEX);
			expect(hex(montgomery)).not.toBe(PUBLIC_KEY_HEX);
		});

		// The same sentence, as a pairing: a OneAsymmetricKey that carries the
		// Section 7 private key beside the RFC 7748 public key of that private key
		// holds two values from two documents, and the library must not read it as
		// a key pair.
		it('does not import the Section 7 private key beside its RFC 7748 public key', async () => {
			const paired = sequence([
				integer(Uint8Array.of(1)),
				sequence([objectIdentifier(OIDS.ed25519)]),
				octetString(octetString(section7Scalar())),
				implicitPrimitiveContext(
					1,
					new Uint8Array([0, ...(await rfc7748PublicKey(section7Scalar()))]),
				),
			]);
			expect(await importPkcs8Der(paired, ED25519)).toMatchObject({
				ok: false,
				code: 'malformed',
			});
		});
	});

	describe('5. Key Usage Bits', () => {
		const ID_X25519 = '1.3.101.110';
		const ID_X448 = '1.3.101.111';
		const ID_ED448 = '1.3.101.113';

		/**
		 * RFC 9295 §3: the bits an id-X25519 or id-X448 certificate must never assert.
		 *
		 * RFC 8410 §5 listed what must and may be present and stopped there; RFC 9295
		 * §3, which replaces the section, adds the MUST NOT list.
		 */
		const MONTGOMERY_FORBIDDEN_BITS = [
			['digitalSignature'],
			['nonRepudiation'],
			['keyEncipherment'],
			['dataEncipherment'],
			['keyCertSign'],
			['cRLSign'],
		] as const;

		/** RFC 9295 §3: the bits an id-Ed25519 or id-Ed448 certificate must never assert. */
		const EDWARDS_FORBIDDEN_BITS = [
			['keyEncipherment'],
			['dataEncipherment'],
			['keyAgreement'],
			['encipherOnly'],
			['decipherOnly'],
		] as const;

		/**
		 * A SubjectPublicKeyInfo naming `oid` over `octets` zero bytes.
		 *
		 * WebCrypto here implements neither X448 nor Ed448, so those two curves reach
		 * the extension builder as a bare SubjectPublicKeyInfo of the length RFC 7748
		 * and RFC 8032 give the curve. The rule under test reads only the algorithm
		 * identifier, so the key value never has to be a point.
		 */
		function spkiNaming(oid: string, octets: number): Uint8Array {
			return sequence([sequence([objectIdentifier(oid)]), bitString(new Uint8Array(octets))]);
		}

		const X448_SPKI = spkiNaming(ID_X448, 56);
		const ED448_SPKI = spkiNaming(ID_ED448, 57);

		/** The extnValue octets of the keyUsage extension in a built extension list. */
		function keyUsageValueOf(extensions: readonly Uint8Array[]): Uint8Array | undefined {
			for (const extension of extensions) {
				const children = readSequenceChildren(extension);
				const oid = children[0];
				const value = children.at(-1);
				if (oid === undefined || value === undefined) {
					continue;
				}
				if (decodeDerOidOrThrow(oid) === OIDS.keyUsage) {
					return value.value;
				}
			}
			return undefined;
		}

		/** The Section 7 private key and the Section 4 public key it computes. */
		async function issuerKeyPair(): Promise<{
			readonly privateKey: CryptoKey;
			readonly publicKey: CryptoKey;
		}> {
			const privateKey = await importPkcs8PemOrThrow(blockAt(402), ED25519);
			return { privateKey, publicKey: await derivePublicKey(privateKey) };
		}

		/** A certificate over `publicKey`, signed by the Section 7 key. */
		async function issue(
			publicKey: CryptoKey,
			extensions: CertificateExtensionsInput,
		): Promise<CertificateMaterial> {
			const { privateKey, publicKey: issuerPublicKey } = await issuerKeyPair();
			return createCertificate({
				issuer: { commonName: 'IETF Test Demo' },
				subject: { commonName: 'IETF Test Demo' },
				publicKey,
				signerPrivateKey: privateKey,
				issuerPublicKey,
				extensions,
			});
		}

		/** The X25519 key the Section 10.2 certificate carries. */
		function x25519PublicKey(): Promise<CryptoKey> {
			return globalThis.crypto.subtle.importKey(
				'spki',
				toArrayBuffer(parseCertificatePemOrThrow(blockAt(717)).subjectPublicKeyInfoDer),
				{ name: 'X25519' },
				true,
				[],
			);
		}

		/** The Section 4 Ed25519 public key. */
		function ed25519PublicKey(): Promise<CryptoKey> {
			return importSpkiPemOrThrow(blockAt(248), ED25519);
		}

		// "The intended application for the key is indicated in the keyUsage
		// certificate extension." The Section 10.2 certificate indicates id-X25519
		// and spells that application as bit 4 alone.
		it('reads keyAgreement, and only that, from the Section 10.2 X25519 certificate', () => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			expect(certificate.publicKeyAlgorithmOid).toBe(ID_X25519);
			expect(certificate.keyUsage?.flags).toEqual(['keyAgreement']);
		});

		// "If the keyUsage extension is present in a certificate that indicates
		// id-X25519 or id-X448 in SubjectPublicKeyInfo, then the following MUST be
		// present: keyAgreement." The subject key is the RFC's own X25519 key, so
		// only the keyUsage bits differ between these cases and the ones below.
		it.each([
			['digitalSignature'],
			['keyEncipherment'],
			['encipherOnly'],
			['decipherOnly'],
		] as const)(
			'does not issue an X25519 certificate whose keyUsage is %s without keyAgreement',
			async (flag) => {
				await expectRejectedErrorCode(
					issue(await x25519PublicKey(), { keyUsage: [flag] }),
					'montgomery_key_usage_requires_key_agreement',
				);
			},
		);

		// "one of the following MAY also be present: encipherOnly; or decipherOnly."
		it.each([
			[['keyAgreement']],
			[['keyAgreement', 'encipherOnly']],
			[['keyAgreement', 'decipherOnly']],
		] as const)('issues an X25519 certificate whose keyUsage is %p', async (flags) => {
			const certificate = await issue(await x25519PublicKey(), { keyUsage: flags });
			const parsed = parseCertificateDerOrThrow(certificate.der);
			expect(parsed.publicKeyAlgorithmOid).toBe(ID_X25519);
			expect(parsed.keyUsage?.flags).toEqual([...flags]);
		});

		// The clause admits "one of the following", where the two EdDSA clauses below
		// admit "one or both" and "one or more" of theirs, so the two cipher bits are
		// alternatives rather than a pair. RFC 5280 4.2.1.3 gives them contradictory
		// meanings: encipherOnly restricts the key to enciphering data while
		// performing key agreement, decipherOnly to deciphering it.
		it('does not issue an X25519 certificate whose keyUsage sets both cipher bits', async () => {
			await expectRejectedErrorCode(
				issue(await x25519PublicKey(), {
					keyUsage: ['keyAgreement', 'encipherOnly', 'decipherOnly'],
				}),
				'montgomery_key_usage_forbids_both_cipher_bits',
			);
		});

		// "and any of the following MUST NOT be present: digitalSignature;
		// nonRepudiation; keyEncipherment; dataEncipherment; keyCertSign; cRLSign."
		// Each bit joins the keyAgreement the same paragraph requires, so the
		// forbidden bit is the only thing wrong with the set.
		it.each(MONTGOMERY_FORBIDDEN_BITS)(
			'does not issue an X448 certificate whose keyUsage adds %s to keyAgreement',
			(flag) => {
				expectBuildErrorCode(
					() =>
						buildCertificateExtensions(X448_SPKI, undefined, {
							keyUsage: ['keyAgreement', flag],
						}),
					'montgomery_key_usage_forbids_signature_bit',
				);
			},
		);

		// The two encipherment bits are the ones RFC 8410 §5 never named, so they run
		// through the whole builder over the RFC's own X25519 key.
		it.each([['keyEncipherment'], ['dataEncipherment']] as const)(
			'does not issue an X25519 certificate whose keyUsage adds %s to keyAgreement',
			async (flag) => {
				await expectRejectedErrorCode(
					issue(await x25519PublicKey(), { keyUsage: ['keyAgreement', flag] }),
					'montgomery_key_usage_forbids_signature_bit',
				);
			},
		);

		// The same clause names id-X448 alongside id-X25519.
		it('holds an X448 subject key to the same keyAgreement rule', () => {
			expectBuildErrorCode(
				() => buildCertificateExtensions(X448_SPKI, undefined, { keyUsage: ['digitalSignature'] }),
				'montgomery_key_usage_requires_key_agreement',
			);
			expectBuildErrorCode(
				() =>
					buildCertificateExtensions(X448_SPKI, undefined, {
						keyUsage: ['keyAgreement', 'encipherOnly', 'decipherOnly'],
					}),
				'montgomery_key_usage_forbids_both_cipher_bits',
			);
			expect(
				keyUsageValueOf(
					buildCertificateExtensions(X448_SPKI, undefined, {
						keyUsage: ['keyAgreement', 'decipherOnly'],
					}),
				),
			).toEqual(encodeKeyUsage(['keyAgreement', 'decipherOnly']));
		});

		// The clause governs "a certificate", where the two EdDSA clauses below split
		// an end-entity certificate from a certification authority certificate, so
		// basicConstraints leaves the X25519 and X448 set alone.
		it('holds an X25519 certification authority certificate to the same rule', async () => {
			await expectRejectedErrorCode(
				issue(await x25519PublicKey(), {
					basicConstraints: { ca: true },
					keyUsage: ['cRLSign'],
				}),
				'montgomery_key_usage_requires_key_agreement',
			);
			const certificate = await issue(await x25519PublicKey(), {
				basicConstraints: { ca: true },
				keyUsage: ['keyAgreement'],
			});
			const parsed = parseCertificateDerOrThrow(certificate.der);
			expect(parsed.basicConstraints).toEqual({ ca: true });
			expect(parsed.keyUsage?.flags).toEqual(['keyAgreement']);
		});

		// "If the keyUsage extension is present in an end-entity certificate that
		// indicates id-Ed25519 or id-Ed448, then the keyUsage extension MUST contain
		// one or both of the following values: nonRepudiation; and digitalSignature."
		it.each([
			[['digitalSignature']],
			[['nonRepudiation']],
			[['digitalSignature', 'nonRepudiation']],
		] as const)('issues an Ed25519 end-entity certificate whose keyUsage is %p', async (flags) => {
			const certificate = await issue(await ed25519PublicKey(), { keyUsage: flags });
			const parsed = parseCertificateDerOrThrow(certificate.der);
			expect(parsed.basicConstraints).toEqual({ ca: false });
			expect(parsed.keyUsage?.flags).toEqual([...flags]);
		});

		// RFC 9295 §3 adds cRLSign to the end-entity set: "MUST contain at least one
		// of the following: nonRepudiation; digitalSignature; cRLSign". A CRL issuer
		// that is not a certification authority is that case.
		it('issues an Ed25519 end-entity certificate whose keyUsage is only cRLSign', async () => {
			const certificate = await issue(await ed25519PublicKey(), { keyUsage: ['cRLSign'] });
			expect(parseCertificateDerOrThrow(certificate.der).keyUsage?.flags).toEqual(['cRLSign']);
		});

		it.each([['keyEncipherment'], ['keyAgreement']] as const)(
			'does not issue an Ed25519 end-entity certificate whose keyUsage is only %s',
			async (flag) => {
				await expectRejectedErrorCode(
					issue(await ed25519PublicKey(), { keyUsage: [flag] }),
					'edwards_key_usage_requires_signing_bit',
				);
			},
		);

		// The same section forbids keyCertSign outside a certification authority
		// certificate, so the bit is refused here and required below.
		it('does not issue an Ed25519 end-entity certificate asserting keyCertSign', async () => {
			await expectRejectedErrorCode(
				issue(await ed25519PublicKey(), { keyUsage: ['digitalSignature', 'keyCertSign'] }),
				'edwards_key_usage_forbids_key_cert_sign',
			);
		});

		// "and any of the following MUST NOT be present: keyEncipherment;
		// dataEncipherment; keyAgreement; keyCertSign; encipherOnly; decipherOnly."
		// Each bit joins the digitalSignature the same paragraph accepts.
		it.each(EDWARDS_FORBIDDEN_BITS)(
			'does not issue an Ed448 end-entity certificate whose keyUsage adds %s to digitalSignature',
			(flag) => {
				expectBuildErrorCode(
					() =>
						buildCertificateExtensions(ED448_SPKI, undefined, {
							keyUsage: ['digitalSignature', flag],
						}),
					'edwards_key_usage_forbids_agreement_bit',
				);
			},
		);

		// The two encipherment bits are the ones RFC 8410 §5 never named, so they run
		// through the whole builder over the RFC's own Ed25519 key.
		it.each([['keyEncipherment'], ['dataEncipherment']] as const)(
			'does not issue an Ed25519 end-entity certificate whose keyUsage adds %s to digitalSignature',
			async (flag) => {
				await expectRejectedErrorCode(
					issue(await ed25519PublicKey(), { keyUsage: ['digitalSignature', flag] }),
					'edwards_key_usage_forbids_agreement_bit',
				);
			},
		);

		// "If the keyUsage extension is present in a certification authority
		// certificate that indicates id-Ed25519 or id-Ed448 in SubjectPublicKeyInfo,
		// then the keyUsage extension MUST contain: keyCertSign; and zero or more of
		// the following: nonRepudiation; digitalSignature; cRLSign". RFC 8410 §5 had
		// accepted any one of the four; RFC 9295 §3 pins keyCertSign as the required
		// one and demotes the other three to optional.
		it.each([['nonRepudiation'], ['digitalSignature'], ['cRLSign']] as const)(
			'issues an Ed25519 certification authority certificate carrying keyCertSign and %s',
			async (flag) => {
				const certificate = await issue(await ed25519PublicKey(), {
					basicConstraints: { ca: true },
					keyUsage: ['keyCertSign', flag],
				});
				const parsed = parseCertificateDerOrThrow(certificate.der);
				expect(parsed.basicConstraints).toEqual({ ca: true });
				expect(parsed.keyUsage?.flags).toHaveLength(2);
				expect(parsed.keyUsage?.flags).toContain('keyCertSign');
				expect(parsed.keyUsage?.flags).toContain(flag);
			},
		);

		it.each([['nonRepudiation'], ['digitalSignature'], ['cRLSign']] as const)(
			'does not issue an Ed25519 certification authority certificate whose keyUsage is only %s',
			async (flag) => {
				await expectRejectedErrorCode(
					issue(await ed25519PublicKey(), {
						basicConstraints: { ca: true },
						keyUsage: [flag],
					}),
					'edwards_key_usage_requires_key_cert_sign',
				);
			},
		);

		it.each([['keyEncipherment'], ['dataEncipherment'], ['keyAgreement']] as const)(
			'does not issue an Ed25519 certification authority certificate whose keyUsage is only %s',
			async (flag) => {
				await expectRejectedErrorCode(
					issue(await ed25519PublicKey(), {
						basicConstraints: { ca: true },
						keyUsage: [flag],
					}),
					'edwards_key_usage_requires_key_cert_sign',
				);
			},
		);

		// The authority paragraph carries the same MUST NOT list as the end-entity one,
		// so the five bits stay forbidden beside the keyCertSign it requires.
		it.each(EDWARDS_FORBIDDEN_BITS)(
			'does not issue an Ed25519 certification authority certificate whose keyUsage adds %s to keyCertSign',
			async (flag) => {
				await expectRejectedErrorCode(
					issue(await ed25519PublicKey(), {
						basicConstraints: { ca: true },
						keyUsage: ['keyCertSign', flag],
					}),
					'edwards_key_usage_forbids_agreement_bit',
				);
			},
		);

		// "zero or more of the following" admits the whole authority set at once, where
		// the Montgomery clause above admits one cipher bit of its two.
		it('issues an Ed25519 certification authority certificate carrying all four bits', async () => {
			const flags = ['digitalSignature', 'nonRepudiation', 'keyCertSign', 'cRLSign'] as const;
			const certificate = await issue(await ed25519PublicKey(), {
				basicConstraints: { ca: true },
				keyUsage: flags,
			});
			expect(parseCertificateDerOrThrow(certificate.der).keyUsage?.flags).toEqual([...flags]);
		});

		// Both EdDSA clauses name id-Ed448 alongside id-Ed25519.
		it('widens the Ed448 rule from the end-entity set to the authority set', () => {
			expectBuildErrorCode(
				() => buildCertificateExtensions(ED448_SPKI, undefined, { keyUsage: ['keyCertSign'] }),
				'edwards_key_usage_requires_signing_bit',
			);
			expect(
				keyUsageValueOf(
					buildCertificateExtensions(ED448_SPKI, undefined, {
						basicConstraints: { ca: true },
						keyUsage: ['keyCertSign'],
					}),
				),
			).toEqual(encodeKeyUsage(['keyCertSign']));
		});

		// "If the keyUsage extension is present in a CRL issuer certificate that
		// indicates id-Ed25519 or id-Ed448 in SubjectPublicKeyInfo, then the keyUsage
		// extension MUST contain: cRLSign; and zero or more of the following:
		// nonRepudiation; digitalSignature ... and if the CRL issuer is also a
		// certification authority, then the keyUsage extension MUST also contain:
		// keyCertSign." The Section 7 private key computes the Section 4 public key, so
		// the subject key of the certificate is the one signing the CRL under it.
		it.each([
			[['cRLSign'], false],
			[['digitalSignature', 'cRLSign'], false],
			[['keyCertSign', 'cRLSign'], true],
		] as const)(
			'issues an Ed25519 CRL issuer certificate whose keyUsage is %p and verifies a CRL under it',
			async (flags, ca) => {
				const certificate = await issue(await ed25519PublicKey(), {
					basicConstraints: { ca },
					keyUsage: flags,
				});
				const parsed = parseCertificateDerOrThrow(certificate.der);
				expect(parsed.basicConstraints).toEqual({ ca });
				expect(parsed.keyUsage?.flags).toEqual([...flags]);

				const { privateKey, publicKey } = await issuerKeyPair();
				const crl = await createCertificateRevocationList({
					issuer: { commonName: 'IETF Test Demo' },
					signerPrivateKey: privateKey,
					issuerPublicKey: publicKey,
					crlNumber: 1,
					revokedCertificates: [],
				});
				expect(
					await verifyCertificateRevocationListSignature(crl.der, certificate.pem),
				).toMatchObject({ ok: true });
			},
		);

		// Every clause is conditioned on the extension being "present", so a
		// certificate carrying no keyUsage is outside all three. An empty keyUsage
		// reaches no extension either, so it is the same case.
		it.each([[{}], [{ keyUsage: [] }]] as const)(
			'issues an X25519 certificate that carries no keyUsage at all from %p',
			async (extensions) => {
				const certificate = await issue(await x25519PublicKey(), extensions);
				const parsed = parseCertificateDerOrThrow(certificate.der);
				expect(parsed.publicKeyAlgorithmOid).toBe(ID_X25519);
				expect(parsed.keyUsage).toBeUndefined();
			},
		);

		// The clause reads the keyUsage extension of the certificate, so the bits
		// bind wherever the builder was given them.
		it('reads the keyUsage a customExtensions payload carries', async () => {
			await expectRejectedErrorCode(
				issue(await x25519PublicKey(), {
					customExtensions: [{ oid: OIDS.keyUsage, value: encodeKeyUsage(['digitalSignature']) }],
				}),
				'montgomery_key_usage_requires_key_agreement',
			);
		});
	});

	describe('6. EdDSA Signatures', () => {
		/** The group order L that RFC 8032 5.1 gives for Ed25519. */
		const GROUP_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;

		/** The child at `index` of a SEQUENCE, as its own DER element. */

		/** An octet string read as the little-endian integer RFC 8032 5.1.2 encodes. */

		/** `value` as `length` octets in little-endian order. */
		function littleEndianOctets(value: bigint, length: number): Uint8Array {
			const bytes = new Uint8Array(length);
			for (let index = 0; index < length; index += 1) {
				bytes[index] = Number((value >> BigInt(8 * index)) & 0xffn);
			}
			return bytes;
		}

		/** The same Certificate, with its signatureValue field replaced. */

		/** A path over `certificateDer` anchored on the Section 10.1 Ed25519 key. */
		function verifyWithSection101Key(
			certificateDer: Uint8Array,
		): Promise<BuildCandidatePathResult> {
			return buildCandidatePath({
				leaf: certificateDer,
				roots: [],
				trustAnchors: [
					{
						subject: parseCertificatePemOrThrow(blockAt(717)).issuer,
						subjectPublicKeyInfoDer: pemDecodeOrThrow('PUBLIC KEY', blockAt(597)),
						publicKeyAlgorithmOid: OIDS.ed25519,
					},
				],
			});
		}

		/** Whether WebCrypto reads `signature` as an Ed25519 signature over `signedData`, unchanged. */
		function verifiesUnwrapped(
			publicKey: CryptoKey,
			signature: Uint8Array,
			signedData: Uint8Array,
		): Promise<boolean> {
			return globalThis.crypto.subtle.verify(
				{ name: 'Ed25519' },
				publicKey,
				toArrayBuffer(signature),
				toArrayBuffer(signedData),
			);
		}

		/** The children of a constructed element, whatever its tag, as their own DER elements. */

		/**
		 * The signedAttrs of a SignerInfo under the tag its signature covers.
		 *
		 * RFC 5652 Section 5.4 signs the DER SET OF encoding, not the IMPLICIT [0] the
		 * field is carried under.
		 */
		function signedAttrsAsSetOf(signedAttrsDer: Uint8Array): Uint8Array {
			return Uint8Array.from([0x31, ...signedAttrsDer.slice(1)]);
		}

		/** The same ContentInfo, with the SignerInfo signature AlgorithmIdentifier replaced. */
		function withSignerInfoSignatureAlgorithm(
			der: Uint8Array,
			algorithmIdentifier: Uint8Array,
		): Uint8Array {
			const [contentType, content] = constructedChildren(der);
			const signedDataDer = content === undefined ? undefined : constructedChildren(content)[0];
			if (contentType === undefined || signedDataDer === undefined) {
				throw new Error('ContentInfo carries no SignedData');
			}
			const fields = constructedChildren(signedDataDer);
			const signerInfosIndex = fields.length - 1;
			const signerInfos = fields[signerInfosIndex];
			const signerInfo =
				signerInfos === undefined ? undefined : constructedChildren(signerInfos)[0];
			if (signerInfo === undefined) {
				throw new Error('SignedData carries no SignerInfo');
			}
			const absent = hex(sequence([objectIdentifier(OIDS.ed25519)]));
			const rebuiltSignerInfo = sequence(
				constructedChildren(signerInfo).map((field) =>
					hex(field) === absent ? algorithmIdentifier : field,
				),
			);
			const rebuiltSignedData = sequence(
				fields.map((field, index) =>
					index === signerInfosIndex ? setOf([rebuiltSignerInfo]) : field,
				),
			);
			return sequence([contentType, explicitContext(0, rebuiltSignedData)]);
		}

		/** One Ed25519 issuer key, and every structure this library signs with it. */
		async function signEveryStructure(label: string) {
			const issuer = await createSelfSignedCertificate({
				subject: { commonName: `${label}.example` },
				algorithm: ED25519,
				extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
			});
			const subject = await createSelfSignedCertificate({
				subject: { commonName: `${label}-subject.example` },
				algorithm: ED25519,
			});
			const crl = await createCertificateRevocationList({
				issuer: { commonName: `${label}.example` },
				signerPrivateKey: issuer.keyPair.privateKey,
				issuerPublicKey: issuer.keyPair.publicKey,
				crlNumber: 1,
				revokedCertificates: [],
			});
			const requestKeyPair = await generateKeyPair(ED25519);
			const request = await createCertificateSigningRequest({
				subject: { commonName: `${label}-request.example` },
				publicKey: requestKeyPair.publicKey,
				signerPrivateKey: requestKeyPair.privateKey,
			});
			const response = await createOcspResponse({
				signerPrivateKey: issuer.keyPair.privateKey,
				signerCertificate: issuer.certificate.pem,
				responses: [
					{
						certificate: subject.certificate.pem,
						issuerCertificate: issuer.certificate.pem,
						certStatus: 'good',
					},
				],
			});
			const signedData = await createPkcs7SignedData({
				content: Uint8Array.from([0x38, 0x34, 0x31, 0x30]),
				signers: [{ certificate: issuer.certificate.pem, privateKey: issuer.keyPair.privateKey }],
			});
			if (!signedData.ok) {
				throw new Error(`createPkcs7SignedData failed: ${signedData.code}`);
			}
			const parsedSignedData = parsePkcs7SignedDataDer(signedData.value.der);
			if (!parsedSignedData.ok) {
				throw new Error(`parsePkcs7SignedDataDer failed: ${parsedSignedData.code}`);
			}
			const signerInfo = parsedSignedData.value.signerInfos[0];
			if (signerInfo === undefined || !signerInfo.hasSignedAttrs) {
				throw new Error('SignedData carries no signed attributes');
			}
			const parsedResponse = parseOcspResponseDerOrThrow(response.der);
			const responseSignature = parsedResponse.signatureValue;
			const responseDataDer = parsedResponse.responseDataDer;
			if (responseSignature === undefined || responseDataDer === undefined) {
				throw new Error('OCSP response carries no signature');
			}
			return {
				issuerKeyPair: issuer.keyPair,
				requestKeyPair,
				signedDataDer: signedData.value.der,
				certificate: parseCertificatePemOrThrow(issuer.certificate.pem),
				crl: parseCertificateRevocationListDerOrThrow(crl.der),
				request: parseCertificateSigningRequestDerOrThrow(request.der),
				response: parsedResponse,
				responseSignature,
				responseDataDer,
				signerInfo,
			};
		}

		// "The top level structure for a certificate is given below": "Certificate
		// ::= SEQUENCE { tbsCertificate TBSCertificate, signatureAlgorithm
		// AlgorithmIdentifier, signatureValue BIT STRING }". Rebuilding the Section
		// 10.2 certificate from those three children reproduces it byte for byte, so
		// the SEQUENCE holds them in that order and nothing else.
		it('encodes a certificate as a tbsCertificate, an algorithm identifier, and a BIT STRING', () => {
			const der = parseCertificatePemOrThrow(blockAt(717)).der;
			const children = readSequenceChildren(der);
			expect(children.map((child) => child.tag)).toEqual([0x30, 0x30, 0x03]);
			expect(sequence(children.map((child) => sliceElement(der, child)))).toEqual(der);
		});

		// "The same algorithm identifiers are used for signatures as are used for
		// public keys." The Section 10.1 public key and the signature over the
		// Section 10.2 certificate carry one identifier, byte for byte.
		it('names the signature with the identifier the public key uses', () => {
			const spki = pemDecodeOrThrow('PUBLIC KEY', blockAt(597));
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			expect(childAt(certificate.der, 1)).toEqual(childAt(spki, 0));
		});

		it('names a signature it generates with the identifier its signer key uses', async () => {
			const { certificate, keyPair } = await createSelfSignedCertificate({
				subject: { commonName: 'eddsa-identifier.example' },
				algorithm: ED25519,
			});
			const parsed = parseCertificatePemOrThrow(certificate.pem);
			expect(parsed.signatureAlgorithmOid).toBe(OIDS.ed25519);
			expect(childAt(parsed.der, 1)).toEqual(childAt(await exportSpkiDer(keyPair.publicKey), 0));
		});

		// The public key the identifier is shared with is the one that made the
		// signature, which in the Section 10.2 shape is not the one the certificate
		// carries: the Section 7 Ed25519 key signs over the X25519 subject key of
		// Section 10.2. Both signature fields then name id-Ed25519 while the subject
		// key names id-X25519.
		it('names a signature over another key with the identifier of the key that signed', async () => {
			const signerPrivateKey = await importPkcs8PemOrThrow(blockAt(402), ED25519);
			const subjectSpki = parseCertificatePemOrThrow(blockAt(717)).subjectPublicKeyInfoDer;
			const issued = await createCertificate({
				issuer: { commonName: 'IETF Test Demo' },
				subject: { commonName: 'IETF Test Demo' },
				publicKey: await globalThis.crypto.subtle.importKey(
					'spki',
					toArrayBuffer(subjectSpki),
					{ name: 'X25519' },
					true,
					[],
				),
				signerPrivateKey,
				issuerPublicKey: await derivePublicKey(signerPrivateKey),
			});
			const parsed = parseCertificateDerOrThrow(issued.der);
			const signerIdentifier = childAt(pemDecodeOrThrow('PUBLIC KEY', blockAt(597)), 0);
			const tbsChildren = readSequenceChildren(parsed.tbsCertificateDer);
			const signatureIndex = tbsChildren[0]?.tag === 0xa0 ? 2 : 1;
			expect(parsed.publicKeyAlgorithmOid).toBe(OIDS.x25519);
			expect(childAt(parsed.der, 1)).toEqual(signerIdentifier);
			expect(childAt(parsed.tbsCertificateDer, signatureIndex)).toEqual(signerIdentifier);
			expect(childAt(parsed.der, 1)).not.toEqual(childAt(subjectSpki, 0));
		});

		// "The octet string representing the signature is encoded directly in the
		// BIT STRING without adding any additional ASN.1 wrapping. For the
		// Certificate structure, the signature value is wrapped in the
		// "signatureValue" BIT STRING field." WebCrypto verifies the BIT STRING
		// payload as it stands against the tbsCertificate, so nothing sits between
		// the 2*b-bit string and the field.
		it('carries the signature in the BIT STRING with no encoding of its own', async () => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			expect(readRootElement(childAt(certificate.der, 2)).value[0]).toBe(0);
			expect(certificate.signatureValue).toHaveLength(64);
			expect(
				await verifiesUnwrapped(
					await importSpkiPemOrThrow(blockAt(597), ED25519),
					certificate.signatureValue,
					certificate.tbsCertificateDer,
				),
			).toBe(true);
		});

		// "This value is the opaque value ENC(R) || ENC(S) described in Section 3.3
		// of [RFC8032]", which RFC 8032 5.1.6 forms from "R (32 octets) and the
		// little-endian encoding of S (32 octets; the three most significant bits of
		// the final octet are always zero)", and 5.1.7 decodes with S "in the range
		// 0 <= s < L".
		it('holds a 32-octet ENC(R) and an ENC(S) below the group order', () => {
			const signature = parseCertificatePemOrThrow(blockAt(717)).signatureValue;
			expect(signature).toHaveLength(64);
			expect(littleEndianInteger(signature.slice(32))).toBeLessThan(GROUP_ORDER);
			expect((signature[63] ?? 0xff) & 0xe0).toBe(0);
		});

		// The control for every mutation below: rebuilding the Section 10.2
		// certificate around its own signature value leaves a certificate that
		// verifies under the Section 10.1 key, so a later rejection comes from what
		// was changed rather than from the rebuilding.
		it('verifies the Section 10.2 certificate rebuilt around its own signature', async () => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			expect(
				await verifyWithSection101Key(
					withSignatureValue(certificate.der, bitString(certificate.signatureValue)),
				),
			).toMatchObject({ ok: true });
		});

		// RFC 8032 3.3 makes the PureEdDSA signature "the 2*b-bit string ENC(R) ||
		// ENC(S)", which 5.1.7 splits "into two 32-octet halves". A string of another
		// length is not that value, whichever end the octets are missing from or
		// added to.
		it.each([
			['a truncated', (signature: Uint8Array) => signature.slice(0, 63)],
			['a zero-extended', (signature: Uint8Array) => Uint8Array.from([...signature, 0])],
			['a zero-prefixed', (signature: Uint8Array) => Uint8Array.from([0, ...signature])],
		])('does not verify %s Section 10.2 signature', async (_label, resize) => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			const resized = resize(certificate.signatureValue);
			expect(resized).not.toHaveLength(64);
			expect(
				await verifyWithSection101Key(withSignatureValue(certificate.der, bitString(resized))),
			).toMatchObject({ ok: false, code: 'signature_invalid' });
		});

		// Both halves are read, so flipping the low bit of either one alone leaves a
		// signature that no longer verifies.
		it.each([
			['ENC(R)', 0],
			['ENC(S)', 32],
		])('does not verify the Section 10.2 signature with %s altered', async (_label, offset) => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			const altered = new Uint8Array(certificate.signatureValue);
			altered[offset] = (altered[offset] ?? 0) ^ 0x01;
			expect(
				await verifyWithSection101Key(withSignatureValue(certificate.der, bitString(altered))),
			).toMatchObject({ ok: false, code: 'signature_invalid' });
		});

		// RFC 8032 5.1.7 decodes "the second half as an integer S, in the range
		// 0 <= s < L", and "if any of the decodings fail (including S being out of
		// range), the signature is invalid". S + L is the same residue modulo L, so
		// a verdict of verified would come from reducing S rather than rejecting it.
		it('does not verify the Section 10.2 signature with S raised by the group order', async () => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			const raised = new Uint8Array([
				...certificate.signatureValue.slice(0, 32),
				...littleEndianOctets(
					littleEndianInteger(certificate.signatureValue.slice(32)) + GROUP_ORDER,
					32,
				),
			]);
			expect(littleEndianInteger(raised.slice(32))).toBeGreaterThan(GROUP_ORDER);
			expect(
				await verifyWithSection101Key(withSignatureValue(certificate.der, bitString(raised))),
			).toMatchObject({ ok: false, code: 'signature_invalid' });
		});

		// "without adding any additional ASN.1 wrapping". Each wrapping carries the
		// same 64 octets, so a verdict of verified would come from unwrapping them.
		it.each([
			['an OCTET STRING', (signature: Uint8Array) => octetString(signature)],
			[
				'a SEQUENCE of two INTEGERs',
				(signature: Uint8Array) =>
					sequence([integer(signature.slice(0, 32)), integer(signature.slice(32))]),
			],
		])('does not verify a signature wrapped in %s', async (_label, wrap) => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			expect(
				await verifyWithSection101Key(
					withSignatureValue(certificate.der, bitString(wrap(certificate.signatureValue))),
				),
			).toMatchObject({ ok: false, code: 'signature_invalid' });
		});

		// The signature is an octet string encoded directly, so a BIT STRING holding
		// a bit count that is not a whole number of octets does not hold one.
		it('does not parse a certificate whose signatureValue declares an unused bit', () => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			const truncated = new Uint8Array(certificate.signatureValue);
			truncated[63] = (truncated[63] ?? 0) & 0xfe;
			expect(
				parseCertificateDer(withSignatureValue(certificate.der, bitString(truncated, 1))),
			).toMatchObject({ ok: false, code: 'malformed' });
		});

		// "Signatures can be placed in a number of different ASN.1 structures", the
		// Certificate being "illustrative" of the rest. Every structure this library
		// signs with Ed25519 is checked against WebCrypto directly, over the payload
		// that structure signs, so none of them wraps the value.
		it('places the same unwrapped 64-octet value in every structure it signs', async () => {
			const material = await signEveryStructure('eddsa-structures');
			const signed = [
				[
					material.issuerKeyPair.publicKey,
					material.certificate.signatureValue,
					material.certificate.tbsCertificateDer,
				],
				[
					material.issuerKeyPair.publicKey,
					material.crl.signatureValue,
					material.crl.tbsCertListDer,
				],
				[
					material.requestKeyPair.publicKey,
					material.request.signatureValue,
					material.request.certificationRequestInfoDer,
				],
				[material.issuerKeyPair.publicKey, material.responseSignature, material.responseDataDer],
				[
					material.issuerKeyPair.publicKey,
					material.signerInfo.signature,
					signedAttrsAsSetOf(material.signerInfo.signedAttrsDer),
				],
			] as const;

			for (const [publicKey, signature, signedData] of signed) {
				expect(signature).toHaveLength(64);
				expect(await verifiesUnwrapped(publicKey, signature, signedData)).toBe(true);
			}
		});

		// "When used to identify signature algorithms, the parameters MUST be absent."
		// The identifier is written into every one of those structures, so the rule
		// binds each of them and not the certificate alone.
		it('omits the parameters from the signature identifier of every structure it signs', async () => {
			const material = await signEveryStructure('eddsa-structure-params');
			expect([
				material.certificate.signatureAlgorithmOid,
				material.crl.signatureAlgorithmOid,
				material.request.signatureAlgorithmOid,
				material.response.signatureAlgorithmOid,
				material.signerInfo.signatureAlgorithmOid,
			]).toEqual(Array.from({ length: 5 }, () => OIDS.ed25519));
			expect([
				material.certificate.signatureAlgorithmParametersDer,
				material.crl.signatureAlgorithmParametersDer,
				material.request.signatureAlgorithmParametersDer,
				material.response.signatureAlgorithmParametersDer,
				material.signerInfo.signatureAlgorithmParametersDer,
			]).toEqual(Array.from({ length: 5 }, () => undefined));
		});

		// The same rule read back: CMS carries the identifier outside the signedAttrs
		// the signature covers, so the signature stays valid over an unchanged payload
		// and only the parameters can decide the verdict.
		it('does not verify signed data whose Ed25519 identifier carries a NULL', async () => {
			const material = await signEveryStructure('eddsa-signed-data-params');
			expect(
				await verifyPkcs7SignedData(
					withSignerInfoSignatureAlgorithm(
						material.signedDataDer,
						sequence([objectIdentifier(OIDS.ed25519)]),
					),
				),
			).toMatchObject({ ok: true });

			const mutated = withSignerInfoSignatureAlgorithm(
				material.signedDataDer,
				sequence([objectIdentifier(OIDS.ed25519), nullValue()]),
			);
			const reparsed = parsePkcs7SignedDataDer(mutated);
			if (!reparsed.ok) {
				throw new Error(`parsePkcs7SignedDataDer failed: ${reparsed.code}`);
			}
			expect(reparsed.value.signerInfos[0]?.signatureAlgorithmParametersDer).toEqual(
				Uint8Array.from([0x05, 0x00]),
			);
			expect(await verifyPkcs7SignedData(mutated)).toMatchObject({ ok: false, code: 'malformed' });
		});

		// "When used to identify signature algorithms, the parameters MUST be
		// absent." PKCS#10 leaves the identifier outside the signed
		// CertificationRequestInfo, so the signature stays valid over an unchanged
		// payload and only the parameters can decide the verdict.
		it('does not verify a certificate request whose Ed25519 identifier carries a NULL', async () => {
			const keyPair = await generateKeyPair(ED25519);
			const request = await createCertificateSigningRequest({
				subject: { commonName: 'eddsa-request-params.example' },
				publicKey: keyPair.publicKey,
				signerPrivateKey: keyPair.privateKey,
			});
			expect(
				parseCertificateSigningRequestDerOrThrow(request.der).signatureAlgorithmParametersDer,
			).toBeUndefined();
			expect(await verifyCertificateSigningRequest(request.der)).toMatchObject({ ok: true });

			const mutated = sequence(
				readSequenceChildren(request.der).map((child, index) =>
					index === 1
						? sequence([objectIdentifier(OIDS.ed25519), nullValue()])
						: sliceElement(request.der, child),
				),
			);
			expect(
				parseCertificateSigningRequestDerOrThrow(mutated).signatureAlgorithmParametersDer,
			).toEqual(Uint8Array.from([0x05, 0x00]));
			expect(await verifyCertificateSigningRequest(mutated)).toMatchObject({
				ok: false,
				code: 'unsupported_signature_algorithm_parameters',
			});
		});
	});

	describe('7. Private Key Format', () => {
		/** The example carrying the private key alone, at rfc8410.txt:402. */
		const FIRST_EXAMPLE = blockAt(402);

		/**
		 * The example carrying an attribute and the public key, at rfc8410.txt:410.
		 *
		 * rfc8410.txt:414 closes it with six hyphen-minuses where RFC 7468 2 allows
		 * five, so the boundary is repaired before the block is decoded.
		 */
		const SECOND_EXAMPLE = blockAt(410).replace(
			'-----END PRIVATE KEY------',
			'-----END PRIVATE KEY-----',
		);

		/** The child at `index` of a SEQUENCE. */

		/** The `privateKeyAlgorithm` AlgorithmIdentifier as its own DER element. */
		function algorithmDer(der: Uint8Array): Uint8Array {
			return sliceElement(der, fieldAt(der, 1));
		}

		/** The children of the `privateKeyAlgorithm` AlgorithmIdentifier. */
		function algorithmFields(der: Uint8Array): DerElement[] {
			return readSequenceChildren(algorithmDer(der));
		}

		/** The bare id-Ed25519 AlgorithmIdentifier of the example. */
		const ED25519_ALGORITHM = sequence([objectIdentifier(OIDS.ed25519)]);

		/** A OneAsymmetricKey holding `privateKey` bytes under `algorithm`, version v1. */
		function oneAsymmetricKey(
			privateKey: Uint8Array,
			algorithm: Uint8Array = ED25519_ALGORITHM,
		): Uint8Array {
			return sequence([integer(Uint8Array.of(0)), algorithm, octetString(privateKey)]);
		}

		/** The 32 opaque octets the example carries inside its CurvePrivateKey. */
		function exampleSeed(): Uint8Array {
			const der = pemDecodeOrThrow('PRIVATE KEY', FIRST_EXAMPLE);
			return readRootElement(fieldAt(der, 2).value).value;
		}

		// "OneAsymmetricKey ::= SEQUENCE { version Version,
		// privateKeyAlgorithm PrivateKeyAlgorithmIdentifier, privateKey PrivateKey,
		// attributes [0] IMPLICIT Attributes OPTIONAL, ... }", "PrivateKey ::= OCTET
		// STRING", and "when encoding a OneAsymmetricKey object, the private key is
		// wrapped in a CurvePrivateKey object and wrapped by the OCTET STRING of the
		// "privateKey" field", with "CurvePrivateKey ::= OCTET STRING".
		it('wraps the example key in a CurvePrivateKey inside the privateKey OCTET STRING', () => {
			const der = pemDecodeOrThrow('PRIVATE KEY', FIRST_EXAMPLE);
			expect(readSequenceChildren(der).map((child) => child.tag)).toEqual([0x02, 0x30, 0x04]);
			expect(fieldAt(der, 0).value).toEqual(Uint8Array.of(0));
			expect(algorithmFields(der).map((child) => child.tag)).toEqual([0x06]);
			const curvePrivateKey = readRootElement(fieldAt(der, 2).value);
			expect(curvePrivateKey.tag).toBe(0x04);
			expect(curvePrivateKey.value).toHaveLength(32);
		});

		// "'Asymmetric Key Packages' [RFC5958] describes how to encode a private key
		// in a structure that both identifies what algorithm the private key is for
		// and allows for the public key and additional attributes about the key to be
		// included as well." The structure carries id-Ed25519, so an import that is
		// told nothing reaches the same key as one told to expect Ed25519, and one
		// told to expect another algorithm is refused.
		it('reads the algorithm the example names out of the structure', async () => {
			const declared = await importPkcs8PemOrThrow(FIRST_EXAMPLE, ED25519);
			const inferred = await importPkcs8PemOrThrow(FIRST_EXAMPLE);
			expect(declared.type).toBe('private');
			expect(inferred.algorithm.name).toBe('Ed25519');
			expect(await exportSpkiDer(await derivePublicKey(inferred))).toEqual(
				await exportSpkiDer(await derivePublicKey(declared)),
			);
			expect(await importPkcs8Pem(FIRST_EXAMPLE, { kind: 'ecdsa', curve: 'P-256' })).toMatchObject({
				ok: false,
				code: 'malformed',
			});
		});

		// "The 'privateKeyAlgorithm' field uses the AlgorithmIdentifier structure.
		// The structure is encoded as defined above." Above is 3, where "for all of
		// the OIDs, the parameters MUST be absent", so id-Ed25519 followed by a
		// parameter is not the identifier this section places in the field.
		it('does not import a privateKeyAlgorithm that carries parameters', async () => {
			const wrapped = octetString(exampleSeed());
			for (const parameters of [nullValue(), objectIdentifier(OIDS.ed25519)]) {
				const key = oneAsymmetricKey(
					wrapped,
					sequence([objectIdentifier(OIDS.ed25519), parameters]),
				);
				expect(await importPkcs8Der(key, ED25519)).toMatchObject({
					ok: false,
					code: 'malformed',
				});
				expect(await importPkcs8Der(key)).toMatchObject({ ok: false, code: 'malformed' });
			}
			expect(await importPkcs8Der(oneAsymmetricKey(wrapped), ED25519)).toMatchObject({ ok: true });
		});

		// "The algorithm-specific details of how a private key is encoded are left
		// for the document describing the algorithm itself." For id-Ed25519 that is
		// RFC 8032 5.1.5: "The private key is 32 octets (256 bits, corresponding to
		// b) of cryptographically secure random data."
		it('does not import a CurvePrivateKey of any length but 32 octets', async () => {
			const seed = exampleSeed();
			expect(seed).toHaveLength(32);
			const wrongLength = [seed.slice(0, 31), Uint8Array.from([...seed, 0x00]), new Uint8Array(0)];
			for (const scalar of wrongLength) {
				expect(await importPkcs8Der(oneAsymmetricKey(octetString(scalar)), ED25519)).toMatchObject({
					ok: false,
					code: 'malformed',
				});
			}
			expect(await importPkcs8Der(oneAsymmetricKey(octetString(seed)), ED25519)).toMatchObject({
				ok: true,
			});
		});

		// "attributes [0] IMPLICIT Attributes OPTIONAL", where RFC 5958 2 types
		// "Attributes ::= SET OF Attribute" over the "Attribute ::= SEQUENCE {
		// attrType OBJECT IDENTIFIER, attrValues SET OF AttributeValue }" of RFC 5652
		// 5.3. The 10.3 example prints one such attribute, and a [0] field holding
		// anything else is not this structure.
		it('does not import an attributes [0] field that is not a SET OF Attribute', async () => {
			const attributes = fieldAt(pemDecodeOrThrow('PRIVATE KEY', SECOND_EXAMPLE), 3).value;
			const attribute = sliceElement(attributes, readRootElement(attributes));
			const type = sliceElement(attribute, fieldAt(attribute, 0));
			const values = sliceElement(attribute, fieldAt(attribute, 1));
			expect(readSequenceChildren(attribute).map((field) => field.tag)).toEqual([0x06, 0x31]);

			const wrapped = octetString(exampleSeed());
			const withAttributes = (body: Uint8Array): Uint8Array =>
				sequence([
					integer(Uint8Array.of(0)),
					ED25519_ALGORITHM,
					octetString(wrapped),
					implicitConstructedContext(0, body),
				]);

			// SET OF carries no size constraint, so the field may hold one Attribute
			// or none at all.
			for (const body of [attributes, new Uint8Array(0)]) {
				expect(await importPkcs8Der(withAttributes(body), ED25519)).toMatchObject({ ok: true });
			}

			const malformed = [
				type,
				values,
				sequence([type]),
				sequence([values, type]),
				sequence([type, values, type]),
				sequence([type, sequence([values])]),
			];
			for (const body of malformed) {
				expect(await importPkcs8Der(withAttributes(body), ED25519)).toMatchObject({
					ok: false,
					code: 'malformed',
				});
			}
		});

		// The same sentence read the other way: a "privateKey" field that does not
		// hold one DER CurvePrivateKey is not this encoding. Each case keeps the
		// 32 opaque octets of the example and changes only their wrapping.
		it('does not import a privateKey field that is not a DER CurvePrivateKey', async () => {
			const der = pemDecodeOrThrow('PRIVATE KEY', FIRST_EXAMPLE);
			const seed = readRootElement(fieldAt(der, 2).value).value;
			expect(oneAsymmetricKey(octetString(seed))).toEqual(der);
			expect(await importPkcs8Der(oneAsymmetricKey(octetString(seed)), ED25519)).toMatchObject({
				ok: true,
			});

			const malformed = [
				seed,
				Uint8Array.from([0x04, 0x81, 0x20, ...seed]),
				Uint8Array.from([...octetString(seed), 0x00]),
				bitString(seed),
			];
			for (const privateKey of malformed) {
				expect(await importPkcs8Der(oneAsymmetricKey(privateKey), ED25519)).toMatchObject({
					ok: false,
					code: 'malformed',
				});
			}
		});

		// "If present, the "publicKey" field will hold the encoded key as defined in
		// [RFC7748] and [RFC8032]." RFC 5958 2 sets the version to v2 when the field
		// is present. The second example prints the private key of the first, so its
		// publicKey field is byte for byte the subjectPublicKey RFC 8032 gives for
		// that key.
		it('holds the encoded public key of the example private key', async () => {
			const first = pemDecodeOrThrow('PRIVATE KEY', FIRST_EXAMPLE);
			const second = pemDecodeOrThrow('PRIVATE KEY', SECOND_EXAMPLE);
			expect(readSequenceChildren(second).map((child) => child.tag)).toEqual([
				0x02, 0x30, 0x04, 0xa0, 0x81,
			]);
			expect(fieldAt(second, 0).value).toEqual(Uint8Array.of(1));
			expect(fieldAt(second, 2).value).toEqual(fieldAt(first, 2).value);

			const publicKey = await derivePublicKey(await importPkcs8PemOrThrow(FIRST_EXAMPLE, ED25519));
			const spki = await exportSpkiDer(publicKey);
			expect(fieldAt(second, 4).value).toEqual(fieldAt(spki, 1).value);
		});

		// "There exist some private key import functions that have not picked up the
		// new ASN.1 structure OneAsymmetricKey [...] This means a balancing act needs
		// to be done between being able to do a consistency check on the key pair and
		// widest ability to import the key." This library encodes the widest form: no
		// publicKey field, so version v1, with the private key double wrapped.
		it('exports a v1 OneAsymmetricKey carrying only the wrapped private key', async () => {
			const keyPair = await generateKeyPair(ED25519);
			const der = await exportPkcs8Der(keyPair.privateKey);
			expect(readSequenceChildren(der).map((child) => child.tag)).toEqual([0x02, 0x30, 0x04]);
			expect(fieldAt(der, 0).value).toEqual(Uint8Array.of(0));
			expect(algorithmFields(der).map((child) => child.tag)).toEqual([0x06]);
			expect(decodeDerOidOrThrow(fieldAt(algorithmDer(der), 0))).toBe(OIDS.ed25519);
			const curvePrivateKey = readRootElement(fieldAt(der, 2).value);
			expect(curvePrivateKey.tag).toBe(0x04);
			expect(curvePrivateKey.value).toHaveLength(32);

			const reimported = await importPkcs8DerOrThrow(der, ED25519);
			expect(await exportSpkiDer(await derivePublicKey(reimported))).toEqual(
				await exportSpkiDer(keyPair.publicKey),
			);
			expect(await exportPkcs8Der(await importPkcs8PemOrThrow(FIRST_EXAMPLE, ED25519))).toEqual(
				pemDecodeOrThrow('PRIVATE KEY', FIRST_EXAMPLE),
			);
		});

		it('rejects the example whose END boundary carries six hyphen-minuses', async () => {
			// rfc8410.txt:414 prints "-----END PRIVATE KEY------". RFC 7468 2 requires
			// exactly five on both ends, "no more, no less", so this printing of an
			// otherwise valid key is not a conforming textual encoding.
			expect(blockAt(410).endsWith('-----END PRIVATE KEY------')).toBe(true);
			expect(await importPkcs8Pem(blockAt(410), ED25519)).toMatchObject({
				ok: false,
				code: 'malformed',
			});
			// The same key with the boundary repaired imports, so the sixth hyphen is
			// the whole of what the failure reports.
			expect(
				await importPkcs8Pem(
					blockAt(410).replace('-----END PRIVATE KEY------', '-----END PRIVATE KEY-----'),
					ED25519,
				),
			).toMatchObject({ ok: true });
		});
	});

	describe('8. Human-Readable Algorithm Names', () => {
		/** Final arc of each 1.3.101 algorithm OID, keyed by the name this section gives it. */
		const CURVE_ARCS = {
			X25519: 0x6e,
			X448: 0x6f,
			Ed25519: 0x70,
			Ed448: 0x71,
		} as const;

		/**
		 * The Section 10.2 certificate with every 1.3.101 OID ending in `from` remapped.
		 *
		 * The subject key ends in the id-X25519 arc once; the signature identifier ends
		 * in the id-Ed25519 arc twice, in the tbsCertificate and in the outer
		 * signatureAlgorithm, and both have to move together for the two to keep
		 * matching. Every arc here is one octet, so the DER lengths do not change.
		 */
		function withCurveArc(from: number, to: number): Uint8Array {
			const der = new Uint8Array(parseCertificatePemOrThrow(blockAt(717)).der);
			const prefix = [0x06, 0x03, 0x2b, 0x65, from];
			let occurrences = 0;
			for (let index = 0; index + 5 <= der.length; index += 1) {
				if (prefix.every((byte, offset) => der[index + offset] === byte)) {
					der[index + 4] = to;
					occurrences += 1;
				}
			}
			expect(occurrences).toBeGreaterThan(0);
			return der;
		}

		// "Use the string "ECDH" when referring to a public key of type "X25519" or
		// "X448" when the curve is not known or relevant." "When the curve is known,
		// use the more specific string of "X25519" or "X448"." The Section 10.2
		// subject key carries id-X25519, so its curve is known from the certificate
		// alone and the specific name applies.
		it('names the Section 10.2 subject public key "X25519"', () => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			expect(certificate.publicKeyAlgorithmOid).toBe(OIDS.x25519);
			expect(certificate.publicKeyAlgorithmName).toBe('X25519');
		});

		// "Use the string "EdDSA" when referring to a signing public key or signature
		// when the curve is not known or relevant." "When the curve is known, use a
		// more specific string. For the id-Ed25519 value use the string "Ed25519"."
		it('names the Section 10.2 signature "Ed25519"', () => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			expect(certificate.signatureAlgorithmOid).toBe(OIDS.ed25519);
			expect(certificate.signatureAlgorithmName).toBe('Ed25519');
		});

		// The four OIDs of Section 3 each fix a curve, so each subject key gets the
		// specific name: "X25519" or "X448" for a key agreement key, "Ed25519" for
		// id-Ed25519, and "Ed448" for id-Ed448.
		it.each(Object.entries(CURVE_ARCS))(
			'names an id-%s subject public key after its own curve',
			(name, arc) => {
				const certificate = parseCertificateDerOrThrow(withCurveArc(CURVE_ARCS.X25519, arc));
				expect(certificate.publicKeyAlgorithmOid).toBe(`1.3.101.${arc}`);
				expect(certificate.publicKeyAlgorithmName).toBe(name);
			},
		);

		// "For the id-Ed25519 value use the string "Ed25519". For id-Ed448, use
		// "Ed448"." Neither signature gets the curve-free "EdDSA".
		it.each([
			['Ed25519', CURVE_ARCS.Ed25519],
			['Ed448', CURVE_ARCS.Ed448],
		])('names an id-%s signature after its own curve', (name, arc) => {
			const certificate = parseCertificateDerOrThrow(withCurveArc(CURVE_ARCS.Ed25519, arc));
			expect(certificate.signatureAlgorithmOid).toBe(`1.3.101.${arc}`);
			expect(certificate.signatureAlgorithmName).toBe(name);
		});

		/** An Ed25519 certificate request whose SubjectPublicKeyInfo names `oid` instead. */
		async function requestWithPublicKeyOid(oid: string): Promise<Uint8Array> {
			const keyPair = await generateKeyPair(ED25519);
			const request = await createCertificateSigningRequest({
				subject: { commonName: 'names-request.example' },
				publicKey: keyPair.publicKey,
				signerPrivateKey: keyPair.privateKey,
			});
			const [info, signatureAlgorithm, signature] = readSequenceChildren(request.der);
			if (info === undefined || signatureAlgorithm === undefined || signature === undefined) {
				throw new Error('Malformed CertificationRequest');
			}
			const infoDer = sliceElement(request.der, info);
			const infoChildren = readSequenceChildren(infoDer);
			const subjectPublicKeyInfo = infoChildren[2];
			if (subjectPublicKeyInfo === undefined) {
				throw new Error('Missing SubjectPublicKeyInfo');
			}
			const spkiDer = sliceElement(infoDer, subjectPublicKeyInfo);
			const subjectPublicKey = readSequenceChildren(spkiDer)[1];
			if (subjectPublicKey === undefined) {
				throw new Error('Missing subjectPublicKey');
			}
			return sequence([
				sequence(
					infoChildren.map((child, at) =>
						at === 2
							? sequence([
									sequence([objectIdentifier(oid)]),
									sliceElement(spkiDer, subjectPublicKey),
								])
							: sliceElement(infoDer, child),
					),
				),
				sliceElement(request.der, signatureAlgorithm),
				sliceElement(request.der, signature),
			]);
		}

		// A certificate request names its subject public key through its own parse
		// path, so "When the curve is known, use the more specific string of "X25519"
		// or "X448"" and "For the id-Ed25519 value use the string "Ed25519". For
		// id-Ed448, use "Ed448"" have to hold there as well as on a certificate.
		it.each(Object.entries(CURVE_ARCS))(
			'names an id-%s certificate request subject public key after its own curve',
			async (name, arc) => {
				const request = parseCertificateSigningRequestDerOrThrow(
					await requestWithPublicKeyOid(`1.3.101.${arc}`),
				);
				expect(request.publicKeyAlgorithmOid).toBe(`1.3.101.${arc}`);
				expect(request.publicKeyAlgorithmName).toBe(name);
			},
		);

		// "For the id-Ed25519 value use the string "Ed25519". For id-Ed448, use
		// "Ed448"." A certificate request signature is named by the same rule.
		it.each([
			['Ed25519', OIDS.ed25519],
			['Ed448', OIDS.ed448],
		])('names an id-%s certificate request signature after its own curve', async (name, oid) => {
			const keyPair = await generateKeyPair(ED25519);
			const request = await createCertificateSigningRequest({
				subject: { commonName: 'names-request.example' },
				publicKey: keyPair.publicKey,
				signerPrivateKey: keyPair.privateKey,
			});
			const parsed = parseCertificateSigningRequestDerOrThrow(
				replaceCsrSignatureAlgorithm(request.der, sequence([objectIdentifier(oid)])),
			);
			expect(parsed.signatureAlgorithmOid).toBe(oid);
			expect(parsed.signatureAlgorithmName).toBe(name);
		});

		// "Use the string "ECDH" when referring to a public key of type "X25519" or
		// "X448" when the curve is not known or relevant." "Use the string "EdDSA"
		// when referring to a signing public key or signature when the curve is not
		// known or relevant." Every name this library reports comes from an
		// AlgorithmIdentifier OID, and an OID always fixes the curve, so no OID in the
		// catalog may claim either curve-free name.
		it('never names a catalog OID "ECDH" or "EdDSA"', () => {
			const generic = Object.values(OIDS).flatMap((oid) =>
				[describePublicKeyAlgorithm(oid, undefined), describeSignatureAlgorithm(oid, undefined)]
					.filter((name) => name === 'ECDH' || name === 'EdDSA')
					.map((name) => `${oid} -> ${name}`),
			);
			expect(generic).toEqual([]);
		});

		// "For the purpose of consistent cross-implementation naming, this section
		// establishes human-readable names for the algorithms specified in this
		// document. Implementations SHOULD use these names when referring to the
		// algorithms." Every structure this library names an algorithm in reports the
		// same "Ed25519", for the signature and for the signing public key alike.
		it('names an Ed25519 signature "Ed25519" in every structure it parses', async () => {
			const issuer = await createSelfSignedCertificate({
				subject: { commonName: 'names.example' },
				algorithm: ED25519,
				extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
			});
			const subject = await createSelfSignedCertificate({
				subject: { commonName: 'names-subject.example' },
				algorithm: ED25519,
			});
			const crl = await createCertificateRevocationList({
				issuer: { commonName: 'names.example' },
				signerPrivateKey: issuer.keyPair.privateKey,
				issuerPublicKey: issuer.keyPair.publicKey,
				crlNumber: 1,
				revokedCertificates: [],
			});
			const requestKeyPair = await generateKeyPair(ED25519);
			const request = await createCertificateSigningRequest({
				subject: { commonName: 'names-request.example' },
				publicKey: requestKeyPair.publicKey,
				signerPrivateKey: requestKeyPair.privateKey,
			});
			const response = await createOcspResponse({
				signerPrivateKey: issuer.keyPair.privateKey,
				signerCertificate: issuer.certificate.pem,
				responses: [
					{
						certificate: subject.certificate.pem,
						issuerCertificate: issuer.certificate.pem,
						certStatus: 'good',
					},
				],
			});
			const signedData = await createPkcs7SignedData({
				content: Uint8Array.from([0x38, 0x34, 0x31, 0x30]),
				signers: [{ certificate: issuer.certificate.pem, privateKey: issuer.keyPair.privateKey }],
			});
			if (!signedData.ok) {
				throw new Error(`createPkcs7SignedData failed: ${signedData.code}`);
			}
			const parsedSignedData = parsePkcs7SignedDataDer(signedData.value.der);
			if (!parsedSignedData.ok) {
				throw new Error(`parsePkcs7SignedDataDer failed: ${parsedSignedData.code}`);
			}

			const parsedCertificate = parseCertificatePemOrThrow(issuer.certificate.pem);
			const parsedRequest = parseCertificateSigningRequestDerOrThrow(request.der);
			expect([
				parsedCertificate.signatureAlgorithmName,
				parsedCertificate.publicKeyAlgorithmName,
				parseCertificateRevocationListDerOrThrow(crl.der).signatureAlgorithmName,
				parsedRequest.signatureAlgorithmName,
				parsedRequest.publicKeyAlgorithmName,
				parseOcspResponseDerOrThrow(response.der).signatureAlgorithmName,
				parsedSignedData.value.signerInfos[0]?.signatureAlgorithmName,
			]).toEqual(Array.from({ length: 7 }, () => 'Ed25519'));
		});

		// The names this section gives are the names the library hands to WebCrypto
		// for the same algorithm, so a key it generates reports "Ed25519" too.
		it('names a generated key pair "Ed25519"', async () => {
			const keyPair = await generateKeyPair(ED25519);
			expect([keyPair.privateKey.algorithm.name, keyPair.publicKey.algorithm.name]).toEqual([
				'Ed25519',
				'Ed25519',
			]);
		});
	});

	describe('9. ASN.1 Module', () => {
		/** `id-edwards-curve-algs OBJECT IDENTIFIER ::= { 1 3 101 }`. */
		const ID_EDWARDS_CURVE_ALGS = '1.3.101';

		/** The content octets of the arc every OID in the module hangs off. */
		const ARC_CONTENT = objectIdentifier(ID_EDWARDS_CURVE_ALGS).slice(2);

		/** An AlgorithmIdentifier naming `oid` and carrying no parameters. */
		const identifier = (oid: string): Uint8Array => sequence([objectIdentifier(oid)]);

		/** The same SEQUENCE, with the child at `index` replaced. */
		function withChild(der: Uint8Array, index: number, replacement: Uint8Array): Uint8Array {
			return sequence(
				readSequenceChildren(der).map((child, at) =>
					at === index ? replacement : sliceElement(der, child),
				),
			);
		}

		/** The same SEQUENCE, with a DER NULL added to the AlgorithmIdentifier at `index`. */
		function withNullParameters(der: Uint8Array, index: number, oid: string): Uint8Array {
			return withChild(der, index, sequence([objectIdentifier(oid), nullValue()]));
		}

		/** The same SEQUENCE, with its one id-Ed25519 AlgorithmIdentifier child replaced. */
		function withSignatureAlgorithm(der: Uint8Array, replacement: Uint8Array): Uint8Array {
			const ed25519 = hex(identifier(OIDS.ed25519));
			const children = readSequenceChildren(der).map((child) => sliceElement(der, child));
			if (children.filter((child) => hex(child) === ed25519).length !== 1) {
				throw new Error('SEQUENCE carries no single id-Ed25519 AlgorithmIdentifier');
			}
			return sequence(children.map((child) => (hex(child) === ed25519 ? replacement : child)));
		}

		/** The children of a constructed element, whatever its tag. */

		/** The same ContentInfo, with the SignerInfo signature AlgorithmIdentifier replaced. */
		function withSignerInfoAlgorithm(der: Uint8Array, algorithmIdentifier: Uint8Array): Uint8Array {
			const [contentType, content] = constructedChildren(der);
			const signedDataDer = content === undefined ? undefined : constructedChildren(content)[0];
			if (contentType === undefined || signedDataDer === undefined) {
				throw new Error('ContentInfo carries no SignedData');
			}
			const fields = constructedChildren(signedDataDer);
			const signerInfosIndex = fields.length - 1;
			const signerInfos = fields[signerInfosIndex];
			const signerInfo =
				signerInfos === undefined ? undefined : constructedChildren(signerInfos)[0];
			if (signerInfo === undefined) {
				throw new Error('SignedData carries no SignerInfo');
			}
			const rebuiltSignerInfo = withSignatureAlgorithm(signerInfo, algorithmIdentifier);
			return sequence([
				contentType,
				explicitContext(
					0,
					sequence(
						fields.map((field, index) =>
							index === signerInfosIndex ? setOf([rebuiltSignerInfo]) : field,
						),
					),
				),
			]);
		}

		/** A path over `certificateDer`, anchored on the self-issued certificate's own subject key. */
		function verifySelfIssued(certificateDer: Uint8Array): Promise<BuildCandidatePathResult> {
			const certificate = parseCertificateDerOrThrow(certificateDer);
			return buildCandidatePath({
				leaf: certificateDer,
				roots: [],
				trustAnchors: [
					{
						subject: certificate.issuer,
						subjectPublicKeyInfoDer: certificate.subjectPublicKeyInfoDer,
						publicKeyAlgorithmOid: certificate.publicKeyAlgorithmOid,
					},
				],
			});
		}

		/**
		 * One Ed25519 issuer, and each structure it signs both under id-Ed25519 and
		 * under `oid`.
		 *
		 * The certificate and the CRL name their signature algorithm inside the payload
		 * the signature covers, so each is signed again over the payload naming `oid`.
		 * CMS and OCSP leave the identifier outside the signed payload, so those two
		 * keep the signature the library produced.
		 */
		async function structuresSignedUnder(oid: string): Promise<{
			readonly certificate: { readonly control: Uint8Array; readonly relabelled: Uint8Array };
			readonly crl: { readonly control: Uint8Array; readonly relabelled: Uint8Array };
			readonly response: { readonly control: Uint8Array; readonly relabelled: Uint8Array };
			readonly signedData: { readonly control: Uint8Array; readonly relabelled: Uint8Array };
			readonly issuerCertificatePem: string;
		}> {
			const issuer = await createSelfSignedCertificate({
				subject: { commonName: 'key-agree.example' },
				algorithm: ED25519,
				extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
			});
			const subject = await createSelfSignedCertificate({
				subject: { commonName: 'key-agree-subject.example' },
				algorithm: ED25519,
			});
			const sign = async (payload: Uint8Array): Promise<Uint8Array> =>
				new Uint8Array(
					await globalThis.crypto.subtle.sign(
						{ name: 'Ed25519' },
						issuer.keyPair.privateKey,
						toArrayBuffer(payload),
					),
				);

			const tbsCertificateDer = parseCertificatePemOrThrow(
				issuer.certificate.pem,
			).tbsCertificateDer;
			const reissue = async (algorithmIdentifier: Uint8Array): Promise<Uint8Array> => {
				const tbs = withSignatureAlgorithm(tbsCertificateDer, algorithmIdentifier);
				return sequence([tbs, algorithmIdentifier, bitString(await sign(tbs))]);
			};

			const crl = await createCertificateRevocationList({
				issuer: { commonName: 'key-agree.example' },
				signerPrivateKey: issuer.keyPair.privateKey,
				issuerPublicKey: issuer.keyPair.publicKey,
				crlNumber: 1,
				revokedCertificates: [],
			});
			const tbsCertListDer = parseCertificateRevocationListDerOrThrow(crl.der).tbsCertListDer;
			const reissueCrl = async (algorithmIdentifier: Uint8Array): Promise<Uint8Array> => {
				const tbs = withSignatureAlgorithm(tbsCertListDer, algorithmIdentifier);
				return sequence([tbs, algorithmIdentifier, bitString(await sign(tbs))]);
			};

			const response = await createOcspResponse({
				signerPrivateKey: issuer.keyPair.privateKey,
				signerCertificate: issuer.certificate.pem,
				responses: [
					{
						certificate: subject.certificate.pem,
						issuerCertificate: issuer.certificate.pem,
						certStatus: 'good',
					},
				],
			});
			const withBasicResponseAlgorithm = (algorithmIdentifier: Uint8Array): Uint8Array => {
				const [status, responseBytes] = readSequenceChildren(response.der);
				if (status === undefined || responseBytes === undefined) {
					throw new Error('OCSPResponse carries no responseBytes');
				}
				const responseBytesDer = response.der.slice(responseBytes.start, responseBytes.end);
				const [responseType, basicResponse] = readSequenceChildren(responseBytesDer);
				if (responseType === undefined || basicResponse === undefined) {
					throw new Error('ResponseBytes is malformed');
				}
				const basic = responseBytesDer.slice(basicResponse.start, basicResponse.end);
				return sequence([
					sliceElement(response.der, status),
					explicitContext(
						0,
						sequence([
							sliceElement(responseBytesDer, responseType),
							octetString(withChild(basic, 1, algorithmIdentifier)),
						]),
					),
				]);
			};

			const signedData = await createPkcs7SignedData({
				content: Uint8Array.from([0x38, 0x34, 0x31, 0x30]),
				signers: [{ certificate: issuer.certificate.pem, privateKey: issuer.keyPair.privateKey }],
			});
			if (!signedData.ok) {
				throw new Error(`createPkcs7SignedData failed: ${signedData.code}`);
			}

			return {
				certificate: {
					control: await reissue(identifier(OIDS.ed25519)),
					relabelled: await reissue(identifier(oid)),
				},
				crl: {
					control: await reissueCrl(identifier(OIDS.ed25519)),
					relabelled: await reissueCrl(identifier(oid)),
				},
				response: {
					control: withBasicResponseAlgorithm(identifier(OIDS.ed25519)),
					relabelled: withBasicResponseAlgorithm(identifier(oid)),
				},
				signedData: {
					control: withSignerInfoAlgorithm(signedData.value.der, identifier(OIDS.ed25519)),
					relabelled: withSignerInfoAlgorithm(signedData.value.der, identifier(oid)),
				},
				issuerCertificatePem: issuer.certificate.pem,
			};
		}

		/** A path over the Section 10.2 certificate, anchored on `subjectPublicKeyInfoDer`. */
		function verifyWithAnchorKey(
			subjectPublicKeyInfoDer: Uint8Array,
			publicKeyAlgorithmOid: string,
		): Promise<BuildCandidatePathResult> {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			return buildCandidatePath({
				leaf: certificate.der,
				roots: [],
				trustAnchors: [
					{ subject: certificate.issuer, subjectPublicKeyInfoDer, publicKeyAlgorithmOid },
				],
			});
		}

		/** An Ed25519 certificate request, and the same request under another signature OID. */
		async function requestSignedUnder(oid: string): Promise<{
			readonly signed: Uint8Array;
			readonly relabelled: Uint8Array;
		}> {
			const keyPair = await generateKeyPair(ED25519);
			const request = await createCertificateSigningRequest({
				subject: { commonName: 'asn1-module.example' },
				publicKey: keyPair.publicKey,
				signerPrivateKey: keyPair.privateKey,
			});
			return {
				signed: request.der,
				relabelled: replaceCsrSignatureAlgorithm(request.der, sequence([objectIdentifier(oid)])),
			};
		}

		// "id-edwards-curve-algs OBJECT IDENTIFIER ::= { 1 3 101 }", with
		// "id-X25519 ::= { id-edwards-curve-algs 110 }", "id-X448 ::=
		// { id-edwards-curve-algs 111 }", "id-Ed25519 ::= { id-edwards-curve-algs
		// 112 }", and "id-Ed448 ::= { id-edwards-curve-algs 113 }". Each arc is one
		// octet, so each OID encodes as the arc's content octets and that octet.
		it.each([
			['id-X25519', 110, OIDS.x25519],
			['id-X448', 111, OIDS.x448],
			['id-Ed25519', 112, OIDS.ed25519],
			['id-Ed448', 113, OIDS.ed448],
		])('registers %s as arc %i of id-edwards-curve-algs', (_name, arc, oid) => {
			expect(oid).toBe(`${ID_EDWARDS_CURVE_ALGS}.${arc}`);
			expect(objectIdentifier(oid)).toEqual(
				Uint8Array.from([0x06, ARC_CONTENT.length + 1, ...ARC_CONTENT, arc]),
			);
			expect(decodeDerOidOrThrow(readRootElement(objectIdentifier(oid)))).toBe(oid);
		});

		// The module gives id-X25519 and id-X448 to "kaa-X25519 KEY-AGREE" and
		// "kaa-X448 KEY-AGREE", and names neither in a SIGNATURE-ALGORITHM object.
		// PKCS#10 leaves the identifier outside the signed CertificationRequestInfo,
		// so the signature stays valid over an unchanged payload and only the
		// classification of the OID can decide the verdict.
		it.each([
			['id-X25519', OIDS.x25519],
			['id-X448', OIDS.x448],
		])('does not verify a certificate request signed under %s', async (_name, oid) => {
			const { signed, relabelled } = await requestSignedUnder(oid);
			expect(await verifyCertificateSigningRequest(signed)).toMatchObject({ ok: true });
			expect(parseCertificateSigningRequestDerOrThrow(relabelled).signatureAlgorithmOid).toBe(oid);
			expect(await verifyCertificateSigningRequest(relabelled)).toMatchObject({
				ok: false,
				code: 'unsupported_signature_algorithm_parameters',
			});
		});

		// The same two KEY-AGREE objects, read across the rest of the structures
		// Section 6 places signatures in. A certificate and a CRL name their signature
		// algorithm inside the payload the signature covers, so each is signed again
		// under the key-agreement OID and carries a signature that is valid over what
		// it claims to sign; CMS and OCSP name it outside that payload, so those two
		// keep the library's own signature. Every control below is the same structure
		// under id-Ed25519, so only the classification of the OID separates them.
		it.each([
			['id-X25519', OIDS.x25519],
			['id-X448', OIDS.x448],
		])(
			'verifies no certificate, CRL, OCSP response, or signed data under %s',
			async (_name, oid) => {
				const material = await structuresSignedUnder(oid);

				expect(parseCertificateDerOrThrow(material.certificate.control).signatureAlgorithmOid).toBe(
					OIDS.ed25519,
				);
				expect(await verifySelfIssued(material.certificate.control)).toMatchObject({ ok: true });
				expect(
					parseCertificateDerOrThrow(material.certificate.relabelled).signatureAlgorithmOid,
				).toBe(oid);
				expect(await verifySelfIssued(material.certificate.relabelled)).toMatchObject({
					ok: false,
					code: 'unsupported_signature_algorithm_parameters',
				});

				expect(
					await verifyCertificateRevocationListSignature(
						material.crl.control,
						material.issuerCertificatePem,
					),
				).toMatchObject({ ok: true });
				expect(
					parseCertificateRevocationListDerOrThrow(material.crl.relabelled).signatureAlgorithmOid,
				).toBe(oid);
				expect(
					await verifyCertificateRevocationListSignature(
						material.crl.relabelled,
						material.issuerCertificatePem,
					),
				).toMatchObject({ ok: false, code: 'signature_invalid' });

				expect(
					await verifyOcspResponseSignature(
						material.response.control,
						material.issuerCertificatePem,
					),
				).toMatchObject({ ok: true });
				expect(
					parseOcspResponseDerOrThrow(material.response.relabelled).signatureAlgorithmOid,
				).toBe(oid);
				expect(
					await verifyOcspResponseSignature(
						material.response.relabelled,
						material.issuerCertificatePem,
					),
				).toMatchObject({ ok: false, code: 'signature_invalid' });

				expect(await verifyPkcs7SignedData(material.signedData.control)).toMatchObject({
					ok: true,
				});
				const relabelledSignedData = parsePkcs7SignedDataDer(material.signedData.relabelled);
				if (!relabelledSignedData.ok) {
					throw new Error(`parsePkcs7SignedDataDer failed: ${relabelledSignedData.code}`);
				}
				expect(relabelledSignedData.value.signerInfos[0]?.signatureAlgorithmOid).toBe(oid);
				expect(await verifyPkcs7SignedData(material.signedData.relabelled)).toMatchObject({
					ok: false,
					code: 'malformed',
				});
			},
		);

		// "sa-Ed25519 SIGNATURE-ALGORITHM ::= { IDENTIFIER id-Ed25519 [...]
		// PUBLIC-KEYS {pk-Ed25519} }", and "pk-Ed25519 PUBLIC-KEY ::= { IDENTIFIER
		// id-Ed25519 [...] }". The Section 10.2 certificate is self-issued and its
		// own subject key is id-X25519, so anchoring it on that key offers the
		// verifier a public key of the wrong type for the signature it carries.
		it('does not verify an Ed25519 signature against a public key that is not id-Ed25519', async () => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			expect(certificate.signatureAlgorithmOid).toBe(OIDS.ed25519);
			expect(certificate.publicKeyAlgorithmOid).toBe(OIDS.x25519);
			expect(
				await verifyWithAnchorKey(certificate.subjectPublicKeyInfoDer, OIDS.x25519),
			).toMatchObject({ ok: false, code: 'unsupported_signature_algorithm_parameters' });
			expect(
				await verifyWithAnchorKey(pemDecodeOrThrow('PUBLIC KEY', blockAt(597)), OIDS.ed25519),
			).toMatchObject({ ok: true });
		});

		// "pk-Ed25519 PUBLIC-KEY ::= { IDENTIFIER id-Ed25519 [...] PARAMS ARE absent
		// [...] PRIVATE-KEY CurvePrivateKey }". The clause binds the identifier of a
		// key as much as the identifier of a signature, so neither the Section 10.1
		// public key nor the Section 7 private key is readable once its
		// AlgorithmIdentifier carries a DER NULL.
		it('does not read an id-Ed25519 key whose identifier carries a NULL', async () => {
			const spki = pemDecodeOrThrow('PUBLIC KEY', blockAt(597));
			const pkcs8 = pemDecodeOrThrow('PRIVATE KEY', blockAt(402));
			expect(await importSpkiDer(spki, ED25519)).toMatchObject({ ok: true });
			expect(await importPkcs8Der(pkcs8, ED25519)).toMatchObject({ ok: true });

			expect(await importSpkiDer(withNullParameters(spki, 0, OIDS.ed25519), ED25519)).toMatchObject(
				{ ok: false, code: 'malformed' },
			);
			expect(
				await importPkcs8Der(withNullParameters(pkcs8, 1, OIDS.ed25519), ED25519),
			).toMatchObject({ ok: false, code: 'malformed' });
		});

		// The same clause reaches the key a path is anchored on: the Section 10.1
		// key verifies the Section 10.2 certificate, and the same key under an
		// identifier carrying a NULL does not.
		it('does not anchor a path on an id-Ed25519 key whose identifier carries a NULL', async () => {
			const spki = pemDecodeOrThrow('PUBLIC KEY', blockAt(597));
			expect(await verifyWithAnchorKey(spki, OIDS.ed25519)).toMatchObject({ ok: true });
			expect(
				await verifyWithAnchorKey(withNullParameters(spki, 0, OIDS.ed25519), OIDS.ed25519),
			).toMatchObject({ ok: false, code: 'signature_invalid' });
		});
	});

	describe('10. Examples', () => {
		/** The Ed25519 public key printed at rfc8410.txt:597. */
		const PUBLIC_KEY = blockAt(597);

		/** The X25519 certificate printed at rfc8410.txt:717. */
		const CERTIFICATE = blockAt(717);

		/** The private key printed at rfc8410.txt:739, carrying no public key. */
		const PRIVATE_KEY = blockAt(739);

		/** The private key printed at rfc8410.txt:765, carrying an attribute and the public key. */
		const ANNOTATED_PRIVATE_KEY = blockAt(765);

		/**
		 * The octets an ASN.1 dump prints across rfc8410.txt lines `startLine` to `endLine`.
		 *
		 * A dump line puts its offset and length columns before a colon and its
		 * content after, except in the plain hex the section prints for the private
		 * key value, which has no colon at all.
		 */
		function dumpBytes(startLine: number, endLine: number): Uint8Array {
			const collected: number[] = [];
			for (let line = startLine; line <= endLine; line++) {
				const text = lines[line - 1] ?? '';
				const colon = text.indexOf(':');
				const payload = colon === -1 ? text : text.slice(colon + 1);
				for (const match of payload.matchAll(/(?<=^|\s)[0-9A-F]{2}(?=\s|$)/g)) {
					collected.push(Number.parseInt(match[0], 16));
				}
			}
			if (collected.length === 0) {
				throw new Error(`rfc8410.txt:${startLine}-${endLine} prints no octets`);
			}
			return Uint8Array.from(collected);
		}

		/** The single-quoted value an ASN.1 dump line prints. */
		function dumpQuoted(lineNumber: number): string {
			const match = /'([^']*)'/.exec(lines[lineNumber - 1] ?? '');
			const quoted = match?.[1];
			if (quoted === undefined) {
				throw new Error(`rfc8410.txt:${lineNumber} prints no quoted value`);
			}
			return quoted;
		}

		/** The instant an ASN.1 dump line prints as `DD/MM/YYYY HH:MM:SS GMT`. */
		function dumpUtcTime(lineNumber: number): Date {
			const text = lines[lineNumber - 1] ?? '';
			const iso = text.replace(
				/^.*?(\d\d)\/(\d\d)\/(\d{4}) (\d\d:\d\d:\d\d) GMT.*$/,
				'$3-$2-$1T$4Z',
			);
			if (iso === text) {
				throw new Error(`rfc8410.txt:${lineNumber} prints no UTCTime`);
			}
			return new Date(iso);
		}

		/** The value a `Label: value` line of the section 10.1 key listing prints. */
		function listedValue(lineNumber: number, label: string): string {
			const text = (lines[lineNumber - 1] ?? '').trim();
			const prefix = `${label}: `;
			if (!text.startsWith(prefix)) {
				throw new Error(`rfc8410.txt:${lineNumber} does not print ${label}`);
			}
			return text.slice(prefix.length);
		}

		/** The child at `index` of a SEQUENCE. */

		/** The offset and content length a two-column ASN.1 dump line prints. */
		function dumpSpan(lineNumber: number): { offset: number; length: number } {
			const text = lines[lineNumber - 1] ?? '';
			if (/^\s*\d+\s+[0-9A-F]{2}\s+\d+:/.test(text)) {
				throw new Error(`rfc8410.txt:${lineNumber} prints a tag column`);
			}
			const match = /^\s*(\d+)\s+(\d+):/.exec(text);
			const offset = match?.[1];
			const length = match?.[2];
			if (offset === undefined || length === undefined) {
				throw new Error(`rfc8410.txt:${lineNumber} prints no offset and length`);
			}
			return { offset: Number.parseInt(offset, 10), length: Number.parseInt(length, 10) };
		}

		/** The offset, tag byte, and content length a three-column ASN.1 dump line prints. */
		function dumpTagged(lineNumber: number): { offset: number; tag: number; length: number } {
			const match = /^\s*(\d+)\s+([0-9A-F]{2})\s+(\d+):/.exec(lines[lineNumber - 1] ?? '');
			const offset = match?.[1];
			const tag = match?.[2];
			const length = match?.[3];
			if (offset === undefined || tag === undefined || length === undefined) {
				throw new Error(`rfc8410.txt:${lineNumber} prints no offset, tag, and length`);
			}
			return {
				offset: Number.parseInt(offset, 10),
				tag: Number.parseInt(tag, 16),
				length: Number.parseInt(length, 10),
			};
		}

		/**
		 * The bytes of the element a dump prints at `elementLine`, whose first child it
		 * prints at `childLine`.
		 *
		 * A dump prints content lengths, so the header length of an element is the
		 * distance from its own offset to the offset of what it holds.
		 */
		function dumpSlice(der: Uint8Array, elementLine: number, childLine: number): Uint8Array {
			const element = dumpSpan(elementLine);
			return der.slice(element.offset, dumpSpan(childLine).offset + element.length);
		}

		/** The dotted-decimal form of the arcs an ASN.1 dump line prints. */
		function dumpOid(lineNumber: number): string {
			const match = /[({'] ?(\d+(?: \d+)+) ?[)}']/.exec(lines[lineNumber - 1] ?? '');
			const arcs = match?.[1];
			if (arcs === undefined) {
				throw new Error(`rfc8410.txt:${lineNumber} prints no object identifier`);
			}
			return arcs.split(' ').join('.');
		}

		/** The value a `BOOLEAN` dump line prints. */
		function dumpBoolean(lineNumber: number): boolean {
			const text = lines[lineNumber - 1] ?? '';
			if (text.includes('BOOLEAN TRUE')) return true;
			if (text.includes('BOOLEAN FALSE')) return false;
			throw new Error(`rfc8410.txt:${lineNumber} prints no BOOLEAN`);
		}

		/** The value an `INTEGER` dump line prints as a single decimal. */
		function dumpInteger(lineNumber: number): number {
			const match = /INTEGER (\d+)\s*$/.exec(lines[lineNumber - 1] ?? '');
			const value = match?.[1];
			if (value === undefined) {
				throw new Error(`rfc8410.txt:${lineNumber} prints no decimal INTEGER`);
			}
			return Number.parseInt(value, 10);
		}

		/** The unused-bit count and the single set bit a BIT STRING dump prints. */
		function dumpBitString(countLine: number, bitLine: number): { unused: number; bit: number } {
			const unused = /(\d+) unused bits/.exec(lines[countLine - 1] ?? '')?.[1];
			const bit = /\(bit (\d+)\)/.exec(lines[bitLine - 1] ?? '')?.[1];
			if (unused === undefined || bit === undefined) {
				throw new Error(`rfc8410.txt:${countLine}-${bitLine} prints no BIT STRING`);
			}
			return { unused: Number.parseInt(unused, 10), bit: Number.parseInt(bit, 10) };
		}

		describe('10.1. Example Ed25519 Public Key', () => {
			/** The trimmed text of a 1-based line of the RFC. */
			const lineAt = (lineNumber: number): string => (lines[lineNumber - 1] ?? '').trim();

			/** The AlgorithmIdentifier of the listed key, as its own DER element. */
			function listedAlgorithmIdentifier(): Uint8Array {
				const spki = pemDecodeOrThrow('PUBLIC KEY', PUBLIC_KEY);
				return sliceElement(spki, fieldAt(spki, 0));
			}

			/** The algorithm OID of the listed key. */
			function listedAlgorithmOid(): string {
				const [algorithm, ...rest] = readSequenceChildren(listedAlgorithmIdentifier());
				if (algorithm === undefined) {
					throw new Error('AlgorithmIdentifier holds no algorithm');
				}
				expect(rest).toEqual([]);
				return decodeDerOidOrThrow(algorithm);
			}

			// The listing heads the key with "Public Key Algorithm: Ed25519", and the
			// key carries that algorithm itself, so an import told nothing reaches it.
			// Section 8 gives the same OID the same name, so the name this library
			// reports for the key is the one the listing prints.
			it('reads the algorithm the listing names out of the key alone', async () => {
				const key = await importSpkiPemOrThrow(PUBLIC_KEY);
				expect(key.type).toBe('public');
				expect(key.algorithm.name).toBe(listedValue(590, 'Public Key Algorithm'));
				expect(key.usages).toEqual(['verify']);
				expect(describePublicKeyAlgorithm(listedAlgorithmOid(), undefined)).toBe(
					listedValue(590, 'Public Key Algorithm'),
				);
			});

			// "This section contains illustrations of EdDSA public keys and
			// certificates, illustrating parameter choices", and Section 3 fixes the
			// choice for "id-Ed25519 OBJECT IDENTIFIER ::= { 1 3 101 112 }": "the
			// parameters field is absent". The identifier the listing carries holds
			// that OID and nothing beside it, and the library re-encodes the imported
			// key into the same bytes rather than supplying a parameters field.
			it('carries the id-Ed25519 identifier with no parameters, and re-encodes it unchanged', async () => {
				expect(listedAlgorithmOid()).toBe(dumpOid(210));
				expect(await exportSpkiDer(await importSpkiPemOrThrow(PUBLIC_KEY, ED25519))).toEqual(
					pemDecodeOrThrow('PUBLIC KEY', PUBLIC_KEY),
				);
			});

			// The listing prints "Public Key Usage:" with nothing after it, and
			// Section 5 puts "the intended application for the key" in "the keyUsage
			// certificate extension", so a public key on its own asserts none. A
			// certificate this library issues for the key carries the extension only
			// when its caller asks for one.
			it('gives the key no usage of its own', async () => {
				expect(lineAt(593)).toBe('Public Key Usage:');
				const signerPrivateKey = await importPkcs8PemOrThrow(PRIVATE_KEY, ED25519);
				const input = {
					issuer: { commonName: dumpQuoted(642) },
					subject: { commonName: dumpQuoted(654) },
					publicKey: await importSpkiPemOrThrow(PUBLIC_KEY, ED25519),
					signerPrivateKey,
					issuerPublicKey: await derivePublicKey(signerPrivateKey),
				};
				const extensions = {
					keyUsage: ['digitalSignature'],
				} as const satisfies CertificateExtensionsInput;

				const silent = await createCertificate(input);
				expect(parseCertificateDerOrThrow(silent.der).keyUsage).toBeUndefined();
				const declared = await createCertificate({ ...input, extensions });
				expect(parseCertificateDerOrThrow(declared.der).keyUsage?.flags).toEqual([
					...extensions.keyUsage,
				]);
			});

			// The listing gives this key the identifier "Public Key ID:
			// 9b1f5eeded043385e4f7bc623c5975b90bc8bb3b", and the 10.2 certificate
			// carries that same octet string in its subjectKeyIdentifier extension.
			it('names the identifier the 10.2 certificate carries', () => {
				const keyId = listedValue(595, 'Public Key ID');
				expect(keyId).toBe(hex(dumpBytes(698, 700)));
				expect(parseCertificatePemOrThrow(CERTIFICATE).subjectKeyIdentifier).toBe(keyId);
			});

			// RFC 5280 4.2.1.2 method 1 is "the 160-bit SHA-1 hash of the value of the BIT
			// STRING subjectPublicKey (excluding the tag, length, and number of unused
			// bits)", and the same section allows that "Other methods of generating unique
			// numbers are also acceptable". The listed identifier is not that hash of this
			// key, so the library reports the value the example prints and derives method 1
			// only for a certificate it issues itself.
			it('reports the listed identifier and derives method 1 for one it issues', async () => {
				const listed = listedValue(595, 'Public Key ID');
				expect(parseCertificatePemOrThrow(CERTIFICATE).subjectKeyIdentifier).toBe(listed);

				const signerPrivateKey = await importPkcs8PemOrThrow(PRIVATE_KEY, ED25519);
				const issued = await createCertificate({
					issuer: { commonName: dumpQuoted(642) },
					subject: { commonName: dumpQuoted(654) },
					publicKey: await importSpkiPemOrThrow(PUBLIC_KEY, ED25519),
					signerPrivateKey,
					issuerPublicKey: await derivePublicKey(signerPrivateKey),
				});
				const subjectPublicKey = fieldAt(pemDecodeOrThrow('PUBLIC KEY', PUBLIC_KEY), 1);
				const digest = await globalThis.crypto.subtle.digest(
					'SHA-1',
					toArrayBuffer(subjectPublicKey.value.slice(1)),
				);
				const derived = parseCertificateDerOrThrow(issued.der).subjectKeyIdentifier;
				expect(derived).toBe(hex(new Uint8Array(digest)));
				expect(derived).not.toBe(listed);
			});
		});

		describe('10.2. Example X25519 Certificate', () => {
			// The dump reads "[0] { INTEGER 2 }", "INTEGER 56 01 47 4A 2A 8D C3 30",
			// "UTF8String 'IETF Test Demo'" for both names, and UTCTimes of
			// 01/08/2016 12:19:24 GMT and 31/12/2040 23:59:59 GMT.
			it('reports the serial number, names, and validity the dump prints', () => {
				const certificate = parseCertificatePemOrThrow(CERTIFICATE);
				expect(certificate.version).toBe(dumpInteger(631) + 1);
				expect(certificate.serialNumberHex).toBe(hex(dumpBytes(633, 633)));
				const commonName = {
					oid: dumpOid(641),
					key: 'commonName',
					valueTag: 0x0c,
					value: dumpQuoted(642),
				} as const;
				expect(certificate.issuer.attributes).toEqual([commonName]);
				expect(certificate.subject.attributes).toEqual([
					{ ...commonName, oid: dumpOid(653), value: dumpQuoted(654) },
				]);
				expect(certificate.notBefore).toEqual(dumpUtcTime(647));
				expect(certificate.notAfter).toEqual(dumpUtcTime(648));
			});

			// "An example of a self-issued PKIX certificate": the dump prints the Name at
			// offset 29 and prints it again at offset 88, so the two names the parse
			// reports are one Name, byte for byte.
			it('repeats one name as issuer and as subject', () => {
				const certificate = parseCertificatePemOrThrow(CERTIFICATE);
				expect(certificate.issuer.derHex).toBe(hex(dumpSlice(certificate.der, 638, 639)));
				expect(certificate.subject.derHex).toBe(hex(dumpSlice(certificate.der, 650, 651)));
				expect(certificate.issuer.derHex).toBe(certificate.subject.derHex);
			});

			// Every dump line prints the offset and the content length of a field, so each
			// slice the parse hands back must start and end where the example puts it.
			it('places each field at the offset and length the dump prints', () => {
				const certificate = parseCertificatePemOrThrow(CERTIFICATE);
				const der = certificate.der;
				expect(der.length).toBe(dumpSpan(629).offset + dumpSpan(628).length);
				expect(certificate.tbsCertificateDer).toEqual(dumpSlice(der, 629, 630));
				expect(certificate.subjectPublicKeyInfoDer).toEqual(dumpSlice(der, 658, 659));
				const extensions = fieldAt(certificate.tbsCertificateDer, 7);
				expect(sliceElement(certificate.tbsCertificateDer, extensions)).toEqual(
					dumpSlice(der, 667, 668),
				);
				const signature = readRootElement(der.slice(dumpSpan(710).offset));
				expect(signature.tag).toBe(0x03);
				expect(signature.value.length).toBe(dumpSpan(710).length);
				expect(signature.value).toEqual(Uint8Array.of(0, ...certificate.signatureValue));
			});

			// The dump prints the same five-octet AlgorithmIdentifier twice, at offset 22
			// inside the tbsCertificate and at offset 230 beside the signature. RFC 5280
			// 4.1.1.2: "This field MUST contain the same algorithm identifier as the
			// signature field in the sequence tbsCertificate."
			it('names the signature the same way inside and outside the tbsCertificate', () => {
				const certificate = parseCertificatePemOrThrow(CERTIFICATE);
				const inner = dumpSlice(certificate.der, 634, 635);
				expect(inner).toEqual(dumpSlice(certificate.der, 706, 707));
				expect(inner).toEqual(sequence([objectIdentifier(dumpOid(636))]));
				expect(certificate.signatureAlgorithmOid).toBe(dumpOid(708));
			});

			// "An example of a self-issued PKIX certificate using Ed25519 to sign an
			// X25519 public key": the subject key is the ECDH 25519 one the dump prints
			// at offset 124, while the signature at offset 237 is Ed25519.
			it('reports the X25519 subject key and the Ed25519 signature the dump prints', () => {
				const certificate = parseCertificatePemOrThrow(CERTIFICATE);
				expect(certificate.publicKeyAlgorithmOid).toBe(dumpOid(661));
				const subjectPublicKey = fieldAt(certificate.subjectPublicKeyInfoDer, 1);
				expect(subjectPublicKey.tag).toBe(0x03);
				expect(subjectPublicKey.value).toEqual(Uint8Array.of(0, ...dumpBytes(664, 665)));
				expect(certificate.signatureAlgorithmOid).toBe(dumpOid(708));
				expect(certificate.signatureValue).toEqual(dumpBytes(711, 714));
			});

			// The dump prints basicConstraints critical with "BOOLEAN FALSE" for cA,
			// keyUsage as "'10000'B (bit 4)", and subjectKeyIdentifier over the octets
			// 10.1 lists as the public key ID.
			it('reports the extensions the dump prints', () => {
				const certificate = parseCertificatePemOrThrow(CERTIFICATE);
				expect(
					certificate.extensions.map((extension) => [extension.oid, extension.critical]),
				).toEqual([
					[dumpOid(670), dumpBoolean(679)],
					[dumpOid(687), dumpBoolean(688)],
					[dumpOid(695), dumpBoolean(696)],
				]);
				expect(certificate.basicConstraints).toEqual({ ca: dumpBoolean(682) });
				expect(certificate.keyUsage).toEqual({ flags: ['keyAgreement'], nonZeroPadding: false });
				expect(certificate.subjectKeyIdentifier).toBe(hex(dumpBytes(698, 700)));
			});

			// Each extnValue encapsulates a value the dump prints in full: a
			// basicConstraints SEQUENCE spelling cA FALSE, a keyUsage BIT STRING setting
			// one bit under three unused ones, and an OCTET STRING over the key ID.
			it('encapsulates the extension values the dump prints', () => {
				const { extensions } = parseCertificatePemOrThrow(CERTIFICATE);
				const valueDerOf = (oidLine: number): Uint8Array | undefined =>
					extensions.find((extension) => extension.oid === dumpOid(oidLine))?.valueDer;
				expect(valueDerOf(670)).toEqual(
					sequence([Uint8Array.of(0x01, 0x01, dumpBoolean(682) ? 0xff : 0x00)]),
				);
				const { unused, bit } = dumpBitString(690, 691);
				expect(valueDerOf(687)).toEqual(Uint8Array.of(0x03, 0x02, unused, 0x80 >> bit));
				expect(valueDerOf(695)).toEqual(octetString(dumpBytes(698, 700)));
			});

			// The dump spells the criticality of all three extensions, including the
			// "BOOLEAN FALSE" at offsets 187 and 203 that X.690 11.5 omits for a value
			// equal to the DEFAULT. The certificate the RFC prints is the one that must
			// parse, so a spelled-out FALSE reads as non-critical rather than failing.
			it('reads the criticality DEFAULT the example spells out', () => {
				const certificate = parseCertificatePemOrThrow(CERTIFICATE);
				const extensions = fieldAt(certificate.tbsCertificateDer, 7);
				expect(extensions.tag).toBe(0xa3);
				const listed = readSequenceChildren(extensions.value);
				expect(listed).toHaveLength(3);
				const criticality = listed.map((extension) => {
					const fields = readSequenceChildren(sliceElement(extensions.value, extension));
					expect(fields.map((field) => field.tag)).toEqual([0x06, 0x01, 0x04]);
					return fieldAt(sliceElement(extensions.value, extension), 1).value;
				});
				expect(criticality).toEqual([
					Uint8Array.of(0xff),
					Uint8Array.of(0x00),
					Uint8Array.of(0x00),
				]);
			});

			// The dump prints eight fields under the tbsCertificate and prints nothing
			// between the subjectPublicKeyInfo at 115 and the [3] extensions at 159,
			// where RFC 5280 4.1.2.8 places issuerUniqueID and subjectUniqueID.
			it('holds the eight tbsCertificate fields the dump prints and neither unique identifier', () => {
				const certificate = parseCertificatePemOrThrow(CERTIFICATE);
				const base = dumpSpan(629).offset;
				const fields = readSequenceChildren(certificate.tbsCertificateDer).map((field) => ({
					offset: base + field.start - field.headerLength,
					length: field.length,
				}));
				expect(fields).toEqual([630, 633, 634, 638, 646, 650, 658, 667].map(dumpSpan));
			});

			// RFC 5280 4.1.2.5: "CAs conforming to this profile MUST always encode
			// certificate validity dates through the year 2049 as UTCTime; certificate
			// validity dates in 2050 or later MUST be encoded as GeneralizedTime." The
			// dump names both bounds UTCTime and puts the later of them in 2040, so a
			// certificate this library issues over the same window carries the same tag.
			it('carries both validity bounds as the UTCTime the dump names', async () => {
				const boundsOf = (tbs: Uint8Array): readonly DerElement[] =>
					readSequenceChildren(sliceElement(tbs, fieldAt(tbs, 4)));
				expect([647, 648].map((line) => (lines[line - 1] ?? '').includes('UTCTime'))).toEqual([
					true,
					true,
				]);
				expect(dumpUtcTime(648).getUTCFullYear()).toBeLessThan(2050);
				const certificate = parseCertificatePemOrThrow(CERTIFICATE);
				expect(boundsOf(certificate.tbsCertificateDer).map((bound) => bound.tag)).toEqual([
					0x17, 0x17,
				]);

				const signerPrivateKey = await importPkcs8PemOrThrow(PRIVATE_KEY, ED25519);
				const issued = await createCertificate({
					issuer: { commonName: dumpQuoted(642) },
					subject: { commonName: dumpQuoted(654) },
					publicKey: await importSpkiPemOrThrow(PUBLIC_KEY, ED25519),
					signerPrivateKey,
					issuerPublicKey: await derivePublicKey(signerPrivateKey),
					validity: { notBefore: dumpUtcTime(647), notAfter: dumpUtcTime(648) },
				});
				const parsed = parseCertificateDerOrThrow(issued.der);
				expect(boundsOf(parsed.tbsCertificateDer).map((bound) => bound.tag)).toEqual([0x17, 0x17]);
				expect([parsed.notBefore, parsed.notAfter]).toEqual([dumpUtcTime(647), dumpUtcTime(648)]);
			});

			// RFC 5280 4.1.2.4: "If the names in the issuer and subject field in a
			// certificate match [...] then the certificate is self-issued", and 3.2:
			// "Self-signed certificates are self-issued certificates where the digital
			// signature may be verified by the public key bound into the certificate."
			// This certificate repeats one Name and binds an X25519 key that verifies
			// nothing, so only the 10.1 Ed25519 key anchors it, and a verifier that
			// treated self-issued as self-signed would refuse the RFC's own example.
			it('validates as a self-issued path anchored on the 10.1 key', async () => {
				const certificate = parseCertificatePemOrThrow(CERTIFICATE);
				expect(certificate.issuer.derHex).toBe(certificate.subject.derHex);
				expect(certificate.publicKeyAlgorithmOid).toBe(dumpOid(661));
				const result = await verifyCertificateChain({
					leaf: CERTIFICATE,
					roots: [],
					trustAnchors: [
						{
							subject: certificate.issuer,
							subjectPublicKeyInfoDer: pemDecodeOrThrow('PUBLIC KEY', PUBLIC_KEY),
							publicKeyAlgorithmOid: OIDS.ed25519,
						},
					],
					at: dumpUtcTime(647),
				});
				expect(result).toMatchObject({ ok: true });
			});

			// A certificate whose own key does verify its signature is self-signed, and
			// the same call must still refuse it without `allowSelfSignedLeaf`.
			it('refuses a leaf its own key signs', async () => {
				const created = await createSelfSignedCertificate({
					subject: { commonName: dumpQuoted(642) },
					algorithm: ED25519,
				});
				const anchored = {
					leaf: created.certificate.pem,
					roots: [created.certificate.pem],
				} as const;
				expect(await verifyCertificateChain(anchored)).toMatchObject({
					ok: false,
					code: 'self_signed_leaf_not_allowed',
				});
				expect(
					await verifyCertificateChain({ ...anchored, allowSelfSignedLeaf: true }),
				).toMatchObject({ ok: true });
			});
		});

		describe('10.3. Examples of Ed25519 Private Key', () => {
			/** The offset of the tag byte of a field, which is the offset a dump prints for it. */
			const offsetOf = (field: DerElement): number => field.start - field.headerLength;

			// "Note that the value of the private key is: D4 EE 72 DB [...] 58 42",
			// and the same section prints the public key of that private key at 10.1.
			it('imports the private key printed without a public key', async () => {
				const der = pemDecodeOrThrow('PRIVATE KEY', PRIVATE_KEY);
				expect(fieldAt(der, 2).value).toEqual(dumpBytes(752, 754));
				expect(readRootElement(fieldAt(der, 2).value).value).toEqual(dumpBytes(759, 760));
				const key = await importPkcs8PemOrThrow(PRIVATE_KEY);
				expect(key.algorithm.name).toBe('Ed25519');
				expect(await exportSpkiDer(await derivePublicKey(key))).toEqual(
					pemDecodeOrThrow('PUBLIC KEY', PUBLIC_KEY),
				);
			});

			// The dump prints a tag column beside every field of the key without a public
			// key: SEQUENCE 30 over INTEGER 02, SEQUENCE 30 over OBJECT IDENTIFIER 06, and
			// OCTET STRING 04, ending 46 octets after the two its own header takes. Each
			// field lands on the offset the dump prints and runs the length it prints.
			it('encodes the fields the dump tags, and stops where the dump stops', () => {
				const der = pemDecodeOrThrow('PRIVATE KEY', PRIVATE_KEY);
				expect(der.length).toBe(dumpTagged(746).offset + dumpTagged(745).length);
				expect(readRootElement(der).tag).toBe(dumpTagged(745).tag);
				expect(readSequenceChildren(der).map((field) => field.tag)).toEqual([
					dumpTagged(746).tag,
					dumpTagged(747).tag,
					dumpTagged(751).tag,
				]);
				expect(readSequenceChildren(der).map(offsetOf)).toEqual([
					dumpTagged(746).offset,
					dumpTagged(747).offset,
					dumpTagged(751).offset,
				]);
				expect(fieldAt(der, 0).value).toEqual(Uint8Array.of(dumpInteger(746)));
				expect(fieldAt(der, 0).value).toHaveLength(dumpTagged(746).length);
				expect(fieldAt(der, 1).value).toHaveLength(dumpTagged(747).length);
				expect(fieldAt(der, 2).value).toHaveLength(dumpTagged(751).length);
				// 3: "for all of the OIDs, the parameters MUST be absent", and
				// `readRootElement` refuses trailing data, so the five octets the dump
				// gives the AlgorithmIdentifier reading back as one element is that absence.
				const algorithm = readRootElement(fieldAt(der, 1).value);
				expect(algorithm.tag).toBe(dumpTagged(748).tag);
				expect(algorithm.value).toHaveLength(dumpTagged(748).length);
				expect(decodeDerOidOrThrow(algorithm)).toBe(dumpOid(749));
			});

			// "The following example, in addition to encoding the private key, has an
			// attribute included as well as the public key." The dump names the
			// attribute '1 2 840 113549 1 9 9 20' over the UTF8String 'Curdle Chairs',
			// and the [1] field repeats the 10.1 subjectPublicKey.
			it('carries the attribute and the public key the dump prints', () => {
				const first = pemDecodeOrThrow('PRIVATE KEY', PRIVATE_KEY);
				const second = pemDecodeOrThrow('PRIVATE KEY', ANNOTATED_PRIVATE_KEY);
				expect(second.length).toBe(dumpSpan(794).offset + dumpSpan(793).length);
				expect(readSequenceChildren(second).map(offsetOf)).toEqual([
					dumpSpan(794).offset,
					dumpSpan(795).offset,
					dumpSpan(798).offset,
					dumpSpan(803).offset,
					dumpSpan(811).offset,
				]);
				expect(fieldAt(second, 0).value).toEqual(Uint8Array.of(dumpInteger(794)));
				expect(fieldAt(second, 2).value).toEqual(dumpBytes(799, 801));
				expect(fieldAt(second, 2).value).toEqual(fieldAt(first, 2).value);

				// The dump names the same algorithm as the first printing, over the same
				// five octets, so this printing carries no `parameters` either.
				expect(fieldAt(second, 1).value).toHaveLength(dumpSpan(795).length);
				expect(decodeDerOidOrThrow(readRootElement(fieldAt(second, 1).value))).toBe(dumpOid(796));
				expect(sliceElement(second, fieldAt(second, 1))).toEqual(
					sliceElement(first, fieldAt(first, 1)),
				);

				const attribute = fieldAt(second, 3);
				expect(attribute.tag).toBe(0xa0);
				expect(sliceElement(second, attribute)).toEqual(dumpSlice(second, 803, 804));
				expect(attribute.value).toEqual(dumpSlice(second, 804, 805));
				expect(readSequenceChildren(attribute.value).map((field) => field.tag)).toEqual([
					0x06, 0x31,
				]);
				expect(decodeDerOidOrThrow(fieldAt(attribute.value, 0))).toBe(
					dumpQuoted(805).replaceAll(' ', '.'),
				);
				expect(fieldAt(attribute.value, 0).value).toHaveLength(dumpSpan(805).length);
				expect(fieldAt(attribute.value, 1).value).toHaveLength(dumpSpan(806).length);
				const attributeValue = readRootElement(fieldAt(attribute.value, 1).value);
				expect(attributeValue.tag).toBe(0x0c);
				expect(attributeValue.value).toHaveLength(dumpSpan(807).length);
				expect(new TextDecoder().decode(attributeValue.value)).toBe(dumpQuoted(807));

				const publicKey = fieldAt(second, 4);
				expect(publicKey.tag).toBe(0x81);
				expect(publicKey.value.length).toBe(dumpSpan(811).length);
				expect(publicKey.value).toEqual(dumpBytes(811, 813));
				expect(publicKey.value).toEqual(
					fieldAt(pemDecodeOrThrow('PUBLIC KEY', PUBLIC_KEY), 1).value,
				);
			});

			// RFC 5958 2 makes `attributes [0]` and `publicKey [1]` optional, and 7
			// notes that "there exist some private key import functions that have not
			// picked up the new ASN.1 structure OneAsymmetricKey [...] they will not
			// accept a private key structure that contains the public key field". Bun
			// 1.3.14 and earlier is one of them (oven-sh/bun#35432), so this library
			// reduces the key to its v1 fields before handing it to the platform and
			// reaches the 10.1 key pair from either printing.
			it('imports the annotated key the platform pkcs8 import refuses', async () => {
				const second = pemDecodeOrThrow('PRIVATE KEY', ANNOTATED_PRIVATE_KEY);
				const stripped = sequence([
					integer(Uint8Array.of(0)),
					sliceElement(second, fieldAt(second, 1)),
					sliceElement(second, fieldAt(second, 2)),
				]);
				expect(stripped).toEqual(pemDecodeOrThrow('PRIVATE KEY', PRIVATE_KEY));

				for (const der of [stripped, second]) {
					const key = await importPkcs8DerOrThrow(der, ED25519);
					expect(await exportSpkiDer(await derivePublicKey(key))).toEqual(
						pemDecodeOrThrow('PUBLIC KEY', PUBLIC_KEY),
					);
				}
			});

			// "An example of the same Ed25519 private key encoded with an attribute and
			// the public key." The two printings hold one private key, and this library
			// exports the printing that carries the private key alone, so either one
			// re-encodes to the first printing octet for octet.
			it('exports either printing as the printing that carries the private key alone', async () => {
				for (const pem of [PRIVATE_KEY, ANNOTATED_PRIVATE_KEY]) {
					expect(await exportPkcs8Der(await importPkcs8PemOrThrow(pem, ED25519))).toEqual(
						pemDecodeOrThrow('PRIVATE KEY', PRIVATE_KEY),
					);
				}
			});

			// The second printing is "the same Ed25519 private key [...] and the public
			// key", so its `publicKey [1]` is the public key of the private key beside
			// it. 7 names what the field buys, "being able to do a consistency check on
			// the key pair", so a [1] field carrying another key is not a key pair this
			// library imports. The X25519 subjectPublicKey of 10.2 is such another key.
			it('does not import the annotated key with a publicKey the private key does not have', async () => {
				const second = pemDecodeOrThrow('PRIVATE KEY', ANNOTATED_PRIVATE_KEY);
				const withPublicKey = (bits: Uint8Array): Uint8Array =>
					sequence([
						integer(Uint8Array.of(1)),
						sliceElement(second, fieldAt(second, 1)),
						sliceElement(second, fieldAt(second, 2)),
						sliceElement(second, fieldAt(second, 3)),
						implicitPrimitiveContext(1, bits),
					]);

				const own = fieldAt(second, 4).value;
				expect(withPublicKey(own)).toEqual(second);
				expect(await importPkcs8Der(withPublicKey(own), ED25519)).toMatchObject({ ok: true });

				const foreign = fieldAt(
					parseCertificatePemOrThrow(CERTIFICATE).subjectPublicKeyInfoDer,
					1,
				).value;
				expect(foreign).toHaveLength(own.length);
				expect(foreign).not.toEqual(own);
				expect(await importPkcs8Der(withPublicKey(foreign), ED25519)).toMatchObject({
					ok: false,
					code: 'malformed',
				});
			});
		});
	});

	describe('11. IANA Considerations', () => {
		/** The registry the ASN.1 module of Section 9 is registered in. */
		const SMI_SECURITY_FOR_PKIX_MODULE_IDENTIFIER = '1.3.6.1.5.5.7.0';

		/** `id-mod-safecurves-pkix`, value 93 of that registry. */
		const ID_MOD_SAFECURVES_PKIX = `${SMI_SECURITY_FOR_PKIX_MODULE_IDENTIFIER}.93`;

		/** The arc RFC 8411 Table 1 assigns the algorithm OIDs from. */
		const DONATED_ARC = '1.3.101';

		/**
		 * Decimals of the 1.3.101 arc that name no algorithm, with the reason RFC 8411
		 * Table 1 gives.
		 *
		 * 99 and 128 sit outside the donated 100-127 range and stay with DigiCert; 100
		 * is held back for a future child registry; 114 and 115 are reserved against
		 * draft-ietf-curdle-pkix-03 and name no algorithm of this RFC; 109, 116, and
		 * 127 are unassigned decimals of the donated range, 127 being its last.
		 */
		const UNNAMED_DECIMALS = [
			[99, 'retained by DigiCert'],
			[100, 'reserved for child reg'],
			[109, 'unassigned'],
			[114, 'reserved for id-EdDSA25519-ph'],
			[115, 'reserved for id-EdDSA448-ph'],
			[116, 'unassigned'],
			[127, 'unassigned'],
			[128, 'retained by DigiCert'],
		] as const;

		/** The same SEQUENCE, with the AlgorithmIdentifier at `index` naming `oid` and no parameters. */

		/** An Ed25519 certificate request, and the same request relabelled with `oid`. */
		async function requestRelabelledAs(oid: string): Promise<{
			readonly signed: Uint8Array;
			readonly relabelled: Uint8Array;
		}> {
			const keyPair = await generateKeyPair(ED25519);
			const request = await createCertificateSigningRequest({
				subject: { commonName: 'iana.example' },
				publicKey: keyPair.publicKey,
				signerPrivateKey: keyPair.privateKey,
			});
			return {
				signed: request.der,
				relabelled: replaceCsrSignatureAlgorithm(request.der, sequence([objectIdentifier(oid)])),
			};
		}

		// "The OIDs are being independently registered in the IANA registry "SMI
		// Security for Cryptographic Algorithms" in [RFC8411]." That registry, RFC 8411
		// Table 1, assigns 110 to id-X25519, 111 to id-X448, 112 to id-EdDSA25519, and
		// 113 to id-EdDSA448, and requires the Decimal column to be "a number between
		// 100 and 127 inclusive". Those four are every algorithm this library may name
		// under 1.3.101. The module identifier of the first paragraph belongs to a
		// registry of ASN.1 modules and reaches no encoded structure, so it is not
		// among the OIDs the library carries either.
		it('names the four decimals the cryptographic algorithm registry assigns', () => {
			const underArc = Object.entries(OIDS)
				.filter(([, oid]) => oid.startsWith(`${DONATED_ARC}.`))
				.sort(([, left], [, right]) => left.localeCompare(right));
			expect(underArc).toEqual([
				['x25519', `${DONATED_ARC}.110`],
				['x448', `${DONATED_ARC}.111`],
				['ed25519', `${DONATED_ARC}.112`],
				['ed448', `${DONATED_ARC}.113`],
			]);
			for (const [, oid] of underArc) {
				const decimal = Number(oid.slice(DONATED_ARC.length + 1));
				expect(decimal).toBeGreaterThanOrEqual(100);
				expect(decimal).toBeLessThanOrEqual(127);
			}
			expect(
				Object.values(OIDS).filter((oid) =>
					oid.startsWith(`${SMI_SECURITY_FOR_PKIX_MODULE_IDENTIFIER}.`),
				),
			).toEqual([]);
		});

		// The registry identifies an algorithm by the decimal it assigns, so a decimal
		// it leaves unassigned names no key. The Section 10.1 public key and the
		// Section 7 private key are the control: relabelling the AlgorithmIdentifier is
		// the only change, and neither the inferred nor the requested import may read
		// the bytes as the id-Ed25519 key they still hold.
		it.each(UNNAMED_DECIMALS)(
			'imports no key whose algorithm is 1.3.101.%i (%s)',
			async (decimal) => {
				const oid = `${DONATED_ARC}.${decimal}`;
				const spki = pemDecodeOrThrow('PUBLIC KEY', blockAt(597));
				const pkcs8 = pemDecodeOrThrow('PRIVATE KEY', blockAt(402));
				expect(await importSpkiDer(spki)).toMatchObject({ ok: true });
				expect(await importPkcs8Der(pkcs8)).toMatchObject({ ok: true });

				const relabelledSpki = withAlgorithmOid(spki, 0, oid);
				const relabelledPkcs8 = withAlgorithmOid(pkcs8, 1, oid);
				expect(await importSpkiDer(relabelledSpki)).toMatchObject({
					ok: false,
					code: 'malformed',
				});
				expect(await importSpkiDer(relabelledSpki, ED25519)).toMatchObject({
					ok: false,
					code: 'malformed',
				});
				expect(await importPkcs8Der(relabelledPkcs8)).toMatchObject({
					ok: false,
					code: 'malformed',
				});
				expect(await importPkcs8Der(relabelledPkcs8, ED25519)).toMatchObject({
					ok: false,
					code: 'malformed',
				});
			},
		);

		// The same decimals name no signature. PKCS#10 keeps the identifier outside the
		// signed CertificationRequestInfo, so relabelling leaves a signature that is
		// still valid over its payload and only the unassigned OID can decide the
		// verdict.
		it.each(UNNAMED_DECIMALS)(
			'verifies no certificate request signed under 1.3.101.%i (%s)',
			async (decimal) => {
				const oid = `${DONATED_ARC}.${decimal}`;
				const { signed, relabelled } = await requestRelabelledAs(oid);
				expect(await verifyCertificateSigningRequest(signed)).toMatchObject({ ok: true });
				expect(parseCertificateSigningRequestDerOrThrow(relabelled).signatureAlgorithmOid).toBe(
					oid,
				);
				expect(await verifyCertificateSigningRequest(relabelled)).toMatchObject({
					ok: false,
					code: 'unsupported_signature_algorithm_parameters',
				});
			},
		);

		// Every row of RFC 8411 Table 1 is a decimal directly under the arc, so an
		// assignment names one whole OID. The arc itself is "id-edwards-curve-algs
		// OBJECT IDENTIFIER ::= { 1 3 101 }" of the Section 9 module, which no
		// SIGNATURE-ALGORITHM, KEY-AGREE, or PUBLIC-KEY object names, and the registry
		// has no row below a decimal it assigns. Neither shape may be read as the
		// algorithm it sits next to.
		it.each([
			['the bare arc', DONATED_ARC],
			['a child of id-Ed25519', `${DONATED_ARC}.112.1`],
			['a child of id-X25519', `${DONATED_ARC}.110.0`],
		])('names no algorithm at %s', async (_label, oid) => {
			const spki = pemDecodeOrThrow('PUBLIC KEY', blockAt(597));
			const pkcs8 = pemDecodeOrThrow('PRIVATE KEY', blockAt(402));
			expect(await importSpkiDer(withAlgorithmOid(spki, 0, oid))).toMatchObject({
				ok: false,
				code: 'malformed',
			});
			expect(await importSpkiDer(withAlgorithmOid(spki, 0, oid), ED25519)).toMatchObject({
				ok: false,
				code: 'malformed',
			});
			expect(await importPkcs8Der(withAlgorithmOid(pkcs8, 1, oid))).toMatchObject({
				ok: false,
				code: 'malformed',
			});

			const { relabelled } = await requestRelabelledAs(oid);
			expect(parseCertificateSigningRequestDerOrThrow(relabelled).signatureAlgorithmOid).toBe(oid);
			expect(await verifyCertificateSigningRequest(relabelled)).toMatchObject({
				ok: false,
				code: 'unsupported_signature_algorithm_parameters',
			});
		});

		// An unassigned decimal is reported as itself and gets no name, so a caller
		// reading a certificate cannot mistake it for one of the four. The Section 10.2
		// certificate spells id-X25519 once, in its subject key, and every decimal of
		// this arc is one octet, so moving that octet to 114 leaves the DER lengths
		// alone.
		it('gives an unassigned 1.3.101 decimal no algorithm name', () => {
			const der = new Uint8Array(parseCertificatePemOrThrow(blockAt(717)).der);
			const idX25519 = [...objectIdentifier(OIDS.x25519)];
			let occurrences = 0;
			for (let index = 0; index + idX25519.length <= der.length; index += 1) {
				if (idX25519.every((byte, offset) => der[index + offset] === byte)) {
					der[index + idX25519.length - 1] = 114;
					occurrences += 1;
				}
			}
			expect(occurrences).toBe(1);
			const parsed = parseCertificateDerOrThrow(der);
			expect(parsed.publicKeyAlgorithmOid).toBe(`${DONATED_ARC}.114`);
			expect(parsed.publicKeyAlgorithmName).toBe(`Unknown (${DONATED_ARC}.114)`);
		});

		// "For the ASN.1 module in Section 9, IANA has registered value 93 for
		// "id-mod-safecurves-pkix" in the "SMI Security for PKIX Module Identifier"
		// (1.3.6.1.5.5.7.0) registry." The registered value is the OID
		// 1.3.6.1.5.5.7.0.93, whose DER is one encoding.
		it('encodes id-mod-safecurves-pkix as value 93 of the PKIX module registry', () => {
			const der = objectIdentifier(ID_MOD_SAFECURVES_PKIX);
			expect(hex(der)).toBe('06082b0601050507005d');
			expect(decodeDerOidOrThrow(readRootElement(der))).toBe(ID_MOD_SAFECURVES_PKIX);
		});

		// The module identifier names the ASN.1 module, in a registry of modules rather
		// than of algorithms, so no key and no signature may be read under it.
		it('reads no key and no signature under id-mod-safecurves-pkix', async () => {
			const spki = pemDecodeOrThrow('PUBLIC KEY', blockAt(597));
			const pkcs8 = pemDecodeOrThrow('PRIVATE KEY', blockAt(402));
			expect(await importSpkiDer(withAlgorithmOid(spki, 0, ID_MOD_SAFECURVES_PKIX))).toMatchObject({
				ok: false,
				code: 'malformed',
			});
			expect(
				await importPkcs8Der(withAlgorithmOid(pkcs8, 1, ID_MOD_SAFECURVES_PKIX)),
			).toMatchObject({ ok: false, code: 'malformed' });

			const { relabelled } = await requestRelabelledAs(ID_MOD_SAFECURVES_PKIX);
			expect(await verifyCertificateSigningRequest(relabelled)).toMatchObject({
				ok: false,
				code: 'unsupported_signature_algorithm_parameters',
			});
		});
	});

	describe('12. Security Considerations', () => {
		/** The group order L that RFC 8032 5.1 gives for Ed25519. */
		const GROUP_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;

		/** The X25519 subject key of the Section 10.2 certificate. */
		const X25519_SPKI = parseCertificatePemOrThrow(blockAt(717)).subjectPublicKeyInfoDer;

		/** The octets printed as hexadecimal across 1-based lines of a vendored RFC. */
		async function hexAt(rfc: string, ...lineNumbers: readonly number[]): Promise<Uint8Array> {
			const printed = (await Bun.file(`${rfcDir}/${rfc}`).text()).split('\n');
			const digits = lineNumbers.map((number) => (printed[number - 1] ?? '').trim()).join('');
			if (!/^[0-9a-f]+$/u.test(digits)) {
				throw new Error(`${rfc} lines ${lineNumbers.join(', ')} print no hexadecimal: ${digits}`);
			}
			return hexToBytes(digits);
		}

		/** A v0 OneAsymmetricKey holding `privateKey` under id-Ed25519. */
		function ed25519Pkcs8(privateKey: Uint8Array): Uint8Array {
			return sequence([
				integer(Uint8Array.from([0])),
				sequence([objectIdentifier(OIDS.ed25519)]),
				octetString(octetString(privateKey)),
			]);
		}

		/** The 32 key octets of an Ed25519 SubjectPublicKeyInfo. */
		function publicKeyOctets(spki: Uint8Array): Uint8Array {
			return readSequenceChildren(spki)[1]?.value.slice(1) ?? new Uint8Array();
		}

		/** The child at `index` of a SEQUENCE, as its own DER element. */

		/** The same SEQUENCE, with the AlgorithmIdentifier child at `index` naming `oid`. */

		/** An octet string read as the little-endian integer RFC 8032 5.1.2 encodes. */

		/** The same signature, with S raised by the group order it is reduced modulo. */
		function withRaisedS(signature: Uint8Array): Uint8Array {
			const raised = littleEndianInteger(signature.slice(32)) + GROUP_ORDER;
			const octets = new Uint8Array(32);
			for (let index = 0; index < 32; index += 1) {
				octets[index] = Number((raised >> BigInt(8 * index)) & 0xffn);
			}
			expect(littleEndianInteger(octets)).toBeGreaterThan(GROUP_ORDER);
			return new Uint8Array([...signature.slice(0, 32), ...octets]);
		}

		/** The same SEQUENCE, with the BIT STRING at index 2 holding `signature`. */

		/** The same OCSPResponse, with the signature of its BasicOCSPResponse replaced. */
		function withBasicResponseSignature(der: Uint8Array, signature: Uint8Array): Uint8Array {
			const responseBytes = readRootElement(childAt(der, 1)).value;
			const basic = readRootElement(childAt(responseBytes, 1)).value;
			return sequence([
				childAt(der, 0),
				explicitContext(
					0,
					sequence([
						childAt(responseBytes, 0),
						octetString(withSignatureValue(basic, bitString(signature))),
					]),
				),
			]);
		}

		/** The code a builder threw, or `undefined` when it returned. */

		/** The children of a constructed element, whatever its tag, as their own DER elements. */

		/** The same ContentInfo, with the OCTET STRING signature of its SignerInfo replaced. */
		function withSignerInfoSignature(der: Uint8Array, signature: Uint8Array): Uint8Array {
			const [contentType, content] = constructedChildren(der);
			const signedDataDer = content === undefined ? undefined : constructedChildren(content)[0];
			if (contentType === undefined || signedDataDer === undefined) {
				throw new Error('ContentInfo carries no SignedData');
			}
			const fields = constructedChildren(signedDataDer);
			const signerInfosIndex = fields.length - 1;
			const signerInfos = fields[signerInfosIndex];
			const signerInfo =
				signerInfos === undefined ? undefined : constructedChildren(signerInfos)[0];
			if (signerInfo === undefined) {
				throw new Error('SignedData carries no SignerInfo');
			}
			const signerInfoFields = constructedChildren(signerInfo);
			const rebuiltSignerInfo = sequence(
				signerInfoFields.map((field, index) =>
					index === signerInfoFields.length - 1 ? octetString(signature) : field,
				),
			);
			const rebuiltSignedData = sequence(
				fields.map((field, index) =>
					index === signerInfosIndex ? setOf([rebuiltSignerInfo]) : field,
				),
			);
			return sequence([contentType, explicitContext(0, rebuiltSignedData)]);
		}

		/** One Ed25519 certification authority, and one end-entity certificate under it. */
		async function edwardsAuthority(label: string) {
			const issuer = await createSelfSignedCertificate({
				subject: { commonName: 'IETF Test Demo' },
				algorithm: ED25519,
				extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
			});
			const subject = await createSelfSignedCertificate({
				subject: { commonName: `${label}-subject.example` },
				algorithm: ED25519,
			});
			return { issuer, subject };
		}

		// "The procedures for going from a private key to a public key are different
		// when used with Diffie-Hellman versus when used with Edwards Signatures."
		// RFC 7748 6.1 states X25519(a, 9) for its own private key a, and RFC 8032 7.1
		// TEST 1 states the Ed25519 public key of its own secret key. Reading a as an
		// Ed25519 private key runs the second procedure over the first procedure's
		// input, and the public key that comes out is not the one RFC 7748 prints.
		it('runs the EdDSA procedure over a private key, not the Diffie-Hellman one', async () => {
			const edwardsPrivateKey = await hexAt('rfc8032.txt', 1307, 1308);
			const edwardsPublicKey = await hexAt('rfc8032.txt', 1311, 1312);
			const derivedEdwards = await derivePublicKey(
				await importPkcs8DerOrThrow(ed25519Pkcs8(edwardsPrivateKey), ED25519),
			);
			expect(publicKeyOctets(await exportSpkiDer(derivedEdwards))).toEqual(edwardsPublicKey);

			const montgomeryPrivateKey = await hexAt('rfc7748.txt', 769);
			const montgomeryPublicKey = await hexAt('rfc7748.txt', 771);
			const derivedFromMontgomery = await derivePublicKey(
				await importPkcs8DerOrThrow(ed25519Pkcs8(montgomeryPrivateKey), ED25519),
			);
			const derivedOctets = publicKeyOctets(await exportSpkiDer(derivedFromMontgomery));
			expect(derivedOctets).toHaveLength(montgomeryPublicKey.length);
			expect(derivedOctets).not.toEqual(montgomeryPublicKey);
			expect(childAt(await exportSpkiDer(derivedFromMontgomery), 0)).toEqual(
				sequence([objectIdentifier(OIDS.ed25519)]),
			);
		});

		// "This means that the same public key cannot be used for both ECDH and EdDSA."
		// The Section 10.2 certificate is self-issued, so its X25519 subject key stands
		// where its Ed25519 verification key would: relabelling that key id-Ed25519
		// offers 32 octets WebCrypto reads as a point, and the signature over the
		// certificate still does not verify under it.
		it('verifies no signature under an ECDH key value relabelled id-Ed25519', async () => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			const relabelled = withAlgorithmOid(X25519_SPKI, 0, OIDS.ed25519);
			expect(await importSpkiDer(relabelled, ED25519)).toMatchObject({ ok: true });
			expect(
				await buildCandidatePath({
					leaf: certificate.der,
					roots: [],
					trustAnchors: [
						{
							subject: certificate.issuer,
							subjectPublicKeyInfoDer: relabelled,
							publicKeyAlgorithmOid: OIDS.ed25519,
						},
					],
				}),
			).toMatchObject({ ok: false, code: 'signature_invalid' });
		});

		// The same sentence read from the other side: the Section 10.1 key verifies the
		// Section 10.2 certificate, and those same 32 octets are no key at all once
		// their identifier claims the ECDH algorithm.
		it('reads no key from an EdDSA key value relabelled id-X25519', async () => {
			const spki = pemDecodeOrThrow('PUBLIC KEY', blockAt(597));
			const pkcs8 = pemDecodeOrThrow('PRIVATE KEY', blockAt(402));
			const relabelledSpki = withAlgorithmOid(spki, 0, OIDS.x25519);
			expect(await importSpkiDer(relabelledSpki)).toMatchObject({ ok: false, code: 'malformed' });
			expect(await importSpkiDer(relabelledSpki, ED25519)).toMatchObject({
				ok: false,
				code: 'malformed',
			});
			expect(await importPkcs8Der(withAlgorithmOid(pkcs8, 1, OIDS.x25519))).toMatchObject({
				ok: false,
				code: 'malformed',
			});

			const certificate = parseCertificatePemOrThrow(blockAt(717));
			expect(
				await buildCandidatePath({
					leaf: certificate.der,
					roots: [],
					trustAnchors: [
						{
							subject: certificate.issuer,
							subjectPublicKeyInfoDer: relabelledSpki,
							publicKeyAlgorithmOid: OIDS.x25519,
						},
					],
				}),
			).toMatchObject({ ok: false, code: 'unsupported_signature_algorithm_parameters' });
		});

		// The same sentence binds the builders that name a certificate as the holder
		// of a verification key. A SignerInfo and a BasicOCSPResponse each carry an
		// EdDSA signature beside the certificate that is supposed to verify it, so
		// neither may be built around the Section 10.2 certificate and its ECDH key.
		it('binds no signature to a signer certificate holding an X25519 key', async () => {
			const { issuer, subject } = await edwardsAuthority('ecdh-signer');
			const content = Uint8Array.from([0x38, 0x34, 0x31, 0x30]);
			expect(
				await createPkcs7SignedData({
					content,
					signers: [{ certificate: issuer.certificate.pem, privateKey: issuer.keyPair.privateKey }],
				}),
			).toMatchObject({ ok: true });
			expect(
				await createPkcs7SignedData({
					content,
					signers: [{ certificate: blockAt(717), privateKey: issuer.keyPair.privateKey }],
				}),
			).toMatchObject({ ok: false, code: 'signer_certificate_key_mismatch' });

			const responses = [
				{
					certificate: subject.certificate.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			] as const;
			expect(
				await createOcspResponse({
					signerPrivateKey: issuer.keyPair.privateKey,
					signerCertificate: issuer.certificate.pem,
					responses,
				}),
			).toMatchObject({ der: expect.any(Uint8Array) });
			await expectRejectedErrorCode(
				createOcspResponse({
					signerPrivateKey: issuer.keyPair.privateKey,
					signerCertificate: blockAt(717),
					responses,
				}),
				'signer_certificate_key_mismatch',
			);
		});

		// Read from the verifier's side: a CRL and an OCSP response take their
		// verification key from a certificate the caller supplies, and the Section
		// 10.2 certificate names the same issuer as the Ed25519 authority that signed
		// them. Only its ECDH subject key separates the two, and it decides the verdict.
		it('verifies no CRL or OCSP response under a certificate holding an X25519 key', async () => {
			const { issuer, subject } = await edwardsAuthority('ecdh-verifier');
			expect(parseCertificatePemOrThrow(blockAt(717)).subject.derHex).toBe(
				parseCertificatePemOrThrow(issuer.certificate.pem).subject.derHex,
			);
			const crl = await createCertificateRevocationList({
				issuer: { commonName: 'IETF Test Demo' },
				signerPrivateKey: issuer.keyPair.privateKey,
				issuerPublicKey: issuer.keyPair.publicKey,
				crlNumber: 1,
				revokedCertificates: [],
			});
			expect(
				await verifyCertificateRevocationListSignature(crl.der, issuer.certificate.pem),
			).toMatchObject({ ok: true });
			expect(await verifyCertificateRevocationListSignature(crl.der, blockAt(717))).toMatchObject({
				ok: false,
				code: 'signature_invalid',
			});

			const response = await createOcspResponse({
				signerPrivateKey: issuer.keyPair.privateKey,
				signerCertificate: issuer.certificate.pem,
				responses: [
					{
						certificate: subject.certificate.pem,
						issuerCertificate: issuer.certificate.pem,
						certStatus: 'good',
					},
				],
			});
			expect(await verifyOcspResponseSignature(response.der, issuer.certificate.pem)).toMatchObject(
				{ ok: true },
			);
			expect(await verifyOcspResponseSignature(response.der, blockAt(717))).toMatchObject({
				ok: false,
				code: 'signature_invalid',
			});
		});

		// A certificate states the application of its subject key in keyUsage, so a
		// key that cannot be used for both algorithms cannot claim both applications.
		// RFC 5280 4.2.1.3 asserts digitalSignature, nonRepudiation, keyCertSign, and
		// cRLSign over a key used to verify signatures, which an X25519 or X448 key
		// never is.
		it.each([['digitalSignature'], ['nonRepudiation'], ['keyCertSign'], ['cRLSign']] as const)(
			'does not issue an X25519 certificate whose keyUsage adds %s to keyAgreement',
			(flag) => {
				expect(
					buildErrorCode(() =>
						buildCertificateExtensions(
							X25519_SPKI,
							undefined,
							flag === 'keyCertSign'
								? { basicConstraints: { ca: true }, keyUsage: ['keyAgreement', flag] }
								: { keyUsage: ['keyAgreement', flag] },
						),
					),
				).toBe('montgomery_key_usage_forbids_signature_bit');
			},
		);

		// The same clause asserts keyAgreement over a key used for key agreement, which
		// an Ed25519 or Ed448 key never is, and leaves encipherOnly and decipherOnly
		// undefined without it.
		it.each([['keyAgreement'], ['encipherOnly'], ['decipherOnly']] as const)(
			'does not issue an Ed25519 certificate whose keyUsage adds %s to digitalSignature',
			async (flag) => {
				const spki = pemDecodeOrThrow('PUBLIC KEY', blockAt(597));
				expect(
					buildErrorCode(() =>
						buildCertificateExtensions(spki, undefined, {
							keyUsage: ['digitalSignature', flag],
						}),
					),
				).toBe('edwards_key_usage_forbids_agreement_bit');

				const signerPrivateKey = await importPkcs8PemOrThrow(blockAt(402), ED25519);
				await expectRejectedErrorCode(
					createCertificate({
						issuer: { commonName: 'IETF Test Demo' },
						subject: { commonName: 'IETF Test Demo' },
						publicKey: await importSpkiPemOrThrow(blockAt(597), ED25519),
						signerPrivateKey,
						issuerPublicKey: await derivePublicKey(signerPrivateKey),
						extensions: { keyUsage: ['digitalSignature', flag] },
					}),
					'edwards_key_usage_forbids_agreement_bit',
				);
			},
		);

		// The rule reaches only the two applications the sentence separates, so the
		// signing bits keep combining with each other.
		it('issues a certification authority certificate signing both certificates and CRLs', () => {
			expect(
				buildCertificateExtensions(pemDecodeOrThrow('PUBLIC KEY', blockAt(597)), undefined, {
					basicConstraints: { ca: true },
					keyUsage: ['digitalSignature', 'keyCertSign', 'cRLSign'],
				}),
			).toBeInstanceOf(Array);
		});

		// "The security considerations of [RFC5280], [RFC7748], and [RFC8032] apply
		// accordingly." RFC 8032 8.4: "Ed25519 and Ed448 signatures are not malleable
		// due to the verification check that decoded S is smaller than l. Without this
		// check, one can add a multiple of l into a scalar part and still pass
		// signature verification." Section 6 places signatures in structures beyond the
		// certificate, and the check binds in each of them.
		it('verifies no CRL, request, response, or signed data whose S is raised by the group order', async () => {
			const issuer = await createSelfSignedCertificate({
				subject: { commonName: 'malleability.example' },
				algorithm: ED25519,
				extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
			});
			const subject = await createSelfSignedCertificate({
				subject: { commonName: 'malleability-subject.example' },
				algorithm: ED25519,
			});
			const crl = await createCertificateRevocationList({
				issuer: { commonName: 'malleability.example' },
				signerPrivateKey: issuer.keyPair.privateKey,
				issuerPublicKey: issuer.keyPair.publicKey,
				crlNumber: 1,
				revokedCertificates: [],
			});
			const requestKeyPair = await generateKeyPair(ED25519);
			const request = await createCertificateSigningRequest({
				subject: { commonName: 'malleability-request.example' },
				publicKey: requestKeyPair.publicKey,
				signerPrivateKey: requestKeyPair.privateKey,
			});
			const response = await createOcspResponse({
				signerPrivateKey: issuer.keyPair.privateKey,
				signerCertificate: issuer.certificate.pem,
				responses: [
					{
						certificate: subject.certificate.pem,
						issuerCertificate: issuer.certificate.pem,
						certStatus: 'good',
					},
				],
			});

			const crlSignature = parseCertificateRevocationListDerOrThrow(crl.der).signatureValue;
			expect(
				await verifyCertificateRevocationListSignature(
					withSignatureValue(crl.der, bitString(crlSignature)),
					issuer.certificate.pem,
				),
			).toMatchObject({ ok: true });
			expect(
				await verifyCertificateRevocationListSignature(
					withSignatureValue(crl.der, bitString(withRaisedS(crlSignature))),
					issuer.certificate.pem,
				),
			).toMatchObject({ ok: false, code: 'signature_invalid' });

			const requestSignature = parseCertificateSigningRequestDerOrThrow(request.der).signatureValue;
			expect(
				await verifyCertificateSigningRequest(
					withSignatureValue(request.der, bitString(requestSignature)),
				),
			).toMatchObject({ ok: true });
			expect(
				await verifyCertificateSigningRequest(
					withSignatureValue(request.der, bitString(withRaisedS(requestSignature))),
				),
			).toMatchObject({ ok: false, code: 'signature_invalid' });

			const responseSignature = parseOcspResponseDerOrThrow(response.der).signatureValue;
			if (responseSignature === undefined) {
				throw new Error('OCSP response carries no signature');
			}
			expect(
				await verifyOcspResponseSignature(
					withBasicResponseSignature(response.der, responseSignature),
					issuer.certificate.pem,
				),
			).toMatchObject({ ok: true });
			expect(
				await verifyOcspResponseSignature(
					withBasicResponseSignature(response.der, withRaisedS(responseSignature)),
					issuer.certificate.pem,
				),
			).toMatchObject({ ok: false, code: 'signature_invalid' });

			const signedData = await createPkcs7SignedData({
				content: Uint8Array.from([0x38, 0x34, 0x31, 0x30]),
				signers: [{ certificate: issuer.certificate.pem, privateKey: issuer.keyPair.privateKey }],
			});
			if (!signedData.ok) {
				throw new Error(`createPkcs7SignedData failed: ${signedData.code}`);
			}
			const parsedSignedData = parsePkcs7SignedDataDer(signedData.value.der);
			if (!parsedSignedData.ok) {
				throw new Error(`parsePkcs7SignedDataDer failed: ${parsedSignedData.code}`);
			}
			const signerInfoSignature = parsedSignedData.value.signerInfos[0]?.signature;
			if (signerInfoSignature === undefined) {
				throw new Error('SignedData carries no SignerInfo');
			}
			expect(
				await verifyPkcs7SignedData(
					withSignerInfoSignature(signedData.value.der, signerInfoSignature),
				),
			).toMatchObject({ ok: true });
			expect(
				await verifyPkcs7SignedData(
					withSignerInfoSignature(signedData.value.der, withRaisedS(signerInfoSignature)),
				),
			).toMatchObject({ ok: false, code: 'signature_invalid' });
		});

		// The same import reaches RFC 8032 8.2: "EdDSA signatures are deterministic.
		// This protects against attacks arising from signing with bad randomness".
		// Nothing outside the key and the message may enter a signature, so pinning
		// every field a certificate encodes pins the 64 octets signed over it.
		it('signs one tbsCertificate twice with the same 64 octets', async () => {
			const keyPair = await generateKeyPair(ED25519);
			const input = {
				issuer: { commonName: 'deterministic.example' },
				subject: { commonName: 'deterministic.example' },
				publicKey: keyPair.publicKey,
				signerPrivateKey: keyPair.privateKey,
				serialNumber: Uint8Array.from([0x84, 0x10]),
				// Validity belongs under `validity`; left at the top level it is ignored
				// and defaults to the current time, so two calls a second apart encode
				// different UTCTime digits and nothing about determinism is tested.
				validity: {
					notBefore: new Date('2018-08-01T00:00:00Z'),
					notAfter: new Date('2028-08-01T00:00:00Z'),
				},
			} as const;
			const first = parseCertificateDerOrThrow((await createCertificate(input)).der);
			const second = parseCertificateDerOrThrow((await createCertificate(input)).der);
			expect(first.tbsCertificateDer).toEqual(second.tbsCertificateDer);
			expect(first.signatureValue).toHaveLength(64);
			expect(first.signatureValue).toEqual(second.signatureValue);

			const other = await generateKeyPair(ED25519);
			const underOtherKey = parseCertificateDerOrThrow(
				(await createCertificate({ ...input, signerPrivateKey: other.privateKey })).der,
			);
			expect(underOtherKey.tbsCertificateDer).toEqual(first.tbsCertificateDer);
			expect(underOtherKey.signatureValue).not.toEqual(first.signatureValue);
		});
	});

	describe('13. References', () => {
		/** An entry of section 13: the RFC it names, and the title it quotes for it. */
		interface ReferenceEntry {
			readonly number: number;
			readonly title: string;
		}

		/** The entries printed between two headings of section 13, their wrapped lines joined. */
		function referenceEntries(from: string, to: string): readonly ReferenceEntry[] {
			const start = lines.findIndex((line) => line.trimEnd() === from);
			const end = lines.findIndex((line) => line.trimEnd() === to);
			if (start < 0 || end < start) {
				throw new Error(`rfc8410.txt has no ${from} ... ${to} range`);
			}
			const collected: { number: number; text: string }[] = [];
			for (const line of lines.slice(start, end)) {
				const opening = /^ {3}\[RFC(\d+)] {2}(\S.*)$/.exec(line);
				const number = opening?.[1];
				const head = opening?.[2];
				if (number !== undefined && head !== undefined) {
					collected.push({ number: Number(number), text: head.trim() });
					continue;
				}
				const continuation = /^ {14}(\S.*)$/.exec(line)?.[1];
				const previous = collected[collected.length - 1];
				if (continuation !== undefined && previous !== undefined) {
					previous.text = `${previous.text} ${continuation.trim()}`;
				}
			}
			return collected.map(({ number, text }) => {
				const title = /"([^"]+)"/.exec(text)?.[1];
				if (title === undefined) {
					throw new Error(`the RFC ${number} entry of rfc8410.txt quotes no title`);
				}
				return { number, title: title.replace(/\s+/g, ' ') };
			});
		}

		/** Of `entries`, the RFC numbers whose text this repository vendors. */
		async function vendoredRfcs(entries: readonly ReferenceEntry[]): Promise<number[]> {
			const present: number[] = [];
			for (const { number } of entries) {
				if (await Bun.file(`${rfcDir}/rfc${number}.txt`).exists()) present.push(number);
			}
			return present;
		}

		/** Whether the vendored text of an entry is the document that entry names. */
		async function namesItsDocument({ number, title }: ReferenceEntry): Promise<boolean> {
			const text = (await Bun.file(`${rfcDir}/rfc${number}.txt`).text()).replace(/\s+/g, ' ');
			return text.includes(`Request for Comments: ${number} `) && text.includes(title);
		}

		/** Each entry paired with whether the file vendored for it is the document it names. */
		function identities(
			entries: readonly ReferenceEntry[],
		): Promise<readonly (readonly [number, boolean])[]> {
			return Promise.all(
				entries.map(
					async ({ number, title }) => [number, await namesItsDocument({ number, title })] as const,
				),
			);
		}

		/** The heading a line opens, if it opens one. */
		function headingAt(line: string): string | undefined {
			const match = /^(?:(\d+(?:\.\d+)*)\.|(Appendix [A-Z])\.|(Acknowledgments))(?: |$)/.exec(line);
			return match?.[1] ?? match?.[2] ?? match?.[3];
		}

		/** The RFC numbers a line cites. */
		function citedOn(line: string): number[] {
			return [...line.matchAll(/\[RFC(\d+)]/g)].flatMap(([, number]) =>
				number === undefined ? [] : [Number(number)],
			);
		}

		/** The headings of rfc8410.txt that cite a given RFC, in document order. */
		const CITING_SECTIONS: ReadonlyMap<number, readonly string[]> = (() => {
			const found = new Map<number, string[]>();
			let section = 'front matter';
			for (const line of lines) {
				section = headingAt(line) ?? section;
				for (const number of citedOn(line)) {
					const seen = found.get(number) ?? [];
					if (!seen.includes(section)) seen.push(section);
					found.set(number, seen);
				}
			}
			return found;
		})();

		/** Each entry paired with the headings that cite it. */
		function citations(
			entries: readonly ReferenceEntry[],
		): readonly (readonly [number, readonly string[]])[] {
			return entries.map(({ number }) => [number, CITING_SECTIONS.get(number) ?? []] as const);
		}

		/** The `index`-th child of a SEQUENCE. */
		function elementAt(der: Uint8Array, index: number): DerElement {
			const child = readSequenceChildren(der)[index];
			if (child === undefined) {
				throw new Error(`no child at index ${index}`);
			}
			return child;
		}

		describe('13.1. Normative References', () => {
			const NORMATIVE = referenceEntries(
				'13.1.  Normative References',
				'13.2.  Informative References',
			);

			const P256 = { kind: 'ecdsa', curve: 'P-256' } as const;

			/** The number an arc token names, whether it is written `us(840)` or `840`. */
			function arcOf(token: string): string | undefined {
				return /^\d+$/.test(token) ? token : /^[\w-]+\((\d+)\)$/.exec(token)?.[1];
			}

			/** The lines of an assignment body, from the one after its `::= {` through its `}`. */
			function bodyFrom(name: string, opening: number): readonly string[] {
				const close = rfc5480Lines.findIndex(
					(line, index) => index > opening && line.trimEnd().endsWith('}'),
				);
				if (close < 0) {
					throw new Error(`the ${name} assignment of rfc5480.txt has no closing brace`);
				}
				return rfc5480Lines.slice(opening + 1, close + 1);
			}

			/** The arcs an assignment carries, in the order it writes them. */
			function arcsFrom(name: string, opening: number): readonly string[] {
				return bodyFrom(name, opening)
					.flatMap((line) => line.replace(/}\s*$/, '').trim().split(/\s+/))
					.filter(Boolean)
					.map((token) => {
						const arc = arcOf(token);
						if (arc === undefined) {
							throw new Error(`the ${name} assignment of rfc5480.txt carries ${token}`);
						}
						return arc;
					});
			}

			/** The dotted form of every `name OBJECT IDENTIFIER ::= { arcs }` rfc5480.txt prints. */
			const RFC5480_OIDS: ReadonlyMap<string, string> = new Map(
				rfc5480Lines.flatMap((line, index) => {
					const name = /^ +(\S+) OBJECT IDENTIFIER ::= \{$/.exec(line)?.[1];
					return name === undefined ? [] : [[name, arcsFrom(name, index).join('.')] as const];
				}),
			);

			/** The OID rfc5480.txt assigns to a name, rejecting a name it assigns none. */
			function rfc5480Oid(name: string): string {
				const oid = RFC5480_OIDS.get(name);
				if (oid === undefined) {
					throw new Error(`rfc5480.txt assigns no OID to ${name}`);
				}
				return oid;
			}

			/** The curve names of RFC 5480 2.1.1.1, in the order that section publishes them. */
			const NAMED_CURVES = [...RFC5480_OIDS.keys()].filter((name) => /^sec[pt]\d/.test(name));

			/** The three of them this library implements, paired with the WebCrypto name it uses. */
			const IMPLEMENTED_CURVES = [
				['P-256', 'secp256r1'],
				['P-384', 'secp384r1'],
				['P-521', 'secp521r1'],
			] as const;

			/** The Ed25519-signed issuer and the EC leaf whose SubjectPublicKeyInfo gets rewritten. */
			async function ecLeafUnderEd25519Issuer(): Promise<{
				readonly roots: readonly string[];
				readonly der: Uint8Array;
				readonly reissue: (algorithm: Uint8Array) => Promise<Uint8Array>;
			}> {
				const issuer = await createSelfSignedCertificate({
					subject: { commonName: 'ed25519-ec-issuer.example' },
					algorithm: ED25519,
					extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
				});
				const keyPair = await generateKeyPair(P256);
				const leaf = await createCertificate({
					subject: { commonName: 'ec-domain-parameters.example' },
					issuer: { commonName: 'ed25519-ec-issuer.example' },
					publicKey: keyPair.publicKey,
					signerPrivateKey: issuer.keyPair.privateKey,
				});
				const tbs = sliceElement(leaf.der, elementAt(leaf.der, 0));
				const tbsChildren = readSequenceChildren(tbs);
				const spkiElement = tbsChildren[6];
				if (spkiElement === undefined) {
					throw new Error('tbsCertificate carries no subjectPublicKeyInfo');
				}
				const subjectPublicKey = sliceElement(
					sliceElement(tbs, spkiElement),
					elementAt(sliceElement(tbs, spkiElement), 1),
				);
				return {
					roots: [issuer.certificate.pem],
					der: leaf.der,
					reissue: async (algorithm: Uint8Array): Promise<Uint8Array> => {
						const rebuilt = sequence(
							tbsChildren.map((element, index) =>
								index === 6 ? sequence([algorithm, subjectPublicKey]) : sliceElement(tbs, element),
							),
						);
						const signature = await crypto.subtle.sign(
							{ name: 'Ed25519' },
							issuer.keyPair.privateKey,
							toArrayBuffer(rebuilt),
						);
						return sequence([
							rebuilt,
							sliceElement(leaf.der, elementAt(leaf.der, 1)),
							bitString(new Uint8Array(signature)),
						]);
					},
				};
			}

			// Every suite under test/rfc/ reads its fixtures out of docs/rfc/, so a
			// reference RFC 8410 depends on normatively has to be readable there
			// before the clause it carries can be checked against this library.
			it('vendors the text of every normative reference', async () => {
				expect(NORMATIVE.map(({ number }) => number)).toEqual([
					2119, 5280, 5480, 5958, 7748, 8032, 8174,
				]);
				expect(await vendoredRfcs(NORMATIVE)).toEqual(NORMATIVE.map(({ number }) => number));
			});

			// A file named rfcNNNN.txt is only the reference if it is the document the
			// entry titles, so each one is matched against both the number its own
			// header prints and the title RFC 8410 quotes for it.
			it('vendors, for every normative reference, the document its entry names', async () => {
				expect(NORMATIVE).toEqual([
					{ number: 2119, title: 'Key words for use in RFCs to Indicate Requirement Levels' },
					{
						number: 5280,
						title:
							'Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile',
					},
					{ number: 5480, title: 'Elliptic Curve Cryptography Subject Public Key Information' },
					{ number: 5958, title: 'Asymmetric Key Packages' },
					{ number: 7748, title: 'Elliptic Curves for Security' },
					{ number: 8032, title: 'Edwards-Curve Digital Signature Algorithm (EdDSA)' },
					{ number: 8174, title: 'Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words' },
				]);
				expect(await identities(NORMATIVE)).toEqual(NORMATIVE.map(({ number }) => [number, true]));
			});

			// An entry is bibliography; the clause it carries is asserted where RFC 8410
			// cites it, and this is where each one is cited. RFC 5480 is the exception:
			// it is normative but reaches no numbered section, so nothing else in this
			// suite is bound by it and the two tests below stand for it.
			it('cites every normative reference from a numbered section, except RFC 5480', () => {
				expect(citations(NORMATIVE)).toEqual([
					[2119, ['2', '13.1']],
					[5280, ['3', '12', '13.1', 'Acknowledgments']],
					[5480, ['13.1', 'Acknowledgments']],
					[5958, ['7', '13.1', 'Appendix A']],
					[7748, ['1', '4', '7', '12', '13.1', 'Appendix A']],
					[8032, ['1', '4', '6', '7', '12', '13.1', 'Appendix A']],
					[8174, ['2', '13.1']],
				]);
			});

			// RFC 5480 2.1.1: "The parameter for id-ecPublicKey is as follows and MUST
			// always be present", over an ECParameters whose implicitCurve (a NULL) and
			// specifiedCurve (a SEQUENCE) alternatives "MUST NOT be used in PKIX", and
			// "If the elliptic curve domain parameters are not present, then clients
			// MUST reject the certificate." This is the rule RFC 8410 3 departs from
			// for its own OIDs, whose parameters field is absent instead.
			it('accepts only a namedCurve as the ECParameters of an ecPublicKey key', async () => {
				const keyPair = await generateKeyPair(P256);
				const spki = await keyPair.exportSpkiDer();
				const subjectPublicKey = sliceElement(spki, elementAt(spki, 1));
				const withParameters = (parameters: readonly Uint8Array[]): Uint8Array =>
					sequence([
						sequence([objectIdentifier(OIDS.ecPublicKey), ...parameters]),
						subjectPublicKey,
					]);

				expect(
					await importSpkiDer(withParameters([objectIdentifier(OIDS.prime256v1)])),
				).toMatchObject({ ok: true });
				for (const parameters of [
					[],
					[nullValue()],
					[sequence([objectIdentifier(OIDS.prime256v1)])],
				]) {
					expect(await importSpkiDer(withParameters(parameters))).toMatchObject({
						ok: false,
						code: 'malformed',
					});
				}
			});

			// RFC 5480 2.2: "The first octet of the OCTET STRING indicates whether the
			// key is compressed or uncompressed. The uncompressed form is indicated by
			// 0x04 and the compressed form is indicated by either 0x02 or 0x03 [...]
			// The public key MUST be rejected if any other value is included in the
			// first octet", with "The hybrid form of the ECC public key from [X9.62]
			// MUST NOT be used" ruling out its 0x06 and 0x07.
			it('emits an uncompressed ECPoint and rejects any other leading octet', async () => {
				const keyPair = await generateKeyPair(P256);
				const spki = await keyPair.exportSpkiDer();
				const subjectPublicKey = elementAt(spki, 1);
				expect(subjectPublicKey.tag).toBe(0x03);
				expect(subjectPublicKey.value).toHaveLength(1 + 1 + 64);
				expect(subjectPublicKey.value[0]).toBe(0x00);
				expect(subjectPublicKey.value[1]).toBe(0x04);

				const algorithm = sliceElement(spki, elementAt(spki, 0));
				for (const leading of [0x00, 0x05, 0x06, 0x07]) {
					const point = Uint8Array.from(subjectPublicKey.value.slice(1));
					point[0] = leading;
					expect(await importSpkiDer(sequence([algorithm, bitString(point)]))).toMatchObject({
						ok: false,
						code: 'malformed',
					});
				}
			});

			// RFC 5480 2.1: "id-ecPublicKey indicates that the algorithms that can be
			// used with the subject public key are unrestricted [...] id-ecPublicKey
			// MUST be supported", over the OID rfc5480.txt spells
			// { iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }, and
			// 2.1.1.1 publishes "curve identifiers for the fifteen NIST-recommended
			// curves". The expected values are read out of the vendored text rather
			// than repeated here, so a wrong arc in oids.json fails this.
			it.each(IMPLEMENTED_CURVES)(
				'spells a %s key as id-ecPublicKey over the %s OID of RFC 5480 2.1.1.1',
				async (curve, name) => {
					expect(NAMED_CURVES).toHaveLength(15);
					const keyPair = await generateKeyPair({ kind: 'ecdsa', curve });
					const spki = await keyPair.exportSpkiDer();
					const identifier = readSequenceChildren(sliceElement(spki, elementAt(spki, 0)));
					const [algorithm, parameters] = identifier;
					if (algorithm === undefined || parameters === undefined) {
						throw new Error('the AlgorithmIdentifier carries no parameters');
					}
					expect(identifier).toHaveLength(2);
					expect(decodeDerOidOrThrow(algorithm)).toBe(rfc5480Oid('id-ecPublicKey'));
					expect(decodeDerOidOrThrow(parameters)).toBe(rfc5480Oid(name));
					expect(await importSpkiDer(spki)).toMatchObject({ ok: true });
				},
			);

			// The other twelve identifiers of 2.1.1.1 are curves this library does not
			// implement. RFC 5480 requires the namedCurve choice, not every curve named
			// under it, so refusing one is conformant and importing it as some other
			// curve is not.
			it('refuses every namedCurve of RFC 5480 2.1.1.1 it does not implement', async () => {
				const implemented: readonly string[] = IMPLEMENTED_CURVES.map(([, name]) => name);
				const unimplemented = NAMED_CURVES.filter((name) => !implemented.includes(name));
				expect(unimplemented).toHaveLength(12);

				const keyPair = await generateKeyPair(P256);
				const spki = await keyPair.exportSpkiDer();
				const subjectPublicKey = sliceElement(spki, elementAt(spki, 1));
				for (const name of unimplemented) {
					const foreign = sequence([
						sequence([
							objectIdentifier(rfc5480Oid('id-ecPublicKey')),
							objectIdentifier(rfc5480Oid(name)),
						]),
						subjectPublicKey,
					]);
					expect(await importSpkiDer(foreign)).toMatchObject({ ok: false, code: 'malformed' });
				}
			});

			// RFC 5480 2.1.1: "The AlgorithmIdentifier within SubjectPublicKeyInfo is
			// the only place within a certificate where the elliptic curve domain
			// parameters may be located. If the elliptic curve domain parameters are
			// not present, then clients MUST reject the certificate." implicitCurve and
			// specifiedCurve are the two other alternatives, both of which "MUST NOT be
			// used in PKIX", and neither locates a namedCurve OID either. Each rewritten
			// certificate is signed again, so the domain parameters are the only thing
			// left wrong with it.
			it.each([
				['no parameters at all', []],
				['an implicitCurve NULL', [nullValue()]],
				['a specifiedCurve SEQUENCE', [sequence([objectIdentifier(OIDS.prime256v1)])]],
			] as const)('rejects a chain whose EC leaf carries %s', async (_label, parameters) => {
				const { roots, der, reissue } = await ecLeafUnderEd25519Issuer();
				expect(await verifyCertificateChain({ leaf: der, roots })).toMatchObject({ ok: true });

				const rewritten = await reissue(
					sequence([objectIdentifier(rfc5480Oid('id-ecPublicKey')), ...parameters]),
				);
				expect(parseCertificateDerOrThrow(rewritten).publicKeyParametersOid).toBeUndefined();
				expect(await verifyCertificateChain({ leaf: rewritten, roots })).toMatchObject({
					ok: false,
					code: 'ec_domain_parameters_missing',
					index: 0,
				});
			});

			// RFC 5480 2.1: "id-ecDH indicates that the algorithm that can be used with
			// the subject public key is restricted to the Elliptic Curve Diffie-Hellman
			// algorithm [...] id-ecDH MAY be supported", and the same for id-ecMQV.
			// This library supports neither, so a key either OID identifies may not be
			// spent verifying an ECDSA signature — the identical point under
			// id-ecPublicKey is the control.
			it.each([['id-ecDH'], ['id-ecMQV']] as const)(
				'does not verify an ECDSA signature under a %s subject public key',
				async (name) => {
					const issuer = await createSelfSignedCertificate({
						subject: { commonName: 'ec-restricted-issuer.example' },
						algorithm: P256,
						extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
					});
					const keyPair = await generateKeyPair(P256);
					const leaf = await createCertificate({
						subject: { commonName: 'ec-restricted-leaf.example' },
						issuer: { commonName: 'ec-restricted-issuer.example' },
						publicKey: keyPair.publicKey,
						signerPrivateKey: issuer.keyPair.privateKey,
					});
					const parsedIssuer = parseCertificateDerOrThrow(issuer.certificate.der);
					const spki = parsedIssuer.subjectPublicKeyInfoDer;
					const anchor = (algorithmOid: string): TrustAnchor => ({
						subject: parsedIssuer.subject,
						subjectPublicKeyInfoDer: sequence([
							sequence([objectIdentifier(algorithmOid), objectIdentifier(rfc5480Oid('secp256r1'))]),
							sliceElement(spki, elementAt(spki, 1)),
						]),
						publicKeyAlgorithmOid: algorithmOid,
						publicKeyParametersOid: rfc5480Oid('secp256r1'),
					});

					expect(
						await verifyCertificateChain({
							leaf: leaf.der,
							roots: [],
							trustAnchors: [anchor(rfc5480Oid('id-ecPublicKey'))],
						}),
					).toMatchObject({ ok: true });
					expect(
						await verifyCertificateChain({
							leaf: leaf.der,
							roots: [],
							trustAnchors: [anchor(rfc5480Oid(name))],
						}),
					).toMatchObject({ ok: false, code: 'unsupported_signature_algorithm_parameters' });
				},
			);
		});

		describe('13.2. Informative References', () => {
			const INFORMATIVE = referenceEntries(
				'13.2.  Informative References',
				'Appendix A.  Invalid Encodings',
			);

			/** The 1-based line of every BEGIN boundary rfc8410.txt prints. */
			const BLOCK_LINES = lines.flatMap((line, index) =>
				line.trim().startsWith('-----BEGIN ') ? [index + 1] : [],
			);

			/** The label the BEGIN line of the block at a 1-based line carries. */
			function labelAt(start: number): string {
				const label = /^-----BEGIN (.*)-----$/.exec(blockAt(start).split('\n')[0] ?? '')?.[1];
				if (label === undefined) {
					throw new Error(`rfc8410.txt:${start} carries no label`);
				}
				return label;
			}

			/** Whether the block beginning at a 1-based line decodes under this library. */
			function decodes(start: number): boolean {
				try {
					pemDecodeOrThrow(labelAt(start), blockAt(start));
					return true;
				} catch {
					return false;
				}
			}

			/** The widths of the base64 lines of a printing, its two boundaries dropped. */
			function bodyWidths(text: string): readonly number[] {
				return text
					.trimEnd()
					.split('\n')
					.slice(1, -1)
					.map((line) => line.length);
			}

			// RFC 7468 is cited in 4 and 7 as the textual encoding the examples there
			// are printed in, and RFC 8411 in 11 as the registry the OIDs are
			// recorded in, so both are read as fixtures by this suite even though
			// they are classified informative.
			it('vendors the text of every informative reference', async () => {
				expect(INFORMATIVE.map(({ number }) => number)).toEqual([3279, 4055, 5639, 7468, 8411]);
				expect(await vendoredRfcs(INFORMATIVE)).toEqual(INFORMATIVE.map(({ number }) => number));
			});

			// Matched against number and title, as in 13.1.
			it('vendors, for every informative reference, the document its entry names', async () => {
				expect(INFORMATIVE).toEqual([
					{
						number: 3279,
						title:
							'Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile',
					},
					{
						number: 4055,
						title:
							'Additional Algorithms and Identifiers for RSA Cryptography for use in the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile',
					},
					{
						number: 5639,
						title:
							'Elliptic Curve Cryptography (ECC) Brainpool Standard Curves and Curve Generation',
					},
					{ number: 7468, title: 'Textual Encodings of PKIX, PKCS, and CMS Structures' },
					{
						number: 8411,
						title: 'IANA Registration for the Cryptographic Algorithm Object Identifier Range',
					},
				]);
				expect(await identities(INFORMATIVE)).toEqual(
					INFORMATIVE.map(({ number }) => [number, true]),
				);
			});

			// RFC 3279, RFC 4055 and RFC 5639 reach no numbered section: Acknowledgments
			// names them as documents text was drawn from, which binds this library to
			// nothing. RFC 7468 and RFC 8411 do reach one, and the clause each carries
			// is asserted at 4 and 7, and at 11, respectively.
			it('cites only RFC 7468 and RFC 8411 from a numbered section', () => {
				expect(citations(INFORMATIVE)).toEqual([
					[3279, ['13.2', 'Acknowledgments']],
					[4055, ['13.2', 'Acknowledgments']],
					[5639, ['13.2', 'Acknowledgments']],
					[7468, ['4', '7', '13.2']],
					[8411, ['11', '13.2']],
				]);
			});

			// 4: "The following is an example of a public key encoded using the textual
			// encoding defined in [RFC7468]." 7 says the same of the private key it
			// prints and, for the annotated one after it, "the textual encoding defined
			// in [RFC7468] is used". Ten of the eleven blocks printed decode; the
			// eleventh closes on a sixth hyphen, which RFC 7468 3 does not admit, since
			// its posteb is "-----END " label "-----" over a label whose ABNF ends on a
			// labelchar and never on a hyphen-minus.
			it('decodes every block printed but the one whose END line carries a sixth hyphen', () => {
				expect(BLOCK_LINES).toEqual([248, 402, 410, 597, 717, 739, 765, 991, 1002, 1019, 1024]);
				expect(BLOCK_LINES.map((start) => [start, decodes(start)])).toEqual(
					BLOCK_LINES.map((start) => [start, start !== 410]),
				);

				expect(lines[413]?.trim()).toBe('-----END PRIVATE KEY------');
				const repaired = blockAt(410).replace(
					'-----END PRIVATE KEY------',
					'-----END PRIVATE KEY-----',
				);
				expect(pemDecodeOrThrow('PRIVATE KEY', repaired)).toEqual(
					pemDecodeOrThrow('PRIVATE KEY', blockAt(765)),
				);
			});

			// RFC 7468 2: "Generators MUST wrap the base64-encoded lines so that each
			// line consists of exactly 64 characters except for the final line, which
			// will encode the remainder of the data (within the 64-character line
			// boundary), and they MUST NOT emit extraneous whitespace. Parsers MAY
			// handle other line sizes." Half of the blocks that decode are printed
			// wider than 64, so reading them exercises the parser allowance, and
			// RFC 7468 3 asks new implementations to "emit the strict format
			// (Figure 3)", whose base64fullline is 64base64char. The widths are read
			// out of the vendored text, so a re-wrap that loses or pads a line fails.
			it('reads the wider lines the document prints and re-emits every block at 64', () => {
				const decodable = BLOCK_LINES.filter((start) => start !== 410);
				expect(decodable.map((start) => bodyWidths(blockAt(start)))).toEqual([
					[60],
					[64],
					[60],
					[66, 66, 66, 66, 66, 66, 12],
					[64],
					[64, 64, 28],
					[65, 7],
					[66, 50],
					[66, 46],
					[66, 46],
				]);

				const reprinted = decodable.map((start) => {
					const label = labelAt(start);
					const der = pemDecodeOrThrow(label, blockAt(start));
					const text = pemEncode(label, der);
					expect(pemDecodeOrThrow(label, text)).toEqual(der);
					return [start, text] as const;
				});

				for (const [start, text] of reprinted) {
					const widths = bodyWidths(text);
					expect([start, widths.slice(0, -1)]).toEqual([start, widths.slice(0, -1).map(() => 64)]);
					expect([start, widths[widths.length - 1] ?? 0]).toEqual([
						start,
						Math.min(widths[widths.length - 1] ?? 0, 64),
					]);
				}

				expect(
					reprinted.flatMap(([start, text]) => (text.trimEnd() === blockAt(start) ? [start] : [])),
				).toEqual([248, 402, 597, 739, 765]);
			});

			// Section 13 is where a citation resolves, so every [RFCnnnn] the document
			// prints reaches exactly one entry: the seven of 13.1, or these five.
			// Nothing else pins that, since both lists are read out of their own
			// heading range rather than compared against what the body cites.
			it('carries every reference the document makes that 13.1 does not', () => {
				const normative = referenceEntries(
					'13.1.  Normative References',
					'13.2.  Informative References',
				).map(({ number }) => number);
				const informative = INFORMATIVE.map(({ number }) => number);
				const cited = [...CITING_SECTIONS.keys()].sort((left, right) => left - right);

				expect(cited).toHaveLength(12);
				expect([...normative, ...informative].sort((left, right) => left - right)).toEqual(cited);
				expect(informative.filter((number) => normative.includes(number))).toEqual([]);
			});
		});
	});

	describe('Appendix A. Invalid Encodings', () => {
		/** The 7 first example: the DER printing of the key rfc8410.txt:991 prints in BER. */
		const DER_PRIVATE_KEY = pemDecodeOrThrow('PRIVATE KEY', blockAt(402));

		/** The 7 second example, its END boundary repaired, carrying an attribute and the public key. */
		const V2_PRIVATE_KEY = pemDecodeOrThrow(
			'PRIVATE KEY',
			blockAt(410).replace('-----END PRIVATE KEY------', '-----END PRIVATE KEY-----'),
		);

		/** The child at `index` of a SEQUENCE. */

		/** The `attributes [0]` element of the 7 second example. */
		const ATTRIBUTES = sliceElement(V2_PRIVATE_KEY, fieldAt(V2_PRIVATE_KEY, 3));

		/** The 32 public key octets of the 7 second example. */
		const PUBLIC_KEY = fieldAt(V2_PRIVATE_KEY, 4).value.slice(1);

		/** `publicKey [1]`: an IMPLICIT primitive BIT STRING whose first octet counts the unused bits. */
		function publicKeyField(key: Uint8Array): Uint8Array {
			return implicitPrimitiveContext(1, Uint8Array.from([0x00, ...key]));
		}

		/**
		 * An INTEGER carrying the content octets given, minimal or not.
		 *
		 * `integer()` strips the redundant leading zeros DER forbids, which is what
		 * these cases are about, so the element is laid out by hand.
		 */
		function versionElement(content: readonly number[]): Uint8Array {
			return Uint8Array.from([0x02, content.length, ...content]);
		}

		/** A OneAsymmetricKey over the 7 example private key, with a chosen version element and tail. */
		function oneAsymmetricKeyVersioned(
			version: Uint8Array,
			tail: readonly Uint8Array[],
		): Uint8Array {
			return sequence([
				version,
				sliceElement(V2_PRIVATE_KEY, fieldAt(V2_PRIVATE_KEY, 1)),
				sliceElement(V2_PRIVATE_KEY, fieldAt(V2_PRIVATE_KEY, 2)),
				...tail,
			]);
		}

		/** A OneAsymmetricKey over the 7 example private key, with a chosen version and tail. */
		function oneAsymmetricKey(version: number, tail: readonly Uint8Array[]): Uint8Array {
			return oneAsymmetricKeyVersioned(integer(Uint8Array.of(version)), tail);
		}

		// "As stated in [RFC5958], BER decoding of OneAsymmetricKey objects is a
		// requirement for compliance. Despite this requirement, some acceptors will
		// only decode DER formats. The following is a BER encoding of a private key;
		// it is valid, but it may not be accepted by many systems." The block wraps
		// the 7 example private key in indefinite-length SEQUENCEs, and this library
		// is one of the acceptors that reads DER only.
		it('rejects the BER printing of the key it accepts in DER', async () => {
			const ber = pemDecodeOrThrow('PRIVATE KEY', blockAt(991));
			expect(ber.slice(0, 14)).toEqual(
				Uint8Array.from([
					0x30, 0x80, 0x02, 0x01, 0x00, 0x30, 0x80, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x00, 0x00,
				]),
			);
			expect(ber.slice(-2)).toEqual(Uint8Array.of(0x00, 0x00));
			expect(sliceElement(DER_PRIVATE_KEY, fieldAt(DER_PRIVATE_KEY, 2))).toEqual(ber.slice(14, -2));

			expect(await importPkcs8Der(ber, ED25519)).toMatchObject({ ok: false, code: 'malformed' });
			expect(await importPkcs8Der(ber)).toMatchObject({ ok: false, code: 'malformed' });
			expect(await importPkcs8Der(DER_PRIVATE_KEY, ED25519)).toMatchObject({ ok: true });
		});

		// "First, the use of an OCTET STRING rather than a BIT STRING for the public
		// key. The use of OCTET STRING was a copy error that existed in a previous
		// draft version of this document; the structure is correct in [RFC5958].
		// However, any early implementation may have this wrong."
		it('rejects a SubjectPublicKeyInfo whose subjectPublicKey is an OCTET STRING', async () => {
			const spki = pemDecodeOrThrow('PUBLIC KEY', blockAt(597));
			expect(fieldAt(spki, 1).tag).toBe(0x03);
			const copyError = sequence([
				sliceElement(spki, fieldAt(spki, 0)),
				octetString(fieldAt(spki, 1).value.slice(1)),
			]);

			expect(await importSpkiDer(copyError, ED25519)).toMatchObject({
				ok: false,
				code: 'malformed',
			});
			expect(await importSpkiDer(spki, ED25519)).toMatchObject({ ok: true });
		});

		// The same copy error inside a certificate. 4: "In the X.509 certificate, the
		// subjectPublicKeyInfo field has the SubjectPublicKeyInfo type", so the
		// certificate parse reads the subject key under the same BIT STRING.
		it('rejects a certificate whose subjectPublicKey is an OCTET STRING', () => {
			const certificate = parseCertificatePemOrThrow(blockAt(717));
			const tbsDer = certificate.tbsCertificateDer;
			const tbsChildren = readSequenceChildren(tbsDer);
			const spkiIndex = tbsChildren[0]?.tag === 0xa0 ? 6 : 5;
			const spkiDer = sliceElement(tbsDer, fieldAt(tbsDer, spkiIndex));
			expect(fieldAt(spkiDer, 1).tag).toBe(0x03);
			const copyError = sequence([
				sliceElement(spkiDer, fieldAt(spkiDer, 0)),
				octetString(fieldAt(spkiDer, 1).value.slice(1)),
			]);
			const mutated = sequence([
				sequence(
					tbsChildren.map((child, index) =>
						index === spkiIndex ? copyError : sliceElement(tbsDer, child),
					),
				),
				sliceElement(certificate.der, fieldAt(certificate.der, 1)),
				sliceElement(certificate.der, fieldAt(certificate.der, 2)),
			]);

			expect(parseCertificateDer(mutated)).toMatchObject({ ok: false, code: 'malformed' });
			expect(parseCertificateDer(certificate.der)).toMatchObject({ ok: true });
		});

		// The same copy error inside a OneAsymmetricKey. 7 gives "publicKey [1]
		// IMPLICIT PublicKey OPTIONAL" over "PublicKey ::= BIT STRING", so the field's
		// octets open with the count of unused bits; an OCTET STRING body omits it.
		it('rejects a publicKey [1] field that omits the BIT STRING unused-bit count', async () => {
			expect(
				await importPkcs8Der(
					oneAsymmetricKey(1, [ATTRIBUTES, implicitPrimitiveContext(1, PUBLIC_KEY)]),
					ED25519,
				),
			).toMatchObject({ ok: false, code: 'malformed' });
			expect(
				await importPkcs8Der(
					oneAsymmetricKey(1, [ATTRIBUTES, publicKeyField(PUBLIC_KEY)]),
					ED25519,
				),
			).toMatchObject({ ok: true });
		});

		// "Second, the value of the version field is required to be 0 if the publicKey
		// is absent and 1 if present. This is called out in [RFC5958], but was not
		// duplicated above." RFC 5958 2: "If publicKey is present, then version is set
		// to v2 else version is set to v1", over "Version ::= INTEGER { v1(0), v2(1) }",
		// so an attribute alone leaves the version at v1.
		it('requires version 0 when publicKey is absent and version 1 when it is present', async () => {
			const withPublicKey = [ATTRIBUTES, publicKeyField(PUBLIC_KEY)];

			expect(await importPkcs8Der(oneAsymmetricKey(0, []), ED25519)).toMatchObject({ ok: true });
			expect(await importPkcs8Der(oneAsymmetricKey(0, [ATTRIBUTES]), ED25519)).toMatchObject({
				ok: true,
			});
			expect(await importPkcs8Der(oneAsymmetricKey(1, withPublicKey), ED25519)).toMatchObject({
				ok: true,
			});

			expect(await importPkcs8Der(oneAsymmetricKey(1, []), ED25519)).toMatchObject({
				ok: false,
				code: 'malformed',
			});
			expect(await importPkcs8Der(oneAsymmetricKey(1, [ATTRIBUTES]), ED25519)).toMatchObject({
				ok: false,
				code: 'malformed',
			});
			expect(await importPkcs8Der(oneAsymmetricKey(0, withPublicKey), ED25519)).toMatchObject({
				ok: false,
				code: 'malformed',
			});
		});

		// The version field is "required to be 0 ... and 1", and RFC 5958 2 spells the
		// two out as "Version ::= INTEGER { v1(0), v2(1) } (v1, ..., v2)". A third
		// value names no version of the type, and neither does a second octet of
		// padding in front of one that does.
		it.each([
			['2, which the type does not name', versionElement([0x02])],
			['-1, which the type does not name', versionElement([0xff])],
			['0 padded to two octets', versionElement([0x00, 0x00])],
			['1 padded to two octets', versionElement([0x00, 0x01])],
		])('rejects a OneAsymmetricKey whose version is %s', async (_label, version) => {
			expect(
				await importPkcs8Der(oneAsymmetricKeyVersioned(versionElement([0x00]), []), ED25519),
			).toMatchObject({ ok: true });
			expect(
				await importPkcs8Der(
					oneAsymmetricKeyVersioned(versionElement([0x01]), [
						ATTRIBUTES,
						publicKeyField(PUBLIC_KEY),
					]),
					ED25519,
				),
			).toMatchObject({ ok: true });

			expect(await importPkcs8Der(oneAsymmetricKeyVersioned(version, []), ED25519)).toMatchObject({
				ok: false,
				code: 'malformed',
			});
			expect(
				await importPkcs8Der(
					oneAsymmetricKeyVersioned(version, [ATTRIBUTES, publicKeyField(PUBLIC_KEY)]),
					ED25519,
				),
			).toMatchObject({ ok: false, code: 'malformed' });
		});

		// "Key mismatch errors: If a public key is provided, it may not agree with the
		// private key because either it is wrong or the wrong algorithm was used." The
		// 10.2 certificate carries a different key, and an X25519 one, of which 12
		// says "the same public key cannot be used for both ECDH and EdDSA".
		it('rejects a publicKey [1] field that is not the public key of the privateKey', async () => {
			const certificateSpki = parseCertificatePemOrThrow(blockAt(717)).subjectPublicKeyInfoDer;
			const x25519 = fieldAt(certificateSpki, 1).value.slice(1);
			expect(x25519).not.toEqual(PUBLIC_KEY);

			expect(
				await importPkcs8Der(oneAsymmetricKey(1, [publicKeyField(x25519)]), ED25519),
			).toMatchObject({ ok: false, code: 'malformed' });
			expect(
				await importPkcs8Der(oneAsymmetricKey(1, [publicKeyField(PUBLIC_KEY)]), ED25519),
			).toMatchObject({ ok: true });
		});

		// "What follows here is a brief sampling of some incorrect keys." Every sample
		// prints publicKey [1] as a constructed [1] holding a BIT STRING, where 7
		// gives "publicKey [1] IMPLICIT PublicKey OPTIONAL".
		it.each([1002, 1019, 1024])(
			'rejects the sample key at rfc8410.txt:%i, which tags publicKey [1] explicitly',
			async (line) => {
				const der = pemDecodeOrThrow('PRIVATE KEY', blockAt(line));
				const declared = fieldAt(der, 3);
				expect(declared.tag).toBe(0xa1);
				expect(readRootElement(declared.value).tag).toBe(0x03);

				expect(await importPkcs8Der(der, ED25519)).toMatchObject({ ok: false, code: 'malformed' });
				expect(await importPkcs8Der(der)).toMatchObject({ ok: false, code: 'malformed' });
			},
		);

		// "In the following examples, the key is the wrong length because an all-zero
		// byte has been removed. In one case, the first byte has been removed; in the
		// other case, the last byte has been removed." RFC 8032 5.1.5 sizes an Ed25519
		// public key at 32 octets, so restoring the removed byte is what makes each
		// sample agree with the private key it is printed beside.
		it.each([
			[1019, 'leading'],
			[1024, 'trailing'],
		] as const)(
			'rejects the 31-octet public key at rfc8410.txt:%i until its %s zero byte is restored',
			async (line, position) => {
				const der = pemDecodeOrThrow('PRIVATE KEY', blockAt(line));
				const truncated = readRootElement(fieldAt(der, 3).value).value.slice(1);
				expect(truncated).toHaveLength(31);
				const restored =
					position === 'leading'
						? Uint8Array.from([0x00, ...truncated])
						: Uint8Array.from([...truncated, 0x00]);

				const sample = (key: Uint8Array): Uint8Array =>
					sequence([
						integer(Uint8Array.of(1)),
						sliceElement(der, fieldAt(der, 1)),
						sliceElement(der, fieldAt(der, 2)),
						publicKeyField(key),
					]);

				expect(await importPkcs8Der(sample(truncated), ED25519)).toMatchObject({
					ok: false,
					code: 'malformed',
				});
				expect(await importPkcs8Der(sample(restored), ED25519)).toMatchObject({ ok: true });
			},
		);

		// "Key encoding errors: Both [RFC7748] and [RFC8032] have formatting
		// requirements for keys that need to be enforced." The sample at
		// rfc8410.txt:1002 is X25519, whose scalar RFC 7748 5 decodes with
		// "k_list[0] &= 248; k_list[31] &= 127; k_list[31] |= 64". "For this example,
		// the top bits are set to zero and the bottom three bits are set to 001": the
		// last octet is the one that departs, the first already clearing its low three
		// bits. This library imports no X25519 private key at all, so the sample is
		// refused before its scalar is read.
		it('does not import the X25519 sample key, whose scalar is not clamped', async () => {
			const der = pemDecodeOrThrow('PRIVATE KEY', blockAt(1002));
			const algorithm = sliceElement(der, fieldAt(der, 1));
			expect(decodeDerOidOrThrow(fieldAt(algorithm, 0))).toBe(OIDS.x25519);
			const scalar = readRootElement(fieldAt(der, 2).value).value;
			expect(scalar).toHaveLength(32);
			const clamped = Uint8Array.from(scalar);
			clamped[0] = (clamped[0] ?? 0) & 248;
			clamped[31] = ((clamped[31] ?? 0) & 127) | 64;
			expect(clamped).not.toEqual(scalar);
			expect(clamped.slice(0, 31)).toEqual(scalar.slice(0, 31));
			expect(scalar.slice(31)).toEqual(Uint8Array.of(0x3f));
			expect(clamped.slice(31)).toEqual(Uint8Array.of(0x7f));

			const wellFormed = sequence([
				integer(Uint8Array.of(1)),
				algorithm,
				sliceElement(der, fieldAt(der, 2)),
				publicKeyField(readRootElement(fieldAt(der, 3).value).value.slice(1)),
			]);
			expect(await importPkcs8Der(wellFormed, ED25519)).toMatchObject({
				ok: false,
				code: 'malformed',
			});
			expect(await importPkcs8Der(wellFormed)).toMatchObject({ ok: false, code: 'malformed' });
		});
	});

	describe('Acknowledgments', () => {
		const P256 = { kind: 'ecdsa', curve: 'P-256' } as const;
		const RSA = { kind: 'rsa', modulusLength: 2048 } as const;

		/** The arc RFC 8411 1 records as donated, and the PKIX arc it was donated to undercut. */
		const DONATED_ARC = '1.3.101';
		const PKIX_ARC = '1.3.6.1.5.5.7';

		/** The lines of the section, from its heading through the one before Authors' Addresses. */
		const ACKNOWLEDGMENTS = (() => {
			const start = lines.indexOf('Acknowledgments');
			const end = lines.indexOf("Authors' Addresses");
			if (start < 0 || end < start) {
				throw new Error("rfc8410.txt has no Acknowledgments ... Authors' Addresses range");
			}
			return lines.slice(start, end);
		})();

		/** The RFCs the section names, in the order it names them. */
		const DRAWN_FROM = ACKNOWLEDGMENTS.flatMap((line) =>
			[...line.matchAll(/\[RFC(\d+)]/g)].flatMap(([, number]) =>
				number === undefined ? [] : [Number(number)],
			),
		);

		/**
		 * The dotted OID rfc5639.txt assigns to a name in its Section 4.1.
		 *
		 * An assignment body carries numeric arcs, `label(number)` arcs, and the name of
		 * a shorter assignment, which resolves through this function again.
		 */
		function rfc5639Oid(name: string): string {
			const body = new RegExp(`(?:^| )${name} OBJECT IDENTIFIER ?::= ?\\{([^}]*)\\}`).exec(
				rfc5639Text,
			)?.[1];
			if (body === undefined) {
				throw new Error(`rfc5639.txt assigns no OID to ${name}`);
			}
			return body
				.trim()
				.split(' ')
				.map((token) => {
					const numeric = /^\d+$/.exec(token)?.[0];
					if (numeric !== undefined) return numeric;
					const labelled = /^[\w-]+\((\d+)\)$/.exec(token)?.[1];
					return labelled ?? rfc5639Oid(token);
				})
				.join('.');
		}

		/** The Brainpool curve names of RFC 5639 4.1, in the order that section assigns them. */
		const BRAINPOOL_CURVES = [
			...rfc5639Text.matchAll(/(brainpoolP\w+) OBJECT IDENTIFIER/g),
		].flatMap(([, name]) => (name === undefined ? [] : [name]));

		/** The `index`-th child of a SEQUENCE. */

		/** The subjectPublicKey BIT STRING of a SubjectPublicKeyInfo, as its own DER element. */
		function subjectPublicKeyOf(spki: Uint8Array): Uint8Array {
			return childAt(spki, 1);
		}

		/** The same key bits under an AlgorithmIdentifier naming `oid` with `parameters`. */
		function keyUnder(
			oid: string,
			parameters: readonly Uint8Array[],
			subjectPublicKey: Uint8Array,
		): Uint8Array {
			return sequence([sequence([objectIdentifier(oid), ...parameters]), subjectPublicKey]);
		}

		/** A CA certificate signed with RSA PKCS#1 v1.5 and SHA-256, and the key that signed it. */
		let rsaIssuer:
			| Promise<{ readonly keyPair: CryptoKeyPair; readonly pem: string; readonly der: Uint8Array }>
			| undefined;

		function issuer(): Promise<{
			readonly keyPair: CryptoKeyPair;
			readonly pem: string;
			readonly der: Uint8Array;
		}> {
			rsaIssuer ??= (async () => {
				const created = await createSelfSignedCertificate({
					subject: { commonName: 'rsa-pkcs1-issuer.example' },
					algorithm: RSA,
					extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
				});
				return {
					keyPair: created.keyPair,
					pem: created.certificate.pem,
					der: created.certificate.der,
				};
			})();
			return rsaIssuer;
		}

		/**
		 * An Ed25519 leaf under that issuer, its two signature AlgorithmIdentifiers
		 * carrying `parameters` and its tbsCertificate signed again over them.
		 *
		 * RFC 5280 4.1.1.2 binds the outer signatureAlgorithm to the tbsCertificate
		 * signature field, so both carry the same encoding and the parameters are the
		 * only thing left that can decide the verdict.
		 */
		async function leafSignedWith(parameters: readonly Uint8Array[]): Promise<Uint8Array> {
			const { keyPair } = await issuer();
			const subject = await generateKeyPair(ED25519);
			const leaf = await createCertificate({
				subject: { commonName: 'rsa-signed-leaf.example' },
				issuer: { commonName: 'rsa-pkcs1-issuer.example' },
				publicKey: subject.publicKey,
				signerPrivateKey: keyPair.privateKey,
			});
			const algorithm = sequence([objectIdentifier(OIDS.sha256WithRSAEncryption), ...parameters]);
			const tbs = childAt(leaf.der, 0);
			const tbsChildren = readSequenceChildren(tbs);
			const signatureIndex = tbsChildren[0]?.tag === 0xa0 ? 2 : 1;
			const rebuilt = sequence(
				tbsChildren.map((child, index) =>
					index === signatureIndex ? algorithm : sliceElement(tbs, child),
				),
			);
			const signature = await crypto.subtle.sign(
				{ name: 'RSASSA-PKCS1-v1_5' },
				keyPair.privateKey,
				toArrayBuffer(rebuilt),
			);
			return sequence([rebuilt, algorithm, bitString(new Uint8Array(signature))]);
		}

		// "Text and/or inspiration were drawn from [RFC5280], [RFC3279], [RFC4055],
		// [RFC5480], and [RFC5639]." Those five are where the conventions this library
		// keeps for the algorithms RFC 8410 does not define are written, and the tests
		// below read their clauses out of the vendored text.
		it('draws its text from five documents this repository vendors', async () => {
			expect(DRAWN_FROM).toEqual([5280, 3279, 4055, 5480, 5639]);
			expect(
				await Promise.all(
					DRAWN_FROM.map(async (number) => [
						number,
						await Bun.file(`${rfcDir}/rfc${number}.txt`).exists(),
					]),
				),
			).toEqual(DRAWN_FROM.map((number) => [number, true]));
		});

		// Each document sets its own convention for the parameters field, and RFC 8410 3
		// departs from all of them: RFC 3279 2.3.1, "The parameters field MUST have ASN.1
		// type NULL for this algorithm identifier", repeated by RFC 4055 1.2 as "the
		// rsaEncryption object identifier MUST be used in the algorithm field within the
		// subject public key information, and the parameters field MUST contain NULL";
		// RFC 5480 2.1.1, "The parameter for id-ecPublicKey is as follows and MUST always
		// be present"; RFC 8410 3, "For all of the OIDs, the parameters MUST be absent."
		// Each key carries the bits its own generator produced, so the parameters field
		// is the only thing that differs across a row.
		it('keeps the parameters convention of every document it drew text from', async () => {
			const rsa = await generateKeyPair(RSA);
			const ec = await generateKeyPair(P256);
			const ed = await generateKeyPair(ED25519);
			const keys = [
				[OIDS.rsaEncryption, subjectPublicKeyOf(await rsa.exportSpkiDer()), 'NULL'],
				[OIDS.ecPublicKey, subjectPublicKeyOf(await ec.exportSpkiDer()), 'namedCurve'],
				[OIDS.ed25519, subjectPublicKeyOf(await ed.exportSpkiDer()), 'absent'],
			] as const;
			const forms = [
				['absent', []],
				['NULL', [nullValue()]],
				['namedCurve', [objectIdentifier(OIDS.prime256v1)]],
			] as const;

			for (const [oid, subjectPublicKey, accepted] of keys) {
				for (const [form, parameters] of forms) {
					const result = await importSpkiDer(keyUnder(oid, parameters, subjectPublicKey));
					expect([oid, form, result.ok]).toEqual([oid, form, form === accepted]);
					if (!result.ok) {
						expect(result.code).toBe('malformed');
					}
				}
			}
		});

		// RFC 4055 5, over sha224WithRSAEncryption, sha256WithRSAEncryption,
		// sha384WithRSAEncryption, and sha512WithRSAEncryption: "When any of these four
		// object identifiers appears within an AlgorithmIdentifier, the parameters MUST
		// be NULL. Implementations MUST accept the parameters being absent as well as
		// present." RFC 5280 1 binds this library to that clause: "conforming
		// implementations that use the algorithms identified in [RFC3279], [RFC4055],
		// and [RFC4491] MUST identify and encode the public key materials and digital
		// signatures as described in those specifications." An INTEGER is neither
		// encoding and stays rejected.
		it('verifies a PKCS#1 v1.5 chain whose signature parameters are absent', async () => {
			const { pem, der } = await issuer();
			const roots = [pem];
			expect(parseCertificateDerOrThrow(der).signatureAlgorithmParametersDer).toEqual(nullValue());

			const withNull = await leafSignedWith([nullValue()]);
			expect(parseCertificateDerOrThrow(withNull).signatureAlgorithmParametersDer).toEqual(
				nullValue(),
			);
			expect(await verifyCertificateChain({ leaf: withNull, roots })).toMatchObject({ ok: true });

			const absent = await leafSignedWith([]);
			expect(parseCertificateDerOrThrow(absent).signatureAlgorithmParametersDer).toBeUndefined();
			expect(await verifyCertificateChain({ leaf: absent, roots })).toMatchObject({ ok: true });

			const integerParameters = await leafSignedWith([integer(Uint8Array.of(0))]);
			expect(await verifyCertificateChain({ leaf: integerParameters, roots })).toMatchObject({
				ok: false,
				code: 'unsupported_signature_algorithm_parameters',
			});
		});

		// RFC 5639 4.1 assigns fourteen curve OIDs, and 4.2 spends them the way RFC 5480
		// does: "the field algorithm.parameter of subjectPublicKeyInfo MUST be of type
		// [...] namedCurve to specify the domain parameters by one of the Object
		// Identifiers (OIDs) defined in Section 4.1". This library implements none of
		// them, so each one is refused rather than read as the NIST curve of its size,
		// and none of them earns the name of one. The OIDs are resolved out of the
		// vendored text, so a wrong arc fails this.
		it('reads no key named by a Brainpool curve of RFC 5639 4.1', async () => {
			expect(BRAINPOOL_CURVES).toHaveLength(14);
			expect(BRAINPOOL_CURVES.map(rfc5639Oid)).toEqual(
				BRAINPOOL_CURVES.map((_name, index) => `1.3.36.3.3.2.8.1.1.${index + 1}`),
			);

			const ec = await generateKeyPair(P256);
			const subjectPublicKey = subjectPublicKeyOf(await ec.exportSpkiDer());
			for (const name of BRAINPOOL_CURVES) {
				const oid = rfc5639Oid(name);
				expect(Object.values(OIDS)).not.toContain(oid);
				expect(
					await importSpkiDer(
						keyUnder(OIDS.ecPublicKey, [objectIdentifier(oid)], subjectPublicKey),
					),
				).toMatchObject({ ok: false, code: 'malformed' });
				expect(describePublicKeyAlgorithm(OIDS.ecPublicKey, oid)).toBe('EC');
			}
		});

		// "A big thank you to Symantec for kindly donating the OIDs used in this
		// document." RFC 8411 1 says what the donation bought: it "allowed for shorter
		// values than would be possible using the existing S/MIME or PKIX arcs", the
		// range being { 1 3 101 100 } through { 1 3 101 127 }. Three arcs encode to three
		// octets, so an identifier of this document is shorter than the bare PKIX arc
		// before that arc has named anything, and shorter still than the RSA and EC
		// identifiers, which carry parameters as well.
		it('spends fewer octets on a donated identifier than the PKIX arc could', () => {
			expect(OIDS.ed25519.startsWith(`${DONATED_ARC}.`)).toBe(true);
			expect(objectIdentifier(OIDS.ed25519)).toHaveLength(5);
			expect(objectIdentifier(PKIX_ARC)).toHaveLength(8);
			const underPkix = Object.values(OIDS).filter((oid) => oid.startsWith(`${PKIX_ARC}.`));
			expect(underPkix.length).toBeGreaterThan(0);
			for (const oid of underPkix) {
				expect([oid, objectIdentifier(oid).length > 5]).toEqual([oid, true]);
			}

			expect(sequence([objectIdentifier(OIDS.ed25519)])).toHaveLength(7);
			expect(sequence([objectIdentifier(OIDS.rsaEncryption), nullValue()])).toHaveLength(15);
			expect(
				sequence([objectIdentifier(OIDS.ecPublicKey), objectIdentifier(OIDS.prime256v1)]),
			).toHaveLength(21);
		});
	});

	describe("Authors' Addresses", () => {
		/** One author, as the three lines the section spends on them spell it. */
		interface Author {
			readonly name: string;
			readonly organization: string;
			readonly email: string;
		}

		/** The authors the section names, in the order it names them. */
		const AUTHORS: readonly Author[] = (() => {
			const start = lines.indexOf("Authors' Addresses");
			if (start < 0) {
				throw new Error("rfc8410.txt has no Authors' Addresses heading");
			}
			const body = lines
				.slice(start + 1)
				.map((line) => line.trim())
				.filter((line) => line.length > 0 && !/\[Page \d+]$/.test(line));
			if (body.length === 0 || body.length % 3 !== 0) {
				throw new Error(
					`rfc8410.txt spends ${body.length} lines on its authors, not a multiple of 3`,
				);
			}
			return Array.from({ length: body.length / 3 }, (_unused, index) => {
				const [name, organization, email] = body.slice(index * 3, index * 3 + 3);
				const address = email === undefined ? undefined : /^Email: (\S+)$/.exec(email)?.[1];
				if (name === undefined || organization === undefined || address === undefined) {
					throw new Error(
						`rfc8410.txt author ${String(index)} has no name, organization, and Email line`,
					);
				}
				return { name, organization, email: address };
			});
		})();

		/** The author at `index`, or a failure naming the index the section does not reach. */
		function authorAt(index: number): Author {
			const author = AUTHORS[index];
			if (author === undefined) {
				throw new Error(`rfc8410.txt names no author at ${String(index)}`);
			}
			return author;
		}

		/** The `Local-part` of a Mailbox, per RFC 5280 4.2.1.6. */
		function localPartOf(email: string): string {
			return email.slice(0, email.lastIndexOf('@'));
		}

		/** The `Domain` of a Mailbox, per RFC 5280 4.2.1.6. */
		function hostPartOf(email: string): string {
			return email.slice(email.lastIndexOf('@') + 1);
		}

		/** The value rfc5280.txt Appendix A.1 assigns to an `ub-` bound. */
		function upperBound(name: string): number {
			const assignment = rfc5280Lines.find((line) => line.startsWith(`${name} INTEGER ::= `));
			if (assignment === undefined) {
				throw new Error(`rfc5280.txt assigns no value to ${name}`);
			}
			const digits = /::= (\d+)$/.exec(assignment)?.[1];
			if (digits === undefined) {
				throw new Error(`rfc5280.txt assigns a non-integer value to ${name}: ${assignment}`);
			}
			return Number(digits);
		}

		/** An Ed25519 CA whose own subject is one author, and the key that signs under it. */
		async function certificateAuthority(
			author: Author,
			nameConstraints?: CertificateExtensionsInput['nameConstraints'],
		): Promise<{ readonly keyPair: CryptoKeyPair; readonly pem: string }> {
			const created = await createSelfSignedCertificate({
				subject: { commonName: author.organization, emailAddress: author.email },
				algorithm: ED25519,
				extensions: {
					basicConstraints: { ca: true },
					keyUsage: ['keyCertSign', 'cRLSign'],
					...(nameConstraints === undefined ? {} : { nameConstraints }),
				},
			});
			return { keyPair: created.keyPair, pem: created.certificate.pem };
		}

		// RFC 5280 4.1.2.6, over the subject the section's three lines fill: "When encoding
		// attribute values of type DirectoryString, conforming CAs MUST use PrintableString
		// or UTF8String encoding", and "The attribute value for emailAddress is of type
		// IA5String to permit inclusion of the character '@', which is not part of the
		// PrintableString character set." Every address the section prints carries that
		// character, so no author's line fits the encoding the other two attributes take.
		it('encodes an author as two UTF8Strings and an IA5String', async () => {
			expect(AUTHORS.map((author) => author.email)).toEqual([
				'simon@josefsson.org',
				'ietf@augustcellars.com',
			]);

			for (const author of AUTHORS) {
				expect(() => printableString(author.email)).toThrow();
				const created = await createSelfSignedCertificate({
					subject: {
						commonName: author.name,
						organization: author.organization,
						emailAddress: author.email,
					},
					algorithm: ED25519,
				});
				const parsed = parseCertificateDerOrThrow(created.certificate.der);
				expect(parsed.subject.values).toEqual({
					commonName: author.name,
					organization: author.organization,
					emailAddress: author.email,
				});
				expect(
					parsed.subject.rdns.flatMap((rdn) =>
						rdn.attributes.map((attribute) => [attribute.key, attribute.valueTag]),
					),
				).toEqual([
					['organization', 0x0c],
					['commonName', 0x0c],
					['emailAddress', 0x16],
				]);
			}
		});

		// RFC 5280 4.1.2.6: "emailAddress attribute values are not case-sensitive (e.g.,
		// "subscriber@example.com" is the same as "SUBSCRIBER@EXAMPLE.COM")", the rule
		// RFC 2985 6.1 registers as pkcs9CaseIgnoreMatch and defines to return "TRUE if the
		// strings are the same length and corresponding characters are identical except
		// possibly with regard to case". A leaf that names its issuer with the address in
		// another case names the same certificate authority; one that swaps in the other
		// author's local part names a different one.
		it('chains to an issuer whose DN emailAddress differs only in case', async () => {
			const issuingAuthor = authorAt(1);
			const other = authorAt(0);
			const ca = await certificateAuthority(issuingAuthor);
			const roots = [ca.pem];
			const caSubjectDer = parseCertificatePemOrThrow(ca.pem).subject.rdns.map((rdn) => rdn.derHex);

			async function leafIssuedBy(email: string): Promise<Uint8Array> {
				const subject = await generateKeyPair(ED25519);
				const leaf = await createCertificate({
					subject: { commonName: other.name },
					issuer: { commonName: issuingAuthor.organization, emailAddress: email },
					publicKey: subject.publicKey,
					signerPrivateKey: ca.keyPair.privateKey,
					issuerPublicKey: ca.keyPair.publicKey,
				});
				return leaf.der;
			}

			const sameCase = await leafIssuedBy(issuingAuthor.email);
			expect(parseCertificateDerOrThrow(sameCase).issuer.rdns.map((rdn) => rdn.derHex)).toEqual(
				caSubjectDer,
			);
			expect(await verifyCertificateChain({ leaf: sameCase, roots })).toMatchObject({ ok: true });

			const upperCase = await leafIssuedBy(issuingAuthor.email.toUpperCase());
			expect(
				parseCertificateDerOrThrow(upperCase).issuer.rdns.map((rdn) => rdn.derHex),
			).not.toEqual(caSubjectDer);
			expect(await verifyCertificateChain({ leaf: upperCase, roots })).toMatchObject({ ok: true });

			const otherLocalPart = `${localPartOf(other.email)}@${hostPartOf(issuingAuthor.email)}`;
			expect(otherLocalPart).not.toBe(issuingAuthor.email);
			expect(
				await verifyCertificateChain({ leaf: await leafIssuedBy(otherLocalPart), roots }),
			).toMatchObject({ ok: false, code: 'no_trusted_root' });
		});

		// The same two addresses under the other name form take the other comparison.
		// RFC 5280 7.5, replaced without change to this rule by RFC 9549 7.5.1: "Two email
		// addresses are considered to match if: 1) the local-part of each name is an exact
		// match, AND 2) the host-part of each name matches using a case-insensitive ASCII
		// comparison." RFC 5280 4.2.1.10 spends that on a subtree: "a name constraint for
		// Internet mail addresses MAY specify a particular mailbox, all addresses at a
		// particular host, or all mailboxes in a domain."
		it('separates the two authors by an rfc822Name constraint', async () => {
			const permitted = authorAt(0);
			const excluded = authorAt(1);
			expect(hostPartOf(permitted.email)).not.toBe(hostPartOf(excluded.email));

			const byHost = await certificateAuthority(excluded, {
				permittedSubtrees: [{ base: { type: 'email', value: hostPartOf(permitted.email) } }],
			});
			const byMailbox = await certificateAuthority(excluded, {
				permittedSubtrees: [{ base: { type: 'email', value: permitted.email } }],
			});

			async function verdict(
				ca: { readonly keyPair: CryptoKeyPair; readonly pem: string },
				email: string,
			): Promise<boolean> {
				const subject = await generateKeyPair(ED25519);
				const leaf = await createCertificate({
					subject: { commonName: permitted.name },
					issuer: { commonName: excluded.organization, emailAddress: excluded.email },
					publicKey: subject.publicKey,
					signerPrivateKey: ca.keyPair.privateKey,
					issuerPublicKey: ca.keyPair.publicKey,
					extensions: { subjectAltNames: [{ type: 'email', value: email }] },
				});
				const result = await verifyCertificateChain({ leaf: leaf.der, roots: [ca.pem] });
				if (!result.ok) {
					expect(result.code).toBe('name_constraints_violated');
				}
				return result.ok;
			}

			const local = localPartOf(permitted.email);
			const host = hostPartOf(permitted.email);
			expect([
				await verdict(byHost, permitted.email),
				await verdict(byHost, `${local.toUpperCase()}@${host}`),
				await verdict(byHost, `${local}@${host.toUpperCase()}`),
				await verdict(byHost, excluded.email),
			]).toEqual([true, true, true, false]);

			expect([
				await verdict(byMailbox, permitted.email),
				await verdict(byMailbox, `${local}@${host.toUpperCase()}`),
				await verdict(byMailbox, `${local.toUpperCase()}@${host}`),
				await verdict(byMailbox, excluded.email),
			]).toEqual([true, true, false, false]);
		});

		// RFC 5280 Appendix A.1 bounds every attribute the section fills: X520CommonName and
		// X520OrganizationName are sized "(1..ub-common-name)" and "(1..ub-organization-name)",
		// and "EmailAddress ::= IA5String (SIZE (1..ub-emailaddress-length))". The bounds are
		// read out of the vendored text, and no author's line comes close to one, so the
		// refusal is exercised on the same line padded a character past its bound.
		it('holds each author inside the RFC 5280 Appendix A.1 bounds', async () => {
			const bounds = [
				['commonName', upperBound('ub-common-name')],
				['organization', upperBound('ub-organization-name')],
				['emailAddress', upperBound('ub-emailaddress-length')],
			] as const;
			expect(bounds).toEqual([
				['commonName', 64],
				['organization', 64],
				['emailAddress', 255],
			]);

			for (const author of AUTHORS) {
				const filled = {
					commonName: author.name,
					organization: author.organization,
					emailAddress: author.email,
				} as const;
				for (const [key, bound] of bounds) {
					expect([key, filled[key].length <= bound]).toEqual([key, true]);
					const padded = filled[key].padEnd(bound, 'x');
					const atBound = await createSelfSignedCertificate({
						subject: { ...filled, [key]: padded },
						algorithm: ED25519,
					});
					expect(parseCertificateDerOrThrow(atBound.certificate.der).subject.values).toEqual({
						...filled,
						[key]: padded,
					});
					await expectRejectedErrorCode(
						createSelfSignedCertificate({
							subject: { ...filled, [key]: `${padded}x` },
							algorithm: ED25519,
						}),
						'name_attribute_too_long',
					);
				}
			}
		});
	});
});
