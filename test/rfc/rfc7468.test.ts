import { describe, expect, it } from 'bun:test';
import {
	categorizePemBlocks,
	categorizePemBlocksOrThrow,
	createCertificate,
	createCertificateRevocationList,
	createCertificateSigningRequest,
	createPfx,
	createPkcs7CertBag,
	createPkcs7SignedData,
	createSelfSignedCertificate,
	distinguishedNameToString,
	exportEncryptedPkcs8Pem,
	exportPkcs8Der,
	exportSpkiDer,
	exportSpkiPem,
	generateKeyPair,
	getSubjectPublicKeyOrThrow,
	importEncryptedPkcs8Der,
	importEncryptedPkcs8Pem,
	importPkcs8Der,
	importPkcs8Pem,
	importPkcs8PemOrThrow,
	importSpkiDer,
	importSpkiPem,
	importSpkiPemOrThrow,
	parseCertificateChainPem,
	parseCertificateDer,
	parseCertificatePem,
	parseCertificatePemOrThrow,
	parseCertificateRevocationListDer,
	parseCertificateRevocationListPem,
	parseCertificateRevocationListPemOrThrow,
	parseCertificateSigningRequestDer,
	parseCertificateSigningRequestPem,
	parseCertificateSigningRequestPemOrThrow,
	parsePkcs7CertBagPem,
	parsePkcs7SignedDataDer,
	parsePkcs7SignedDataPem,
	pemDecode,
	pemDecodeOrThrow,
	pemEncode,
	splitPemBlocks,
	splitPemBlocksOrThrow,
	unwrap,
	validateCertificateRevocationList,
	verifyCertificateRevocationListSignature,
	verifyCertificateSigningRequest,
	verifyPkcs7SignedData,
} from '#micro509';
import type { DerElement } from '#micro509/der';
import {
	concatBytes,
	decodeDerBitStringOrThrow,
	decodeDerInteger,
	decodeDerIntegerOrThrow,
	decodeDerOidOrThrow,
	decodeDerTime,
	decodeDerTimeOrThrow,
	derChildrenOrThrow,
	derImplicitConstructedContext,
	derInteger,
	derIntegerFromNumber,
	derOctetString,
	derOid,
	derSequence,
	derSet,
	derTlv,
	derUtf8String,
	hexToBytes,
	readDerRoot,
	readDerRootOrThrow,
	readDerSequenceOrThrow,
	toHex,
} from '#micro509/der';
import { parseGeneralNames } from '#micro509/internal/x509/general-name';
import { parseDistinguishedNameDer } from '#micro509/x509/parse';
import { createSyntheticPkcs7SignedData, expectRejectedErrorCode, rfcDir } from '#test/helpers';

const rfc = await Bun.file(`${rfcDir}/rfc7468.txt`).text();

/** The base64 alphabet and the ABNF core rules live in the referenced documents. */
const rfc4648 = await Bun.file(`${rfcDir}/rfc4648.txt`).text();
const rfc5234 = await Bun.file(`${rfcDir}/rfc5234.txt`).text();

/** Every `-----BEGIN x-----` block in the vendored RFC, keyed by label. */
const examples = new Map<string, string>();
for (const match of rfc.matchAll(/^-----BEGIN (.+?)-----$[\s\S]*?^-----END \1-----$/gm)) {
	if (match[1] !== undefined && !examples.has(match[1])) examples.set(match[1], match[0]);
}

function example(label: string): string {
	const block = examples.get(label);
	if (block === undefined) throw new Error(`rfc7468.txt has no ${label} example`);
	return block;
}

describe('RFC 7468: PKIX Textual Encodings', () => {
	describe('1. Introduction', () => {
		const introducedFormats = [
			[
				'Certificates, CRLs, and Subject Public Key Info [RFC5280]',
				['CERTIFICATE', 'X509 CRL', 'PUBLIC KEY'],
			],
			['PKCS #10: Certification Request Syntax [RFC2986]', ['CERTIFICATE REQUEST']],
			['PKCS #7: Cryptographic Message Syntax [RFC2315]', ['PKCS7']],
			['Cryptographic Message Syntax [RFC5652]', ['CMS']],
			[
				'PKCS #8 Private-Key Information Syntax [RFC5208], renamed One Asymmetric Key [RFC5958], and Encrypted Private-Key Information Syntax',
				['PRIVATE KEY', 'ENCRYPTED PRIVATE KEY'],
			],
			['Attribute Certificates [RFC5755]', ['ATTRIBUTE CERTIFICATE']],
		] as const satisfies readonly (readonly [string, readonly string[]])[];

		it.each(introducedFormats)('decodes the textual encoding of %s', (_format, labels) => {
			// "This document is about the textual encodings of the following formats",
			// which "are normally encoded using the Basic Encoding Rules (BER) or
			// Distinguished Encoding Rules (DER) [X.690]". Each of the six is a
			// top-level SEQUENCE of two or more fields, and readDerSequenceOrThrow
			// rejects trailing octets, indefinite lengths, and non-minimal lengths, so
			// the decoded octets have to be exactly one DER structure and nothing else.
			for (const label of labels) {
				const der = pemDecodeOrThrow(label, example(label));
				expect(readDerSequenceOrThrow(der).length).toBeGreaterThan(1);
			}
		});

		it.each(introducedFormats)('re-encodes the textual encoding of %s', (_format, labels) => {
			// "This document is about the textual encodings of the following formats":
			// reading each figure and writing it back reproduces the RFC's own text.
			for (const label of labels) {
				const figure = example(label);
				expect(pemEncode(label, pemDecodeOrThrow(label, figure))).toBe(`${figure}\n`);
			}
		});

		it('concatenates several certificates into a chain by copy-and-paste', () => {
			// "a user may concatenate several certificates to form a certificate chain
			// with copy-and-paste operations."
			const first = example('CERTIFICATE');
			const second = splitPemBlocksOrThrow(rfc.slice(rfc.indexOf('Subject: CN=Atlantis')))[0];
			expect(second?.label).toBe('CERTIFICATE');
			for (const separator of ['\n', '\n\n', '\npasted from another file\n']) {
				const blocks = splitPemBlocksOrThrow(`${first}${separator}${second?.pem ?? ''}`);
				expect(blocks.map((block) => block.label)).toEqual(['CERTIFICATE', 'CERTIFICATE']);
				expect(
					blocks.map((block) => parseCertificatePemOrThrow(block.pem).subject.values.commonName),
				).toEqual(['GnuTLS certificate authority', 'Atlantis']);
				expect(Array.from(blocks[0]?.bytes ?? [])).toEqual(
					Array.from(pemDecodeOrThrow('CERTIFICATE', first)),
				);
				expect(Array.from(blocks[1]?.bytes ?? [])).toEqual(Array.from(second?.bytes ?? []));
			}
		});

		it('emits text that survives a textual transport', () => {
			// "A disadvantage of a binary data format is that it cannot be interchanged
			// in textual transports, such as email or text documents."
			const binary = new Uint8Array(256);
			for (let index = 0; index < binary.length; index += 1) binary[index] = index;
			const pem = pemEncode('CERTIFICATE', binary);
			expect(pem).toMatch(/^[ -~\n]*$/);
			expect(Array.from(pemDecodeOrThrow('CERTIFICATE', pem))).toEqual(Array.from(binary));
		});

		it('decodes every figure the document prints', () => {
			// "All figures are real, functional examples". Every block in the document,
			// not one per label: the two CERTIFICATE figures and the four
			// non-conforming labels of Appendix A are figures too.
			const figures = [...rfc.matchAll(/^-----BEGIN (.+?)-----$[\s\S]*?^-----END \1-----$/gm)];
			expect(figures).toHaveLength(14);
			for (const figure of figures) {
				const label = figure[1] ?? '';
				const der = pemDecodeOrThrow(label, figure[0]);
				const root = readDerRootOrThrow(der);
				expect(root.tag).toBe(0x30);
				expect(root.end).toBe(der.length);
			}
		});

		it.todo('the RFC 2119 boilerplate, the PEM lineage, and the OpenPGP/OpenSSH comparison carry no runtime claim of their own; Section 2 states the one consequence, that headers are not permitted', () => {});
	});

	describe('2. General Considerations', () => {
		it('permits data before the encapsulation boundaries', () => {
			// "Data before the encapsulation boundaries are permitted, and parsers
			// MUST NOT malfunction when processing such data."
			const withPreamble = `not pem text\n${example('CERTIFICATE')}`;
			expect(splitPemBlocksOrThrow(withPreamble).map((block) => block.label)).toEqual([
				'CERTIFICATE',
			]);
			expect(Array.from(pemDecodeOrThrow('CERTIFICATE', withPreamble))).toEqual(
				Array.from(pemDecodeOrThrow('CERTIFICATE', example('CERTIFICATE'))),
			);
		});

		it('parses a certificate that carries data before its BEGIN line', () => {
			// Figure 7 prints Subject/Issuer/Validity lines ahead of the boundary,
			// which Section 2 permits, so the typed parser has to read the block out
			// of the surrounding text rather than reject the document.
			const start = rfc.indexOf('Subject: CN=Atlantis');
			const terminator = '-----END CERTIFICATE-----';
			const figure7 = rfc.slice(start, rfc.indexOf(terminator, start) + terminator.length);
			expect(figure7.startsWith('Subject: CN=Atlantis\nIssuer: CN=Atlantis\n')).toBe(true);
			expect(parseCertificatePemOrThrow(figure7).subject.values.commonName).toBe('Atlantis');
		});

		it('handles CRLF, CR, and LF newline conventions', () => {
			// "MUST handle different newline conventions"; "lines are divided with
			// CRLF, CR, or LF."
			const lf = pemEncode('CERTIFICATE', Uint8Array.of(1, 2, 3));
			for (const eol of ['\n', '\r', '\r\n']) {
				const converted = lf.replace(/\n/g, eol);
				expect(Array.from(pemDecodeOrThrow('CERTIFICATE', converted))).toEqual([1, 2, 3]);
				expect(splitPemBlocksOrThrow(converted).map((block) => block.label)).toEqual([
					'CERTIFICATE',
				]);
			}
		});

		it('handles a document that mixes newline conventions', () => {
			// Nothing in this section ties a document to a single convention.
			const eols = ['\r\n', '\r', '\n'];
			const lines = pemEncode('CERTIFICATE', Uint8Array.of(1, 2, 3))
				.split('\n')
				.slice(0, -1);
			const mixed = lines.map((line, index) => `${line}${eols[index % eols.length]}`).join('');
			expect(Array.from(pemDecodeOrThrow('CERTIFICATE', mixed))).toEqual([1, 2, 3]);
			expect(splitPemBlocksOrThrow(`preamble\r${mixed}`).map((block) => block.label)).toEqual([
				'CERTIFICATE',
			]);
		});

		it('requires the encapsulation boundaries to occupy their own lines', () => {
			// "Textual encoding begins with a line comprising '-----BEGIN ', a label,
			// and '-----', and ends with a line comprising '-----END ', a label, and
			// '-----'."
			const figure6 = example('CERTIFICATE');
			for (const joined of [
				figure6.replace('-----\n', '-----'),
				figure6.replace('\n-----END', '-----END'),
				`${figure6} trailing`,
			]) {
				expect(() => pemDecodeOrThrow('CERTIFICATE', joined)).toThrow();
			}
		});

		it('requires exactly five hyphen-minus characters on both ends of both boundaries', () => {
			// "There are exactly five hyphen-minus (also known as dash) characters
			// ('-') on both ends of the encapsulation boundaries, no more, no less."
			const pem = pemEncode('CERTIFICATE', Uint8Array.of(1, 2, 3));
			expect(pem.startsWith('-----BEGIN CERTIFICATE-----')).toBe(true);
			expect(pem.endsWith('-----END CERTIFICATE-----\n')).toBe(true);
			for (const boundary of [
				['-----BEGIN CERTIFICATE-----', '----BEGIN CERTIFICATE-----'],
				['-----BEGIN CERTIFICATE-----', '------BEGIN CERTIFICATE-----'],
				['-----BEGIN CERTIFICATE-----', '-----BEGIN CERTIFICATE----'],
				['-----BEGIN CERTIFICATE-----', '-----BEGIN CERTIFICATE------'],
				['-----END CERTIFICATE-----', '----END CERTIFICATE-----'],
				['-----END CERTIFICATE-----', '------END CERTIFICATE-----'],
				['-----END CERTIFICATE-----', '-----END CERTIFICATE----'],
				['-----END CERTIFICATE-----', '-----END CERTIFICATE------'],
			] as const) {
				const wrong = pem.replace(boundary[0], boundary[1]);
				expect(() => pemDecodeOrThrow('CERTIFICATE', wrong)).toThrow();
				expect(splitPemBlocks(wrong).ok).toBe(false);
			}
		});

		it('requires exactly one space separating BEGIN or END from the label', () => {
			// "There is exactly one space character (SP) separating the BEGIN or END
			// from the label."
			const pem = pemEncode('CERTIFICATE', Uint8Array.of(1, 2, 3));
			for (const boundary of [
				['-----BEGIN CERTIFICATE-----', '-----BEGIN  CERTIFICATE-----'],
				['-----BEGIN CERTIFICATE-----', '-----BEGINCERTIFICATE-----'],
				['-----END CERTIFICATE-----', '-----END  CERTIFICATE-----'],
				['-----END CERTIFICATE-----', '-----ENDCERTIFICATE-----'],
			] as const) {
				const wrong = pem.replace(boundary[0], boundary[1]);
				expect(() => pemDecodeOrThrow('CERTIFICATE', wrong)).toThrow();
				expect(splitPemBlocks(wrong).ok).toBe(false);
			}
		});

		it('treats labels as case-sensitive', () => {
			// "Labels are formally case-sensitive, uppercase".
			const figure6 = example('CERTIFICATE');
			for (const variant of ['certificate', 'Certificate']) {
				const relabelled = figure6.replaceAll('CERTIFICATE', variant);
				expect(splitPemBlocksOrThrow(relabelled).map((block) => block.label)).toEqual([variant]);
				expect(pemDecode('CERTIFICATE', relabelled).ok).toBe(false);
				expect(parseCertificatePem(relabelled).ok).toBe(false);
				expect(Array.from(pemDecodeOrThrow(variant, relabelled))).toEqual(
					Array.from(pemDecodeOrThrow('CERTIFICATE', figure6)),
				);
			}
		});

		it('accepts the empty label and rejects labels the grammar excludes', () => {
			// "Labels are ... comprised of zero or more characters; they do not
			// contain consecutive spaces or hyphen-minuses, nor do they contain
			// spaces or hyphen-minuses at either end."
			expect(Array.from(pemDecodeOrThrow('', pemEncode('', Uint8Array.of(1, 2, 3))))).toEqual([
				1, 2, 3,
			]);
			for (const label of [
				'CERT  IFICATE',
				'CERT--IFICATE',
				' CERTIFICATE',
				'CERTIFICATE ',
				'-CERTIFICATE',
				'CERTIFICATE-',
			]) {
				expect(() => pemEncode(label, Uint8Array.of(1, 2, 3))).toThrow('Invalid PEM label');
				const document = `-----BEGIN ${label}-----\nAQID\n-----END ${label}-----\n`;
				expect(splitPemBlocks(document).ok).toBe(false);
				expect(pemDecode(label, document).ok).toBe(false);
			}
		});

		it('puts the same label on the END line as the BEGIN line', () => {
			// "Generators MUST put the same label on the '-----END ' line ... as the
			// corresponding '-----BEGIN ' line."
			for (const label of ['CERTIFICATE', 'X509 CRL', 'PUBLIC KEY']) {
				const pem = pemEncode(label, Uint8Array.of(1, 2, 3));
				expect(pem).toContain(`-----BEGIN ${label}-----`);
				expect(pem).toContain(`-----END ${label}-----`);
			}
		});

		it('does not disregard a label mismatch between the boundaries', () => {
			// "Parsers MAY disregard the label in the post-encapsulation boundary
			// instead of signaling an error if there is a label mismatch". This
			// parser takes the other option the sentence allows and signals.
			const mismatched = pemEncode('CERTIFICATE', Uint8Array.of(1, 2, 3)).replace(
				'-----END CERTIFICATE-----',
				'-----END PRIVATE KEY-----',
			);
			expect(() => pemDecodeOrThrow('CERTIFICATE', mismatched)).toThrow();
		});

		it('does not permit headers to be encoded alongside the data', () => {
			// "textual encoding does *not* define or permit headers to be encoded
			// alongside the data." A header line is not base64, so it cannot decode.
			const pem = pemEncode('CERTIFICATE', Uint8Array.of(1, 2, 3)).replace(
				'-----\n',
				'-----\nProc-Type: 4,ENCRYPTED\n',
			);
			expect(() => pemDecodeOrThrow('CERTIFICATE', pem)).toThrow();
		});

		it('ignores blanks at the ends of lines', () => {
			// "Most extant parsers ignore blanks at the ends of lines"; blank is HT
			// and SP per this section.
			const pem = pemEncode('CERTIFICATE', Uint8Array.of(1, 2, 3)).replaceAll('\n', ' \t\n');
			expect(Array.from(pemDecodeOrThrow('CERTIFICATE', pem))).toEqual([1, 2, 3]);
		});

		it('handles base64 line sizes other than 64 characters', () => {
			// "Parsers MAY handle other line sizes."
			const der = Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8, 9);
			const base64 = pemEncode('CERTIFICATE', der).split('\n').slice(1, -2).join('');
			for (const width of [4, 16, 40]) {
				const wrapped = base64.match(new RegExp(`.{1,${width}}`, 'g'))?.join('\n') ?? '';
				const pem = `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----`;
				expect(Array.from(pemDecodeOrThrow('CERTIFICATE', pem))).toEqual(Array.from(der));
			}
		});

		it('emits no spacing between the pre-encapsulation boundary and the base64', () => {
			// "Empty space can appear between the pre-encapsulation boundary and the
			// base64, but generators SHOULD NOT emit such any such spacing", and
			// generators "MUST NOT emit extraneous whitespace".
			const pem = pemEncode('CERTIFICATE', new Uint8Array(120).fill(3));
			const body = pem.split('\n').slice(1, -2);
			expect(body.every((line) => line === line.trim() && line.length > 0)).toBe(true);
		});

		it('accepts empty space between the pre-encapsulation boundary and the base64', () => {
			// "Empty space can appear between the pre-encapsulation boundary and the
			// base64", so a parser reading what another generator emitted has to take
			// it.
			const spaced = example('CERTIFICATE').replace(
				'-----BEGIN CERTIFICATE-----\n',
				'-----BEGIN CERTIFICATE-----\n \t\n\n',
			);
			expect(Array.from(pemDecodeOrThrow('CERTIFICATE', spaced))).toEqual(
				Array.from(pemDecodeOrThrow('CERTIFICATE', example('CERTIFICATE'))),
			);
		});

		it('accepts files containing multiple textual encoding instances', () => {
			// "Files MAY contain multiple textual encoding instances."
			const bundle = `${example('CERTIFICATE')}\n${example('X509 CRL')}\n${example('PUBLIC KEY')}`;
			expect(splitPemBlocksOrThrow(bundle).map((block) => block.label)).toEqual([
				'CERTIFICATE',
				'X509 CRL',
				'PUBLIC KEY',
			]);
		});

		it('handles non-conforming data gracefully for every label type', () => {
			// "The label type implies that the encoded data follows the specified
			// syntax. Parsers MUST handle non-conforming data gracefully." Each typed
			// parser returns a typed failure, not a throw, for every figure in the
			// RFC that is not of its own type.
			const parsers = [
				['CERTIFICATE', parseCertificatePem],
				['X509 CRL', parseCertificateRevocationListPem],
				['CERTIFICATE REQUEST', parseCertificateSigningRequestPem],
			] as const;
			for (const [accepted, parse] of parsers) {
				for (const label of examples.keys()) {
					const result = parse(example(label));
					expect({ label, accepted, ok: result.ok }).toEqual({
						label,
						accepted,
						ok: label === accepted,
					});
					if (!result.ok) {
						expect(result.code).toBe('malformed');
					}
				}
			}
		});

		it('does not interpret the contents as another label type', () => {
			// "A conforming parser MAY interpret the contents as another label type
			// but ought to be aware of the security implications discussed in the
			// Security Considerations section." Relabelling a figure decodes to the
			// same octets, and the certificate parser still rejects the structure.
			for (const label of examples.keys()) {
				if (label === 'CERTIFICATE') {
					continue;
				}
				const relabelled = example(label).replaceAll(label, 'CERTIFICATE');
				expect(Array.from(pemDecodeOrThrow('CERTIFICATE', relabelled))).toEqual(
					Array.from(pemDecodeOrThrow(label, example(label))),
				);
				const parsed = parseCertificatePem(relabelled);
				expect({ label, ok: parsed.ok }).toEqual({ label, ok: false });
			}
		});
	});

	describe('3. ABNF', () => {
		const NUL = '\u0000';
		const HT = '\u0009';
		const LF = '\u000A';
		const VT = '\u000B';
		const FF = '\u000C';
		const CR = '\u000D';
		const SP = '\u0020';
		const HYPHEN_MINUS = '\u002D';
		const DEL = '\u007F';
		const NBSP = '\u00A0';
		const THIN_SPACE = '\u2009';
		const IDEOGRAPHIC_SPACE = '\u3000';

		/** A `textualmsg` carrying `body`, with none of the optional whitespace. */
		function message(body: string): string {
			return `-----BEGIN X-----\n${body}\n-----END X-----\n`;
		}

		describe('Figure 1: ABNF (Standard)', () => {
			it('accepts a label containing an internal space or hyphen-minus', () => {
				// label = [ labelchar *( ["-" / SP] labelchar ) ]
				for (const label of ['X509 CRL', 'ENCRYPTED PRIVATE KEY', 'X-TEST']) {
					const pem = pemEncode(label, Uint8Array.of(1, 2, 3));
					expect(Array.from(pemDecodeOrThrow(label, pem))).toEqual([1, 2, 3]);
				}
			});

			it('accepts every labelchar and rejects every character outside the class', () => {
				// labelchar = %x21-2C / %x2E-7E ; any printable character, except
				// hyphen-minus
				for (let code = 0x21; code <= 0x7e; code += 1) {
					if (code === HYPHEN_MINUS.charCodeAt(0)) {
						continue;
					}
					const label = String.fromCharCode(code);
					const pem = pemEncode(label, Uint8Array.of(1, 2, 3));
					expect(Array.from(pemDecodeOrThrow(label, pem))).toEqual([1, 2, 3]);
					expect(splitPemBlocksOrThrow(pem).map((block) => block.label)).toEqual([label]);
				}
				for (const label of [
					NUL,
					HT,
					VT,
					FF,
					SP,
					HYPHEN_MINUS,
					DEL,
					NBSP,
					THIN_SPACE,
					IDEOGRAPHIC_SPACE,
				]) {
					expect(() => pemEncode(label, Uint8Array.of(1, 2, 3))).toThrow('Invalid PEM label');
					const document = `-----BEGIN ${label}-----\nAQID\n-----END ${label}-----\n`;
					expect(pemDecode(label, document).ok).toBe(false);
					expect(splitPemBlocks(document).ok).toBe(false);
				}
			});

			it('admits only ALPHA, DIGIT, "+" and "/" in the encoded data', () => {
				// base64char = ALPHA / DIGIT / "+" / "/"
				expect(Array.from(pemDecodeOrThrow('X', message('+/+/')))).toEqual([251, 255, 191]);
				for (const character of ['-', '_', '*', ':', ';', ',', '.', '@', VT, FF, NBSP]) {
					expect(pemDecode('X', message(`AQ${character}D`)).ok).toBe(false);
				}
			});

			it('admits at most two pad characters, and only at the end', () => {
				// base64pad = "=";
				// base64finl = *base64char (base64pad *WSP eol base64pad / *2base64pad)
				//              *WSP eol
				// A lone pad satisfies *2base64pad but not Section 4 of [RFC4648],
				// which Section 2 requires the encapsulated data to follow.
				expect(Array.from(pemDecodeOrThrow('X', message('AQI=')))).toEqual([1, 2]);
				expect(Array.from(pemDecodeOrThrow('X', message('AQ==')))).toEqual([1]);
				for (const body of ['AQ=', 'AQ===', 'A===', 'AQ=I', '=AQI', 'AQID=', 'A']) {
					expect(pemDecode('X', message(body)).ok).toBe(false);
				}
			});

			it('accepts the base64finl pad-on-its-own-line form', () => {
				// base64finl = *base64char (base64pad *WSP eol base64pad / *2base64pad)
				//              *WSP eol
				//         ; ...AB= <EOL> = <EOL> is not good, but is valid
				for (const body of [`AQ=\n=`, `AQ=${SP}${HT}\n=`, `AQ=\n=${SP}${HT}`, `AQ=${CR}=`]) {
					expect(Array.from(pemDecodeOrThrow('X', message(body)))).toEqual([1]);
				}
			});

			it('accepts eolWSP between the pre-encapsulation boundary and base64text', () => {
				// textualmsg = preeb *WSP eol *eolWSP base64text posteb *WSP [eol];
				// eolWSP = WSP / CR / LF
				const figure6 = example('CERTIFICATE');
				const expected = Array.from(pemDecodeOrThrow('CERTIFICATE', figure6));
				expect(expected.length).toBeGreaterThan(0);
				for (const gap of [SP, HT, CR, LF, `${CR}${LF}`, `${SP}${HT}${LF}${LF}`]) {
					const spaced = figure6.replace('-----\n', `-----\n${gap}`);
					expect(Array.from(pemDecodeOrThrow('CERTIFICATE', spaced))).toEqual(expected);
				}
			});

			it('makes the eol after the post-encapsulation boundary optional', () => {
				// textualmsg = ... posteb *WSP [eol]
				const figure6 = example('CERTIFICATE');
				expect(figure6.endsWith('-----END CERTIFICATE-----')).toBe(true);
				const expected = Array.from(pemDecodeOrThrow('CERTIFICATE', figure6));
				for (const tail of ['', LF, CR, `${CR}${LF}`, `${SP}${HT}`, `${SP}${HT}${LF}`]) {
					expect(Array.from(pemDecodeOrThrow('CERTIFICATE', `${figure6}${tail}`))).toEqual(
						expected,
					);
				}
			});

			it('encodes empty content as the one empty line base64text reduces to', () => {
				// base64text = *base64line base64finl, and base64finl carrying neither
				// base64char nor base64pad reduces to *WSP eol, so the shortest
				// textualmsg holds exactly one empty line.
				const empty = pemEncode('X', new Uint8Array(0));
				expect(empty).toBe('-----BEGIN X-----\n\n-----END X-----\n');
				expect(Array.from(pemDecodeOrThrow('X', empty))).toEqual([]);
				expect(pemDecode('X', '-----BEGIN X-----\n-----END X-----\n').ok).toBe(false);
			});
		});

		describe('Figure 2: ABNF (Lax)', () => {
			/** Every position `laxtextualmsg` admits a `W` that Figure 1 may not. */
			function laxPositions(space: string): readonly string[] {
				const document = message('AQID');
				return [
					`${space}${document}`,
					`${document}${space}`,
					document.replace('-----\n', `-----\n${space}`),
					document.replace('AQID', `AQ${space}ID`),
					document.replace('\n-----END', `\n${space}-----END`),
				];
			}

			it('accepts the W characters Figure 1 shares and rejects VT and FF', () => {
				// laxtextualmsg = *W preeb laxbase64text posteb *W;
				// W = WSP / CR / LF / %x0B / %x0C
				// This parser stays line-oriented: it takes the WSP, CR, and LF that
				// eolWSP already admits and rejects the two characters only W adds.
				for (const space of [SP, HT, CR, LF]) {
					for (const candidate of laxPositions(space)) {
						expect(Array.from(pemDecodeOrThrow('X', candidate))).toEqual([1, 2, 3]);
						expect(splitPemBlocksOrThrow(candidate).map((block) => block.label)).toEqual(['X']);
					}
				}
				for (const space of [VT, FF]) {
					for (const candidate of laxPositions(space)) {
						expect(pemDecode('X', candidate).ok).toBe(false);
					}
				}
			});

			it('accepts base64text broken where Figure 1 does not admit a break', () => {
				// laxbase64text = *(W / base64char) [base64pad *W [base64pad *W]],
				// where base64line = 1*base64char *WSP eol admits neither an empty line
				// nor a break inside a four-character group.
				expect(Array.from(pemDecodeOrThrow('X', message(`AQ${LF}ID`)))).toEqual([1, 2, 3]);
				expect(Array.from(pemDecodeOrThrow('X', message(`AQID${LF}${LF}BAUG`)))).toEqual([
					1, 2, 3, 4, 5, 6,
				]);
			});
		});

		describe('Figure 3: ABNF (Strict)', () => {
			// stricttextualmsg = preeb eol strictbase64text posteb eol;
			// strictbase64text = *base64fullline strictbase64finl;
			// base64fullline   = 64base64char eol;
			// strictbase64finl = *15(4base64char) (4base64char / 3base64char base64pad
			//                      / 2base64char 2base64pad) eol
			const STRICT_TEXTUAL_MSG =
				/^-----BEGIN X-----\n(?:[A-Za-z0-9+/]{64}\n)*(?:[A-Za-z0-9+/]{4}){0,15}(?:[A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)\n-----END X-----\n$/;

			it('emits stricttextualmsg for every content length', () => {
				// "New implementations SHOULD emit the strict format (Figure 3)".
				for (let length = 1; length <= 200; length += 1) {
					const content = new Uint8Array(length);
					for (let index = 0; index < length; index += 1) {
						content[index] = (index * 31) % 256;
					}
					expect(pemEncode('X', content)).toMatch(STRICT_TEXTUAL_MSG);
				}
			});

			it('emits base64 lines of exactly 64 characters except the last', () => {
				// "Generators MUST wrap the base64-encoded lines so that each line
				// consists of exactly 64 characters except for the final line, which
				// will encode the remainder of the data (within the 64-character line
				// boundary)". strictbase64finl bounds that final line at 4 to 64
				// characters, in whole four-character groups.
				const pem = pemEncode('CERTIFICATE', new Uint8Array(200).fill(7));
				const body = pem.split('\n').slice(1, -2);
				expect(body.slice(0, -1).every((line) => line.length === 64)).toBe(true);
				const finalLine = body[body.length - 1] ?? '';
				expect(finalLine.length % 4).toBe(0);
				expect(finalLine.length).toBeGreaterThanOrEqual(4);
				expect(finalLine.length).toBeLessThanOrEqual(64);
			});

			it('emits a trailing eol after the post-encapsulation boundary', () => {
				// stricttextualmsg = preeb eol strictbase64text posteb eol
				expect(pemEncode('CERTIFICATE', Uint8Array.of(1)).endsWith('-----\n')).toBe(true);
			});

			it('has no strict encoding for empty content', () => {
				// strictbase64finl requires two base64char before its pads, so Figure 3
				// has no production for zero-length content and the encoder falls back
				// to the Figure 1 minimum.
				expect(pemEncode('X', new Uint8Array(0))).not.toMatch(STRICT_TEXTUAL_MSG);
			});
		});
	});

	describe('4. Guide', () => {
		// "For convenience, these figures summarize the structures, encodings, and
		// references in the following sections".
		const INTEGER = 0x02;
		const BIT_STRING = 0x03;
		const OCTET_STRING = 0x04;
		const OBJECT_IDENTIFIER = 0x06;
		const SEQUENCE = 0x30;
		const CONTEXT_0 = 0xa0;

		/** One Figure 4 row, with the cells of its wrapped continuation line folded in. */
		interface GuideRow {
			readonly section: string;
			readonly label: string;
			readonly asn1Types: readonly string[];
			readonly references: readonly string[];
			readonly modules: readonly string[];
		}

		const figure4 = rfc.slice(rfc.indexOf('Sec. Label'), rfc.indexOf('Figure 4:'));
		const figure4Lines = figure4.split('\n').filter((line) => line.trim() !== '');
		const ruleIndex = figure4Lines.findIndex((line) => line.startsWith('----+'));
		const rule = figure4Lines[ruleIndex] ?? '';
		const columnStops = [...rule].flatMap((character, index) => (character === '+' ? [index] : []));

		/** Splits a figure line at the `+` stops of the figure's own rule. */
		function cellsOf(line: string): readonly string[] {
			const starts = [0, ...columnStops.map((stop) => stop + 1)];
			const ends = [...columnStops, rule.length];
			return starts.map((start, index) => line.slice(start, ends[index]).trim());
		}

		const rowLines: string[][] = [];
		for (const line of figure4Lines.slice(ruleIndex + 1)) {
			const cells = cellsOf(line);
			if (cells.at(0) !== '' || cells.at(1) !== '') {
				rowLines.push([line]);
				continue;
			}
			rowLines.at(-1)?.push(line);
		}

		const guide: readonly GuideRow[] = rowLines.map((lines) => {
			const cells = lines.map(cellsOf);
			const column = (index: number): readonly string[] =>
				cells.flatMap((line) => {
					const cell = line.at(index);
					return cell === undefined || cell === '' ? [] : [cell];
				});
			return {
				section: cells.at(0)?.at(0) ?? '',
				label: cells.at(0)?.at(1) ?? '',
				asn1Types: column(2),
				references: column(3),
				modules: column(4),
			};
		});

		/** The direct children of the DER element reached by following `path` from the root SEQUENCE. */
		function fieldsAt(der: Uint8Array, path: readonly number[]): readonly DerElement[] {
			let fields: readonly DerElement[] = readDerSequenceOrThrow(der);
			for (const index of path) {
				const field = fields.at(index);
				if (field === undefined) {
					throw new Error(`No DER field at index ${index}`);
				}
				fields = derChildrenOrThrow(der, field);
			}
			return fields;
		}

		function fieldAt(der: Uint8Array, path: readonly number[], index: number): DerElement {
			const field = fieldsAt(der, path).at(index);
			if (field === undefined) {
				throw new Error(`No DER field at index ${index}`);
			}
			return field;
		}

		function tagsAt(der: Uint8Array, path: readonly number[]): readonly number[] {
			return fieldsAt(der, path).map((field) => field.tag);
		}

		/** The textual encoding Figure 4 gives a row, in both the forms its readers take. */
		interface GuideExample {
			readonly pem: string;
			readonly der: Uint8Array;
		}

		/** The one structure behind both cells of Figure 4's row 10: RFC 5208 §5 and RFC 5958 §2. */
		function readsAsOneAsymmetricKey({ der }: GuideExample): void {
			// SEQUENCE { version Version, privateKeyAlgorithm
			// PrivateKeyAlgorithmIdentifier, privateKey OCTET STRING, attributes [0]
			// OPTIONAL, ..., publicKey [1] OPTIONAL }. Figure 12 carries neither
			// version 2 field, and RFC 5958 §2 pins those to v1: "If any items tagged
			// as version 2 are used, the version must be v2, else the version should
			// be v1."
			expect(tagsAt(der, [])).toEqual([INTEGER, SEQUENCE, OCTET_STRING]);
			expect(tagsAt(der, [1]).at(0)).toBe(OBJECT_IDENTIFIER);
			expect(decodeDerIntegerOrThrow(fieldAt(der, [], 0))).toBe(0);
		}

		/** Each ASN.1 type Figure 4 names, read against the module its Reference column cites. */
		const asn1TypeReaders = new Map<string, (example: GuideExample) => Promise<void> | void>([
			[
				'Certificate',
				({ pem, der }) => {
					// RFC 5280 §4.1: Certificate ::= SEQUENCE { tbsCertificate
					// TBSCertificate, signatureAlgorithm AlgorithmIdentifier,
					// signatureValue BIT STRING }.
					expect(tagsAt(der, [])).toEqual([SEQUENCE, SEQUENCE, BIT_STRING]);
					expect(tagsAt(der, [1]).at(0)).toBe(OBJECT_IDENTIFIER);
					expect(parseCertificatePem(pem).ok).toBe(true);
				},
			],
			[
				'CertificateList',
				({ pem, der }) => {
					// RFC 5280 §5.1: CertificateList ::= SEQUENCE { tbsCertList
					// TBSCertList, signatureAlgorithm AlgorithmIdentifier,
					// signatureValue BIT STRING }, where TBSCertList opens with an
					// optional version and a signature AlgorithmIdentifier.
					expect(tagsAt(der, [])).toEqual([SEQUENCE, SEQUENCE, BIT_STRING]);
					expect(tagsAt(der, [0]).slice(0, 2)).toEqual([INTEGER, SEQUENCE]);
					expect(parseCertificateRevocationListPem(pem).ok).toBe(true);
				},
			],
			[
				'CertificationRequest',
				({ pem, der }) => {
					// RFC 2986 §4.2: CertificationRequest ::= SEQUENCE {
					// certificationRequestInfo CertificationRequestInfo,
					// signatureAlgorithm AlgorithmIdentifier, signature BIT STRING },
					// where CertificationRequestInfo ends with attributes [0].
					expect(tagsAt(der, [])).toEqual([SEQUENCE, SEQUENCE, BIT_STRING]);
					expect(tagsAt(der, [0]).at(-1)).toBe(CONTEXT_0);
					expect(parseCertificateSigningRequestPem(pem).ok).toBe(true);
				},
			],
			[
				'ContentInfo',
				({ der }) => {
					// RFC 2315 §7 and RFC 5652 §3: ContentInfo ::= SEQUENCE {
					// contentType ContentType, content [0] EXPLICIT ANY DEFINED BY
					// contentType }, so the tagged field wraps exactly one element.
					expect(tagsAt(der, [])).toEqual([OBJECT_IDENTIFIER, CONTEXT_0]);
					expect(tagsAt(der, [1])).toHaveLength(1);
					// Neither figure carries signedData, and reaching that verdict
					// means the reader decoded the ContentInfo and read its contentType
					// rather than rejecting the octets.
					const parsed = parsePkcs7SignedDataDer(der);
					expect(parsed.ok).toBe(false);
					if (!parsed.ok) {
						expect(parsed.code).toBe('not_signed_data');
					}
				},
			],
			['PrivateKeyInfo', readsAsOneAsymmetricKey],
			['OneAsymmetricKey', readsAsOneAsymmetricKey],
			[
				'EncryptedPrivateKeyInfo',
				({ der }) => {
					// RFC 5958 §3: EncryptedPrivateKeyInfo ::= SEQUENCE {
					// encryptionAlgorithm AlgorithmIdentifier, encryptedData
					// EncryptedData }, where EncryptedData ::= OCTET STRING.
					expect(tagsAt(der, [])).toEqual([SEQUENCE, OCTET_STRING]);
					expect(tagsAt(der, [0]).at(0)).toBe(OBJECT_IDENTIFIER);
				},
			],
			[
				'AttributeCertificate',
				({ der }) => {
					// RFC 5755 §4.1: AttributeCertificate ::= SEQUENCE { acinfo
					// AttributeCertificateInfo, signatureAlgorithm AlgorithmIdentifier,
					// signatureValue BIT STRING }, whose acinfo opens with
					// AttCertVersion ::= INTEGER { v2(1) } and "version is v2".
					expect(tagsAt(der, [])).toEqual([SEQUENCE, SEQUENCE, BIT_STRING]);
					expect(decodeDerIntegerOrThrow(fieldAt(der, [0], 0))).toBe(1);
				},
			],
			[
				'SubjectPublicKeyInfo',
				async ({ der }) => {
					// RFC 5280 §4.1: SubjectPublicKeyInfo ::= SEQUENCE { algorithm
					// AlgorithmIdentifier, subjectPublicKey BIT STRING }.
					expect(tagsAt(der, [])).toEqual([SEQUENCE, BIT_STRING]);
					expect(tagsAt(der, [0]).at(0)).toBe(OBJECT_IDENTIFIER);
					expect((await importSpkiDer(der)).ok).toBe(true);
				},
			],
		]);

		/** Drops the `::=` the wrapped `PrivateKeyInfo ::= OneAsymmetricKey` cell carries. */
		function asn1TypeName(cell: string): string {
			return cell.replace(/\s*::=$/, '');
		}

		const guideCases = guide.map((row) => [`${row.section} ${row.label}`, row] as const);

		/** Where the numbered section's heading line starts in the RFC. */
		function sectionStart(section: number): number {
			const heading = new RegExp(`^${section}\\.  `, 'm').exec(rfc);
			if (heading?.index === undefined) {
				throw new Error(`rfc7468.txt has no section ${section} heading`);
			}
			return heading.index;
		}

		/** The public reader that accepts one Figure 4 row, against the label it accepts. */
		const rowReaders = [
			['CERTIFICATE', (der: Uint8Array) => parseCertificateDer(der)],
			['X509 CRL', (der: Uint8Array) => parseCertificateRevocationListDer(der)],
			['CERTIFICATE REQUEST', (der: Uint8Array) => parseCertificateSigningRequestDer(der)],
			['PUBLIC KEY', (der: Uint8Array) => importSpkiDer(der)],
		] as const satisfies readonly (readonly [
			string,
			(der: Uint8Array) => { readonly ok: boolean } | Promise<{ readonly ok: boolean }>,
		])[];

		describe('Figure 4: Convenience Guide', () => {
			it('tabulates one row per label, each naming an ASN.1 type with a reader here', () => {
				expect(cellsOf(figure4Lines[ruleIndex - 1] ?? '')).toEqual([
					'Sec.',
					'Label',
					'ASN.1 Type',
					'Reference',
					'Module',
				]);
				expect(
					guide.map(
						(row) =>
							`${row.section} ${row.label}: ${row.asn1Types.join(' ')} ${row.references.join(' ')} ${row.modules.join(' ')}`,
					),
				).toEqual([
					'5 CERTIFICATE: Certificate [RFC5280] id-pkix1-e',
					'6 X509 CRL: CertificateList [RFC5280] id-pkix1-e',
					'7 CERTIFICATE REQUEST: CertificationRequest [RFC2986] id-pkcs10',
					'8 PKCS7: ContentInfo [RFC2315] id-pkcs7*',
					'9 CMS: ContentInfo [RFC5652] id-cms2004',
					'10 PRIVATE KEY: PrivateKeyInfo ::= OneAsymmetricKey [RFC5208] [RFC5958] id-pkcs8 id-aKPV1',
					'11 ENCRYPTED PRIVATE KEY: EncryptedPrivateKeyInfo [RFC5958] id-aKPV1',
					'12 ATTRIBUTE CERTIFICATE: AttributeCertificate [RFC5755] id-acv2',
					'13 PUBLIC KEY: SubjectPublicKeyInfo [RFC5280] id-pkix1-e',
				]);
				expect(
					guide.flatMap((row) =>
						row.asn1Types.filter((cell) => !asn1TypeReaders.has(asn1TypeName(cell))),
					),
				).toEqual([]);
			});

			it.each(guideCases)('splits the %s example out of the RFC', (_title, row) => {
				expect(splitPemBlocksOrThrow(example(row.label)).map((block) => block.label)).toEqual([
					row.label,
				]);
			});

			it.each(guideCases)('takes the %s example from the section its Sec. cell names', (_, row) => {
				// "these figures summarize the structures, encodings, and references in
				// the following sections", so the example this suite reads for a row has
				// to be the figure printed under the section the row numbers.
				const section = Number(row.section);
				expect(rfc.indexOf(example(row.label))).toBeGreaterThan(sectionStart(section));
				expect(rfc.indexOf(example(row.label))).toBeLessThan(sectionStart(section + 1));
			});

			it.each(guideCases)(
				'cites, for each ASN.1 type the %s row names, the document defining it',
				async (_title, row) => {
					// The Reference column pairs with the ASN.1 Type column cell by cell:
					// row 10 names PrivateKeyInfo against [RFC5208] and OneAsymmetricKey
					// against [RFC5958].
					expect(row.references).toHaveLength(row.asn1Types.length);
					for (const [index, cell] of row.asn1Types.entries()) {
						const number = /^\[RFC(\d+)\]$/.exec(row.references[index] ?? '')?.[1];
						expect(number).toBeDefined();
						const referenced = await Bun.file(`${rfcDir}/rfc${number}.txt`).text();
						expect(referenced).toMatch(new RegExp(`^ *${asn1TypeName(cell)} +::= +SEQUENCE`, 'm'));
					}
				},
			);

			it.each(rowReaders)('reads the %s row and refuses every other', async (label, read) => {
				// Figure 4 gives each row its own ASN.1 type, but rows 5, 6, 7, and 12 all
				// encode as SEQUENCE { SEQUENCE, SEQUENCE, BIT STRING }, so a reader that
				// went no further than the outer shape would take all four.
				for (const row of guide) {
					const result = await read(pemDecodeOrThrow(row.label, example(row.label)));
					expect([row.label, result.ok]).toEqual([row.label, row.label === label]);
				}
			});

			it.each(guideCases)(
				'reads the %s example as every ASN.1 type its row names',
				async (_title, row) => {
					const pem = example(row.label);
					const guideExample = { pem, der: pemDecodeOrThrow(row.label, pem) };
					expect(row.asn1Types.length).toBeGreaterThan(0);
					for (const cell of row.asn1Types) {
						const read = asn1TypeReaders.get(asn1TypeName(cell));
						expect(read).toBeDefined();
						await read?.(guideExample);
					}
				},
			);

			// Figure 4's nine labels are the whole label set this document defines;
			// Appendix A lists the ones it does not. CategorizedPemBlocks buckets
			// certificates, certification requests, unencrypted private keys, and
			// public keys, and documents everything else as uncategorized.
			const buckets = [
				['CERTIFICATE', 'certificates'],
				['X509 CRL', 'others'],
				['CERTIFICATE REQUEST', 'certificateRequests'],
				['PKCS7', 'others'],
				['CMS', 'others'],
				['PRIVATE KEY', 'privateKeys'],
				['ENCRYPTED PRIVATE KEY', 'others'],
				['ATTRIBUTE CERTIFICATE', 'others'],
				['PUBLIC KEY', 'publicKeys'],
			] as const satisfies readonly (readonly [string, string])[];

			it('categorizes exactly the labels Figure 4 tabulates', () => {
				expect(guide.map((row) => row.label)).toEqual(buckets.map(([label]) => label));
			});

			it.each(buckets)('categorizes %s under %s', (label, bucket) => {
				const categorized = categorizePemBlocksOrThrow(example(label));
				expect(categorized[bucket].map((block) => block.label)).toEqual([label]);
			});

			it('keeps every Figure 4 block when they arrive in one file', () => {
				const bundle = guide.map((row) => example(row.label)).join('\n');
				const categorized = categorizePemBlocksOrThrow(bundle);
				const categories = [
					categorized.certificates,
					categorized.certificateRequests,
					categorized.privateKeys,
					categorized.publicKeys,
					categorized.others,
				];
				expect(
					categories
						.flat()
						.map((block) => block.label)
						.sort(),
				).toEqual(guide.map((row) => row.label).sort());
			});
		});

		describe('Figure 5: ASN.1 Module Object Identifier Value Assignments', () => {
			/** One `name OBJECT IDENTIFIER ::= { ... }` assignment, resolved to dotted form. */
			interface ModuleOid {
				readonly name: string;
				readonly oid: string;
				/** The assignment this one extends, when its arc list opens with an earlier name. */
				readonly parent: string | undefined;
			}

			const figure5 = rfc.slice(rfc.indexOf('id-pkixmod OBJECT'), rfc.indexOf('Figure 5:'));
			const moduleOids: ModuleOid[] = [];
			for (const assignment of figure5
				.replace(/\n/g, ' ')
				.matchAll(/([\w-]+)\s+OBJECT IDENTIFIER ::= \{([^}]*)\}/g)) {
				const tokens = (assignment[2] ?? '').trim().split(/\s+/);
				const resolve = (token: string): string => {
					const numbered = /^[\w-]+\((\d+)\)$/.exec(token)?.[1];
					if (numbered !== undefined) {
						return numbered;
					}
					if (/^\d+$/.test(token)) {
						return token;
					}
					return moduleOids.find((entry) => entry.name === token)?.oid ?? token;
				};
				moduleOids.push({
					name: assignment[1] ?? '',
					oid: tokens.map(resolve).join('.'),
					parent: moduleOids.find((entry) => entry.name === tokens.at(0))?.name,
				});
			}

			it('resolves every assignment, covering each module Figure 4 cites', () => {
				expect(moduleOids.map((entry) => `${entry.name} ${entry.oid}`)).toEqual([
					'id-pkixmod 1.3.6.1.5.5.7.0',
					'id-pkix1-e 1.3.6.1.5.5.7.0.18',
					'id-acv2 1.3.6.1.5.5.7.0.61',
					'id-pkcs 1.2.840.113549.1',
					'id-pkcs10 1.2.840.113549.1.10.1.1',
					'id-pkcs7 1.2.840.113549.1.7.0.1',
					'id-pkcs8 1.2.840.113549.1.8.1.1',
					'id-sm-mod 1.2.840.113549.1.9.16.0',
					'id-aKPV1 1.2.840.113549.1.9.16.0.50',
					'id-cms2004 1.2.840.113549.1.9.16.0.24',
				]);
				// The asterisk on Figure 4's id-pkcs7 cell carries the footnote that the
				// OID never appeared in PKCS #7 v1.5 itself.
				const assigned = new Set(moduleOids.map((entry) => entry.name));
				expect(
					guide.flatMap((row) =>
						row.modules.filter((cell) => !assigned.has(cell.replace('*', ''))),
					),
				).toEqual([]);
			});

			/** Every object identifier an RFC's text spells out as `{name(arc) ...}`, dotted. */
			async function objectIdentifiersIn(rfcNumber: string): Promise<ReadonlySet<string>> {
				const text = (await Bun.file(`${rfcDir}/rfc${rfcNumber}.txt`).text()).replace(/\s+/g, ' ');
				const found = new Set<string>();
				for (const group of text.matchAll(/\{([^{}]*)\}/g)) {
					const tokens = (group[1] ?? '')
						.trim()
						.split(' ')
						.filter((token) => token !== '');
					const arcs = tokens.flatMap((token) => {
						const numbered = /^[A-Za-z][\w-]*\((\d+)\)$/.exec(token)?.[1];
						if (numbered !== undefined) {
							return [numbered];
						}
						return /^\d+$/.test(token) ? [token] : [];
					});
					if (tokens.length > 1 && arcs.length === tokens.length) {
						found.add(arcs.join('.'));
					}
				}
				return found;
			}

			it.each(guideCases)(
				'assigns the %s row a module its reference spells out, unless the figure marks it',
				async (_title, row) => {
					// The Module column pairs with the Reference column cell by cell, and
					// the one asterisked cell carries the footnote: "This OID does not
					// actually appear in PKCS #7 v1.5 [RFC2315]."
					expect(row.modules).toHaveLength(row.references.length);
					for (const [index, cell] of row.modules.entries()) {
						const number = /^\[RFC(\d+)\]$/.exec(row.references[index] ?? '')?.[1];
						expect(number).toBeDefined();
						const name = cell.replace('*', '');
						const oid = moduleOids.find((entry) => entry.name === name)?.oid;
						expect(oid).toBeDefined();
						const spelled = await objectIdentifiersIn(number ?? '');
						expect([cell, spelled.has(oid ?? '')]).toEqual([cell, cell === name]);
					}
				},
			);

			// Figure 5 prints its values in the `{name(arc)}` notation rather than as
			// octets, so the codec is anchored against object identifiers the RFC does
			// print encoded: one from each row's own example. Rows 8 and 9 name the same
			// ASN.1 type against different modules, and their contentType is what tells
			// the two apart.
			it.each([
				['CERTIFICATE', [1], 0, '1.2.840.10045.4.3.2'],
				['X509 CRL', [0, 1], 0, '1.2.840.113549.1.1.5'],
				['CERTIFICATE REQUEST', [1], 0, '1.2.840.10045.4.3.2'],
				['PKCS7', [], 0, '1.2.840.113549.1.9.16.1.23'],
				['CMS', [], 0, '1.2.840.113549.1.9.16.1.9'],
				['PRIVATE KEY', [1], 1, '1.3.132.0.10'],
				['ENCRYPTED PRIVATE KEY', [0], 0, '1.2.840.113549.1.5.13'],
				['ATTRIBUTE CERTIFICATE', [1], 0, '1.2.840.113549.1.1.5'],
				['PUBLIC KEY', [0], 0, '1.2.840.10045.2.1'],
			] as const satisfies readonly (readonly [string, readonly number[], number, string])[])(
				'reads and re-encodes the object identifier the %s example prints',
				(label, path, index, oid) => {
					const der = pemDecodeOrThrow(label, example(label));
					const element = fieldAt(der, path, index);
					expect(element.tag).toBe(OBJECT_IDENTIFIER);
					expect(decodeDerOidOrThrow(element)).toBe(oid);
					const printed = der.slice(element.start - element.headerLength, element.end);
					expect(Array.from(derOid(oid))).toEqual(Array.from(printed));
				},
			);

			it.each(moduleOids.map((entry) => [entry.name, entry.oid] as const))(
				'round-trips %s through the DER object identifier codec',
				(_name, oid) => {
					const encoded = derOid(oid);
					expect(encoded.at(0)).toBe(OBJECT_IDENTIFIER);
					expect(decodeDerOidOrThrow(readDerRootOrThrow(encoded))).toBe(oid);
				},
			);

			it.each(
				moduleOids.flatMap((entry) => {
					const parent = moduleOids.find((candidate) => candidate.name === entry.parent);
					return parent === undefined
						? []
						: [[`${entry.name} inside ${parent.name}`, entry.oid, parent.oid] as const];
				}),
			)('encodes %s as an extension of its arc', (_title, childOid, parentOid) => {
				// Each subidentifier is encoded on its own, so an assignment written as
				// `{parent name(n)}` extends the parent's encoding rather than
				// rewriting it.
				const child = readDerRootOrThrow(derOid(childOid)).value;
				const parent = readDerRootOrThrow(derOid(parentOid)).value;
				expect(parent.length).toBeGreaterThan(0);
				expect(child.length).toBeGreaterThan(parent.length);
				expect(Array.from(child.slice(0, parent.length))).toEqual(Array.from(parent));
			});
		});
	});

	describe('5. Textual Encoding of Certificates', () => {
		const BIT_STRING = 0x03;
		const SEQUENCE = 0x30;
		/** `[0] EXPLICIT Version DEFAULT v1`, the optional first TBSCertificate field. */
		const VERSION = 0xa0;

		/** The historical labels Section 5.1 retires. */
		const historicalLabels = ['X509 CERTIFICATE', 'X.509 CERTIFICATE'] as const;

		function sliceElement(source: Uint8Array, element: DerElement): Uint8Array {
			return source.slice(element.start - element.headerLength, element.end);
		}

		function fieldAt(fields: readonly DerElement[], index: number): DerElement {
			const field = fields.at(index);
			if (field === undefined) {
				throw new Error(`No DER field at index ${index}`);
			}
			return field;
		}

		/**
		 * RFC 5280 §4.1: `Certificate ::= SEQUENCE { tbsCertificate TBSCertificate,
		 * signatureAlgorithm AlgorithmIdentifier, signatureValue BIT STRING }`, whose
		 * TBSCertificate carries that same algorithm identifier in its signature field.
		 */
		function expectCertificateStructure(der: Uint8Array): void {
			const root = readDerRootOrThrow(der);
			expect(root.tag).toBe(SEQUENCE);
			expect(root.end).toBe(der.length);
			const fields = readDerSequenceOrThrow(der);
			expect(fields.map((field) => field.tag)).toEqual([SEQUENCE, SEQUENCE, BIT_STRING]);
			// RFC 5280 §4.1.1.2: signatureAlgorithm "MUST contain the same algorithm
			// identifier as the signature field in the sequence tbsCertificate".
			const tbsFields = derChildrenOrThrow(der, fieldAt(fields, 0));
			const signature = fieldAt(tbsFields, fieldAt(tbsFields, 0).tag === VERSION ? 2 : 1);
			expect(Array.from(sliceElement(der, signature))).toEqual(
				Array.from(sliceElement(der, fieldAt(fields, 1))),
			);
		}

		/** The Figure 6 certificate, and the DER under its label. */
		const figure6 = example('CERTIFICATE');
		const figure6Der = pemDecodeOrThrow('CERTIFICATE', figure6);

		describe('5.1. Encoding', () => {
			const INTEGER = 0x02;
			const UTC_TIME = 0x17;
			const GENERALIZED_TIME = 0x18;
			/** `[3] EXPLICIT Extensions OPTIONAL`, the last TBSCertificate field. */
			const EXTENSIONS = 0xa3;

			function tbsFieldsOf(der: Uint8Array): readonly DerElement[] {
				return derChildrenOrThrow(der, fieldAt(readDerSequenceOrThrow(der), 0));
			}

			function validityFieldsOf(der: Uint8Array): readonly DerElement[] {
				return derChildrenOrThrow(der, fieldAt(tbsFieldsOf(der), 4));
			}

			function timeTextOf(der: Uint8Array): readonly string[] {
				return validityFieldsOf(der).map((field) => new TextDecoder().decode(field.value));
			}

			/** Figure 6's own fields, reassembled around a replacement TBSCertificate. */
			function rebuildCertificate(tbsFields: readonly Uint8Array[]): Uint8Array {
				const fields = readDerSequenceOrThrow(figure6Der);
				return derSequence([
					derSequence(tbsFields),
					sliceElement(figure6Der, fieldAt(fields, 1)),
					sliceElement(figure6Der, fieldAt(fields, 2)),
				]);
			}

			/** Figure 6's serialNumber through subjectPublicKeyInfo, the fields every version carries. */
			const basicTbsFields = tbsFieldsOf(figure6Der)
				.slice(1, 7)
				.map((field) => sliceElement(figure6Der, field));
			const figure6VersionField = sliceElement(figure6Der, fieldAt(tbsFieldsOf(figure6Der), 0));
			const figure6ExtensionsField = sliceElement(figure6Der, fieldAt(tbsFieldsOf(figure6Der), 7));
			/** `[0] EXPLICIT Version` holding `v2(1)`. */
			const version2Field = derTlv(0xa0, derTlv(INTEGER, Uint8Array.of(0x01)));
			/** `issuerUniqueID [1] IMPLICIT UniqueIdentifier`, a BIT STRING with no unused bits. */
			const issuerUniqueId = derTlv(0x81, Uint8Array.of(0x00, 0xde, 0xad));
			/** `subjectUniqueID [2] IMPLICIT UniqueIdentifier`, whose last four bits are unused. */
			const subjectUniqueId = derTlv(0x82, Uint8Array.of(0x04, 0xbe, 0xe0));

			interface IssuingContext {
				readonly issuerCommonName: string;
				readonly issuerCertificate: Uint8Array;
				readonly signerPrivateKey: CryptoKey;
				readonly publicKey: CryptoKey;
			}

			async function createIssuingContext(): Promise<IssuingContext> {
				const issuerCommonName = 'RFC 5280 field CA';
				const issuer = await createSelfSignedCertificate({
					subject: { commonName: issuerCommonName },
					extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] },
				});
				const subjectKeyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
				return {
					issuerCommonName,
					issuerCertificate: issuer.certificate.der,
					signerPrivateKey: issuer.keyPair.privateKey,
					publicKey: subjectKeyPair.publicKey,
				};
			}

			async function issueCertificate(
				context: IssuingContext,
				input: {
					readonly serialNumber?: Uint8Array;
					readonly notBefore?: Date;
					readonly notAfter?: Date;
				},
			): Promise<Uint8Array> {
				const issued = await createCertificate({
					subject: { commonName: 'RFC 5280 field leaf' },
					issuer: { commonName: context.issuerCommonName },
					publicKey: context.publicKey,
					signerPrivateKey: context.signerPrivateKey,
					...(input.serialNumber === undefined ? {} : { serialNumber: input.serialNumber }),
					...(input.notBefore === undefined || input.notAfter === undefined
						? {}
						: { validity: { notBefore: input.notBefore, notAfter: input.notAfter } }),
				});
				return issued.der;
			}

			it('parses the Figure 6 CERTIFICATE example', () => {
				// "Public-key certificates are encoded using the 'CERTIFICATE' label."
				const certificate = parseCertificatePemOrThrow(figure6);
				expect(certificate.subject.values.commonName).toBe('GnuTLS certificate authority');
				expect(certificate.issuer.values.commonName).toBe('GnuTLS certificate authority');
				expect(certificate.notBefore.toISOString()).toBe('2011-05-23T20:38:21.000Z');
				expect(certificate.notAfter.toISOString()).toBe('2012-12-22T07:41:51.000Z');
			});

			it('reads the Figure 6 data as an RFC 5280 Certificate', () => {
				// "The encoded data MUST be a BER (DER strongly preferred; see
				// Appendix B) encoded ASN.1 Certificate structure as described in
				// Section 4 of [RFC5280]."
				expectCertificateStructure(figure6Der);
			});

			it('reads every TBSCertificate field the referenced RFC 5280 §4.1 names', () => {
				// The same MUST reaches inside the structure: "TBSCertificate ::= SEQUENCE
				// { version [0] EXPLICIT Version DEFAULT v1, serialNumber
				// CertificateSerialNumber, signature AlgorithmIdentifier, issuer Name,
				// validity Validity, subject Name, subjectPublicKeyInfo
				// SubjectPublicKeyInfo, ... extensions [3] EXPLICIT Extensions OPTIONAL }".
				// RFC 5280 §4.1.2.1: "conforming implementations MUST recognize version 3
				// certificates"; §4.1.2.9: extensions "MUST only appear if the version is 3".
				const tbsFields = tbsFieldsOf(figure6Der);
				expect(tbsFields.map((field) => field.tag)).toEqual([
					VERSION,
					INTEGER,
					SEQUENCE,
					SEQUENCE,
					SEQUENCE,
					SEQUENCE,
					SEQUENCE,
					EXTENSIONS,
				]);
				const certificate = parseCertificatePemOrThrow(figure6);
				expect(certificate.version).toBe(3);
				expect(certificate.extensions.length).toBeGreaterThan(0);
				// "Validity ::= SEQUENCE { notBefore Time, notAfter Time }", where "Time
				// ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }", and
				// "SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
				// subjectPublicKey BIT STRING }".
				for (const time of validityFieldsOf(figure6Der)) {
					expect([UTC_TIME, GENERALIZED_TIME]).toContain(time.tag);
				}
				expect(
					derChildrenOrThrow(figure6Der, fieldAt(tbsFields, 6)).map((field) => field.tag),
				).toEqual([SEQUENCE, BIT_STRING]);
			});

			it('accepts a Certificate of any version the referenced RFC 5280 §4.1.2.1 defines', () => {
				// "Implementations SHOULD be prepared to accept any version certificate.
				// At a minimum, conforming implementations MUST recognize version 3
				// certificates." "If only basic fields are present, the version SHOULD be
				// 1 (the value is omitted from the certificate as the default value)";
				// with a UniqueIdentifier and no extensions "the version SHOULD be 2".
				const figure6Certificate = parseCertificatePemOrThrow(figure6);
				expect(figure6Certificate.version).toBe(3);

				const version1 = unwrap(parseCertificateDer(rebuildCertificate(basicTbsFields)));
				expect(version1.version).toBe(1);
				expect(version1.extensions).toEqual([]);
				expect(version1.subject.derHex).toBe(figure6Certificate.subject.derHex);
				expect(version1.serialNumberHex).toBe(figure6Certificate.serialNumberHex);

				const version2 = unwrap(
					parseCertificateDer(
						rebuildCertificate([version2Field, ...basicTbsFields, issuerUniqueId, subjectUniqueId]),
					),
				);
				expect(version2.version).toBe(2);
				expect(version2.extensions).toEqual([]);
				expect(version2.subject.derHex).toBe(figure6Certificate.subject.derHex);
			});

			it('parses the unique identifiers RFC 5280 §4.1.2.8 tells CAs not to generate', async () => {
				// "These fields MUST only appear if the version is 2 or 3 ... Applications
				// conforming to this profile SHOULD be capable of parsing certificates
				// that include unique identifiers, but there are no processing
				// requirements associated with the unique identifiers." "CAs conforming
				// to this profile MUST NOT generate certificates with unique identifiers."
				const figure6Certificate = parseCertificatePemOrThrow(figure6);
				const withUniqueIds = unwrap(
					parseCertificateDer(
						rebuildCertificate([
							figure6VersionField,
							...basicTbsFields,
							issuerUniqueId,
							subjectUniqueId,
							figure6ExtensionsField,
						]),
					),
				);
				expect(withUniqueIds.version).toBe(3);
				expect(withUniqueIds.extensions.map((extension) => extension.oid)).toEqual(
					figure6Certificate.extensions.map((extension) => extension.oid),
				);

				const onVersion1 = parseCertificateDer(
					rebuildCertificate([...basicTbsFields, issuerUniqueId]),
				);
				expect(onVersion1.ok).toBe(false);
				if (!onVersion1.ok) {
					expect(onVersion1.code).toBe('malformed');
				}

				const generated = await issueCertificate(await createIssuingContext(), {});
				expect(tbsFieldsOf(generated).map((field) => field.tag)).toEqual([
					VERSION,
					INTEGER,
					SEQUENCE,
					SEQUENCE,
					SEQUENCE,
					SEQUENCE,
					SEQUENCE,
					EXTENSIONS,
				]);
			});

			it('confines the extensions field to version 3 certificates', () => {
				// RFC 5280 §4.1.2.9: the extensions field "MUST only appear if the version
				// is 3 (Section 4.1.2.1)", so Figure 6's extensions cannot ride on a
				// TBSCertificate that omits the version field or declares v2.
				expect(parseCertificatePemOrThrow(figure6).extensions.length).toBe(3);
				for (const versionFields of [[], [version2Field]]) {
					const result = parseCertificateDer(
						rebuildCertificate([...versionFields, ...basicTbsFields, figure6ExtensionsField]),
					);
					expect(result.ok).toBe(false);
					if (!result.ok) {
						expect(result.code).toBe('malformed');
					}
				}
			});

			it('handles the zero serial number Figure 6 carries, and serials of twenty octets', async () => {
				// RFC 5280 §4.1.2.2: "Certificate users MUST be able to handle serialNumber
				// values up to 20 octets", and of certificates such as this one, "Non-
				// conforming CAs may issue certificates with serial numbers that are
				// negative or zero. Certificate users SHOULD be prepared to gracefully
				// handle such certificates."
				expect(Array.from(fieldAt(tbsFieldsOf(figure6Der), 1).value)).toEqual([0x00]);
				expect(parseCertificatePemOrThrow(figure6).serialNumberHex).toBe('00');

				const serialHex = '7f0102030405060708090a0b0c0d0e0f10111213';
				const serialNumber = Uint8Array.from(serialHex.match(/../g) ?? [], (octet) =>
					Number.parseInt(octet, 16),
				);
				expect(serialNumber.length).toBe(20);
				const issued = await issueCertificate(await createIssuingContext(), { serialNumber });
				expect(fieldAt(tbsFieldsOf(issued), 1).value.length).toBe(20);
				expect(unwrap(parseCertificateDer(issued)).serialNumberHex).toBe(serialHex);
			});

			it('refuses to issue a certificate under a serial number RFC 5280 forbids', async () => {
				// RFC 5280 §4.1.2.2: "The serial number MUST be a positive integer assigned
				// by the CA to each certificate", "CAs MUST force the serialNumber to be a
				// non-negative integer", and "Conforming CAs MUST NOT use serialNumber
				// values longer than 20 octets."
				const context = await createIssuingContext();
				for (const serialNumber of [new Uint8Array(), Uint8Array.of(0x00, 0x00)]) {
					await expectRejectedErrorCode(
						issueCertificate(context, { serialNumber }),
						'serial_number_not_positive',
					);
				}
				// A 20-octet magnitude whose leading bit is set needs a zero octet in front
				// of it, and the 21-octet INTEGER that produces is over the limit too.
				for (const serialNumber of [new Uint8Array(21).fill(0x01), new Uint8Array(20).fill(0xff)]) {
					await expectRejectedErrorCode(
						issueCertificate(context, { serialNumber }),
						'serial_number_too_long',
					);
				}
				const generated = fieldAt(tbsFieldsOf(await issueCertificate(context, {})), 1);
				expect(generated.value.length).toBeLessThanOrEqual(20);
				expect(generated.value.at(0) ?? 0x80).toBeLessThan(0x80);
				expect(Array.from(generated.value).some((octet) => octet !== 0)).toBe(true);
			});

			it('encodes validity dates through 2049 as UTCTime and later ones as GeneralizedTime', async () => {
				// RFC 5280 §4.1.2.5: "CAs conforming to this profile MUST always encode
				// certificate validity dates through the year 2049 as UTCTime; certificate
				// validity dates in 2050 or later MUST be encoded as GeneralizedTime."
				// §4.1.2.5.1 and §4.1.2.5.2: both forms are Zulu, carry seconds, and
				// GeneralizedTime "values MUST NOT include fractional seconds".
				const straddling = await issueCertificate(await createIssuingContext(), {
					notBefore: new Date('2049-12-31T23:59:59Z'),
					notAfter: new Date('2050-01-01T00:00:00Z'),
				});
				expect(validityFieldsOf(straddling).map((field) => field.tag)).toEqual([
					UTC_TIME,
					GENERALIZED_TIME,
				]);
				expect(timeTextOf(straddling)).toEqual(['491231235959Z', '20500101000000Z']);
				expect(validityFieldsOf(figure6Der).map((field) => field.tag)).toEqual([
					UTC_TIME,
					UTC_TIME,
				]);
				expect(timeTextOf(figure6Der)).toEqual(['110523203821Z', '121222074151Z']);
			});

			it('processes validity dates encoded in either UTCTime or GeneralizedTime', async () => {
				// RFC 5280 §4.1.2.5: "Conforming applications MUST be able to process
				// validity dates that are encoded in either UTCTime or GeneralizedTime."
				// §4.1.2.5.1: "Where YY is greater than or equal to 50, the year SHALL be
				// interpreted as 19YY; and where YY is less than 50, the year SHALL be
				// interpreted as 20YY."
				const context = await createIssuingContext();
				const nineties = await issueCertificate(context, {
					notBefore: new Date('1990-05-06T07:08:09Z'),
					notAfter: new Date('1991-05-06T07:08:09Z'),
				});
				expect(timeTextOf(nineties)).toEqual(['900506070809Z', '910506070809Z']);
				const parsedNineties = unwrap(parseCertificateDer(nineties));
				expect([
					parsedNineties.notBefore.toISOString(),
					parsedNineties.notAfter.toISOString(),
				]).toEqual(['1990-05-06T07:08:09.000Z', '1991-05-06T07:08:09.000Z']);

				const straddling = await issueCertificate(context, {
					notBefore: new Date('2049-01-02T03:04:05Z'),
					notAfter: new Date('2051-01-02T03:04:05Z'),
				});
				expect(validityFieldsOf(straddling).map((field) => field.tag)).toEqual([
					UTC_TIME,
					GENERALIZED_TIME,
				]);
				const parsedStraddling = unwrap(parseCertificateDer(straddling));
				expect([
					parsedStraddling.notBefore.toISOString(),
					parsedStraddling.notAfter.toISOString(),
				]).toEqual(['2049-01-02T03:04:05.000Z', '2051-01-02T03:04:05.000Z']);
			});

			it('names the issuing CA in both the certificate it signs and its own', async () => {
				// RFC 5280 §4.1.2.4: the issuer field "MUST contain a non-empty
				// distinguished name". §4.1.2.6: "If the subject is a CA ... then the
				// subject field MUST be populated with a non-empty distinguished name
				// matching the contents of the issuer field ... in all certificates issued
				// by the subject CA." Figure 6 is such a CA's own certificate.
				const figure6Certificate = parseCertificatePemOrThrow(figure6);
				expect(figure6Certificate.basicConstraints?.ca).toBe(true);
				expect(figure6Certificate.issuer.rdns.length).toBeGreaterThan(0);
				expect(figure6Certificate.subject.derHex).toBe(figure6Certificate.issuer.derHex);

				const context = await createIssuingContext();
				const issuerCertificate = unwrap(parseCertificateDer(context.issuerCertificate));
				expect(issuerCertificate.basicConstraints?.ca).toBe(true);
				expect(issuerCertificate.subject.rdns.length).toBeGreaterThan(0);
				expect(issuerCertificate.subject.derHex).toBe(issuerCertificate.issuer.derHex);
				const leaf = unwrap(parseCertificateDer(await issueCertificate(context, {})));
				expect(leaf.issuer.derHex).toBe(issuerCertificate.subject.derHex);
			});

			it('rejects data under the CERTIFICATE label that is not a Certificate', () => {
				// The same MUST: the label alone does not make the octets a Certificate,
				// so every figure carrying another structure has to come back as a typed
				// failure once relabelled. Figures 16 and 17 carry certificates under a
				// retired label and are covered on their own below.
				for (const label of examples.keys()) {
					if (label === 'CERTIFICATE' || historicalLabels.some((retired) => retired === label)) {
						continue;
					}
					const relabelled = example(label).replaceAll(label, 'CERTIFICATE');
					expect(Array.from(pemDecodeOrThrow('CERTIFICATE', relabelled))).toEqual(
						Array.from(pemDecodeOrThrow(label, example(label))),
					);
					const parsed = parseCertificatePem(relabelled);
					expect({ label, ok: parsed.ok }).toEqual({ label, ok: false });
					if (!parsed.ok) {
						expect(parsed.code).toBe('malformed');
					}
				}
			});

			it('rejects a Certificate whose signatureAlgorithm the TBSCertificate does not carry', () => {
				// RFC 5280 §4.1.1.2: the signatureAlgorithm field "MUST contain the same
				// algorithm identifier as the signature field in the sequence
				// tbsCertificate", and only the inner one is under the signature.
				const fields = readDerSequenceOrThrow(figure6Der);
				const crlDer = pemDecodeOrThrow('X509 CRL', example('X509 CRL'));
				const foreignAlgorithm = sliceElement(crlDer, fieldAt(readDerSequenceOrThrow(crlDer), 1));
				const rebuild = (signatureAlgorithm: Uint8Array): Uint8Array =>
					derSequence([
						sliceElement(figure6Der, fieldAt(fields, 0)),
						signatureAlgorithm,
						sliceElement(figure6Der, fieldAt(fields, 2)),
					]);
				const unchanged = rebuild(sliceElement(figure6Der, fieldAt(fields, 1)));
				expect(Array.from(unchanged)).toEqual(Array.from(figure6Der));
				expect(parseCertificateDer(unchanged).ok).toBe(true);
				const mismatched = parseCertificateDer(rebuild(foreignAlgorithm));
				expect(mismatched.ok).toBe(false);
				if (!mismatched.ok) {
					expect(mismatched.code).toBe('malformed');
				}
			});

			it('reads the Certificate and nothing beyond it', () => {
				// The encoded data is the Certificate structure, so octets outside it are
				// not part of the encoding.
				expect(parseCertificateDer(figure6Der).ok).toBe(true);
				expect(parseCertificateDer(Uint8Array.of(...figure6Der, 0x00)).ok).toBe(false);
				expect(parseCertificateDer(figure6Der.slice(0, figure6Der.length - 1)).ok).toBe(false);
			});

			it('reads only the definite-length DER form of the Certificate', () => {
				// "DER strongly preferred; see Appendix B", whose Figure 20 gives
				// CERTIFICATE reasons 1 and 2: the signature is computed over the DER
				// encoding and hashes identify it, so an indefinite-length BER wrapper of
				// the same content is neither the signed nor the identified structure.
				const root = readDerRootOrThrow(figure6Der);
				const indefinite = Uint8Array.of(
					SEQUENCE,
					0x80,
					...figure6Der.slice(root.start, root.end),
					0x00,
					0x00,
				);
				expect(parseCertificateDer(indefinite).ok).toBe(false);
			});

			it('generates the CERTIFICATE label', async () => {
				// "Generators conforming to this document MUST generate 'CERTIFICATE'
				// labels and MUST NOT generate 'X509 CERTIFICATE' or 'X.509
				// CERTIFICATE' labels."
				const issuer = await createSelfSignedCertificate({
					subject: { commonName: 'label-conformance CA' },
					extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] },
				});
				const subjectKeyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
				const issued = await createCertificate({
					subject: { commonName: 'label-conformance.example' },
					issuer: { commonName: 'label-conformance CA' },
					publicKey: subjectKeyPair.publicKey,
					signerPrivateKey: issuer.keyPair.privateKey,
				});
				for (const pem of [issuer.certificate.pem, issued.pem]) {
					expect(splitPemBlocksOrThrow(pem).map((block) => block.label)).toEqual(['CERTIFICATE']);
				}
			});

			it('puts an RFC 5280 Certificate under each CERTIFICATE label it generates', async () => {
				// "The encoded data MUST be a BER (DER strongly preferred; see
				// Appendix B) encoded ASN.1 Certificate structure as described in
				// Section 4 of [RFC5280]." Appendix B: DER is that restricted profile,
				// so the emitted base64 carries the certificate's DER and nothing else.
				const issuer = await createSelfSignedCertificate({
					subject: { commonName: 'structure CA' },
					extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] },
				});
				const subjectKeyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
				const issued = await createCertificate({
					subject: { commonName: 'structure.example' },
					issuer: { commonName: 'structure CA' },
					publicKey: subjectKeyPair.publicKey,
					signerPrivateKey: issuer.keyPair.privateKey,
				});
				for (const material of [issuer.certificate, issued]) {
					expectCertificateStructure(material.der);
					expect(Array.from(pemDecodeOrThrow('CERTIFICATE', material.pem))).toEqual(
						Array.from(material.der),
					);
				}
			});

			it('does not treat X509 CERTIFICATE or X.509 CERTIFICATE as CERTIFICATE', () => {
				// "Parsers SHOULD NOT treat 'X509 CERTIFICATE' or 'X.509 CERTIFICATE'
				// as equivalent to 'CERTIFICATE'". Relabelling Figure 6 leaves a
				// certificate this library parses, so only the label can decide.
				for (const label of historicalLabels) {
					const relabelled = example('CERTIFICATE').replaceAll('CERTIFICATE', label);
					expect(splitPemBlocksOrThrow(relabelled).map((block) => block.label)).toEqual([label]);
					expect(pemDecode('CERTIFICATE', relabelled).ok).toBe(false);
					expect(parseCertificatePem(relabelled).ok).toBe(false);
					expect(categorizePemBlocksOrThrow(relabelled).certificates).toEqual([]);
					expect(categorizePemBlocksOrThrow(relabelled).others.map((block) => block.label)).toEqual(
						[label],
					);
					const chain = parseCertificateChainPem(relabelled);
					expect(chain.ok && chain.value).toEqual([]);
				}
			});

			it('keeps the Figures 16 and 17 labels out of the certificate category', () => {
				// Appendix A prints both retired labels over the same certificate. The
				// structure under them is the one Section 5.1 requires, so the label is
				// all that keeps them out: they survive splitting verbatim, and no
				// certificate-labelled surface claims them.
				for (const label of historicalLabels) {
					expectCertificateStructure(pemDecodeOrThrow(label, example(label)));
					expect(splitPemBlocksOrThrow(example(label)).map((block) => block.label)).toEqual([
						label,
					]);
					expect(pemDecode('CERTIFICATE', example(label)).ok).toBe(false);
					expect(categorizePemBlocksOrThrow(example(label)).certificates).toEqual([]);
				}
			});
		});

		describe('5.2. Explanatory Text', () => {
			/** Figure 7, whose explanatory lines precede the pre-encapsulation boundary. */
			const figure7 = rfc.slice(rfc.indexOf('Subject: CN=Atlantis'), rfc.indexOf('Figure 7:'));
			const figure7Lines = figure7.split('\n');
			/** Figure 7 from its pre-encapsulation boundary on, without the explanatory text. */
			const figure7Block = figure7Lines.slice(3).join('\n');
			/** What Figure 7 encodes, decoded without going through this library. */
			const figure7Octets = Array.from(
				Buffer.from(
					figure7Lines.slice(4, figure7Lines.indexOf('-----END CERTIFICATE-----')).join(''),
					'base64',
				),
			);

			/** A UTC instant in the `M/D/YYYY h:mm:ss AM` form Figure 7 prints. */
			function printedUtc(date: Date): string {
				const hours = date.getUTCHours();
				const pad = (value: number): string => String(value).padStart(2, '0');
				return [
					`${date.getUTCMonth() + 1}/${date.getUTCDate()}/${date.getUTCFullYear()}`,
					`${hours % 12 === 0 ? 12 : hours % 12}:${pad(date.getUTCMinutes())}:${pad(
						date.getUTCSeconds(),
					)}`,
					hours < 12 ? 'AM' : 'PM',
				].join(' ');
			}

			it('parses the Figure 7 certificate carrying explanatory text', () => {
				// "Many tools are known to emit explanatory text before the BEGIN and
				// after the END lines for PKIX certificates, more than any other
				// type." Section 2 permits that leading data.
				expect(figure7Lines.at(3)).toBe('-----BEGIN CERTIFICATE-----');
				const certificate = parseCertificatePemOrThrow(figure7);
				expect(certificate.subject.values.commonName).toBe('Atlantis');
				expect(certificate.issuer.values.commonName).toBe('Atlantis');
			});

			it('reproduces every key data element Figure 7 states about its certificate', () => {
				// "If emitted, such text SHOULD be related to the certificate, such as
				// providing a textual representation of key data elements in the
				// certificate."
				const certificate = parseCertificatePemOrThrow(figure7);
				expect(figure7Lines.slice(0, 3)).toEqual([
					`Subject: ${distinguishedNameToString(certificate.subject)}`,
					`Issuer: ${distinguishedNameToString(certificate.issuer)}`,
					`Validity: from ${printedUtc(certificate.notBefore)} UTC to ${printedUtc(
						certificate.notAfter,
					)} UTC`,
				]);
			});

			it('reads the certificate the base64 carries, not the values the text prints', () => {
				// "such text SHOULD be related to the certificate": the text describes
				// the certificate, and a certificate is never read out of it. Figure 7
				// with its three lines contradicted still decodes to Figure 7.
				const contradicted = [
					'Subject: CN=Mu',
					'Issuer: CN=Lemuria',
					'Validity: from 1/1/1970 12:00:00 AM UTC to 1/2/1970 12:00:00 AM UTC',
					figure7Block,
				].join('\n');
				const certificate = parseCertificatePemOrThrow(contradicted);
				expect(certificate.subject.values.commonName).toBe('Atlantis');
				expect(certificate.issuer.values.commonName).toBe('Atlantis');
				expect(certificate.notBefore.toISOString()).toBe('2012-07-09T03:10:38.000Z');
				expect(certificate.notAfter.toISOString()).toBe('2013-07-09T03:10:37.000Z');
				expect(Array.from(certificate.der)).toEqual(figure7Octets);
			});

			it('leaves the explanatory text out of the encoded data', () => {
				// The encoded data is what the base64 between the boundaries carries,
				// so text ahead of the BEGIN line contributes no octets, whether or not
				// it is itself made of base64 characters.
				expect(Array.from(pemDecodeOrThrow('CERTIFICATE', figure7))).toEqual(figure7Octets);
				expect(Array.from(pemDecodeOrThrow('CERTIFICATE', figure7Block))).toEqual(figure7Octets);
				const disguised = `Fingerprint: MIIBmTCCAUeg\nMIIBmTCCAUeg\n${figure7}`;
				expect(Array.from(pemDecodeOrThrow('CERTIFICATE', disguised))).toEqual(figure7Octets);
				expect(Array.from(parseCertificatePemOrThrow(disguised).der)).toEqual(figure7Octets);
				expect(splitPemBlocksOrThrow(disguised).map((block) => Array.from(block.bytes))).toEqual([
					figure7Octets,
				]);
			});

			it('reads explanatory text ahead of every label the RFC prints', () => {
				// "for PKIX certificates, more than any other type": more often, not
				// only, so the same leading text is read off every label.
				for (const label of examples.keys()) {
					const annotated = `Label: ${label}\nEmitted by: a tool\n${example(label)}`;
					expect(Array.from(pemDecodeOrThrow(label, annotated))).toEqual(
						Array.from(pemDecodeOrThrow(label, example(label))),
					);
					expect(splitPemBlocksOrThrow(annotated).map((block) => block.label)).toEqual([label]);
				}
			});

			it('reads a certificate whose explanatory text follows the END line', () => {
				// Figure 1 ends textualmsg at the post-encapsulation boundary and
				// Section 2 permits data only before the boundaries, so trailing text
				// makes the document a file of encoding instances: "Files MAY contain
				// multiple textual encoding instances."
				const document = `${figure7}Serial: 42\n`;
				expect(parseCertificatePem(document).ok).toBe(false);
				const blocks = splitPemBlocksOrThrow(document);
				expect(blocks.map((block) => block.label)).toEqual(['CERTIFICATE']);
				expect(parseCertificatePemOrThrow(blocks[0]?.pem ?? '').subject.values.commonName).toBe(
					'Atlantis',
				);
				expect(
					categorizePemBlocksOrThrow(document).certificates.map((block) => block.label),
				).toEqual(['CERTIFICATE']);
				const chain = parseCertificateChainPem(document);
				expect(chain.ok && chain.value.map((entry) => entry.subject.values.commonName)).toEqual([
					'Atlantis',
				]);
				expect(chain.ok && chain.value.map((entry) => Array.from(entry.der))).toEqual([
					figure7Octets,
				]);
			});

			it('reads a file whose certificates each carry their own explanatory text', () => {
				// The explanatory text of Section 5.2 and the multiple instances Section 2
				// permits meet in one file: "Files MAY contain multiple textual encoding
				// instances. This is used, for example, when a file contains several
				// certificates."
				const document = `0 s:CN=Atlantis\n${figure7}1 s:CN=GnuTLS certificate authority\n${figure6}\n`;
				const chain = parseCertificateChainPem(document);
				expect(chain.ok).toBe(true);
				expect(chain.ok && chain.value.map((entry) => entry.subject.values.commonName)).toEqual([
					'Atlantis',
					'GnuTLS certificate authority',
				]);
				expect(
					categorizePemBlocksOrThrow(document).certificates.map((block) => Array.from(block.bytes)),
				).toEqual([figure7Octets, Array.from(figure6Der)]);
			});

			it('emits no explanatory text of its own', async () => {
				// The SHOULD binds tools that choose to emit such text; this library
				// emits none, so its output is the encapsulated message alone.
				const issuer = await createSelfSignedCertificate({
					subject: { commonName: 'no-explanatory-text CA' },
					extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] },
				});
				const subjectKeyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
				const issued = await createCertificate({
					subject: { commonName: 'no-explanatory-text.example' },
					issuer: { commonName: 'no-explanatory-text CA' },
					publicKey: subjectKeyPair.publicKey,
					signerPrivateKey: issuer.keyPair.privateKey,
				});
				for (const { pem, der } of [issuer.certificate, issued]) {
					expect(pem).toBe(pemEncode('CERTIFICATE', der));
					const lines = pem.split('\n');
					expect(lines.at(0)).toBe('-----BEGIN CERTIFICATE-----');
					expect(lines.at(-2)).toBe('-----END CERTIFICATE-----');
					expect(lines.at(-1)).toBe('');
					expect(lines.slice(1, -2).filter((line) => !/^[A-Za-z0-9+/=]+$/.test(line))).toEqual([]);
				}
			});
		});

		describe('5.3. File Extension', () => {
			it('keeps the DER encoding and the textual encoding of one certificate apart', async () => {
				// "To promote interoperability and to separate DER encodings from textual
				// encodings, the extension '.crt' SHOULD be used for the textual encoding
				// of a certificate." This library names no file; it returns both forms of
				// the same certificate side by side, and each converts to the other.
				const { certificate } = await createSelfSignedCertificate({
					subject: { commonName: 'file-extension.example' },
				});
				expect(certificate.pem).toBe(pemEncode('CERTIFICATE', certificate.der));
				expect(Array.from(pemDecodeOrThrow('CERTIFICATE', certificate.pem))).toEqual(
					Array.from(certificate.der),
				);
				expect(certificate.base64).toBe(certificate.pem.split('\n').slice(1, -2).join(''));
				expectCertificateStructure(certificate.der);
			});

			it('accepts exactly one DER certificate where a ".cer" payload is expected', () => {
				// This section "does not disturb the official application/pkix-cert
				// registration [RFC2585] in any way (which states that 'each .cer file
				// contains exactly one certificate, encoded in DER format')". RFC 2585
				// Section 2: "Each '.cer' file contains exactly one certificate, encoded
				// in DER format."
				expect(unwrap(parseCertificateDer(figure6Der)).subject.values.commonName).toBe(
					'GnuTLS certificate authority',
				);
				const withTrailingOctet = new Uint8Array(figure6Der.length + 1);
				withTrailingOctet.set(figure6Der);
				const twoCertificates = new Uint8Array(figure6Der.length * 2);
				twoCertificates.set(figure6Der);
				twoCertificates.set(figure6Der, figure6Der.length);
				for (const der of [withTrailingOctet, twoCertificates]) {
					const result = parseCertificateDer(der);
					expect(result.ok).toBe(false);
					if (!result.ok) expect(result.error.code).toBe('malformed');
				}
			});

			it('reads a ".cer" carrying either encoding into the same certificate', () => {
				// "Implementations should be aware that in spite of this recommendation,
				// many tools still default to encode certificates in this textual
				// encoding with the extension '.cer'", so one file name reaches a
				// consumer holding either DER or the textual encoding.
				expect(unwrap(parseCertificatePem(figure6))).toEqual(
					unwrap(parseCertificateDer(figure6Der)),
				);
				// The textual encoding stays out of the DER reader, and DER stays out of
				// the textual reader.
				expect(parseCertificateDer(new TextEncoder().encode(figure6)).ok).toBe(false);
				expect(parseCertificatePem(new TextDecoder().decode(figure6Der)).ok).toBe(false);
			});
		});
	});

	describe('6. Textual Encoding of Certificate Revocation Lists', () => {
		const INTEGER = 0x02;
		const BIT_STRING = 0x03;
		const OBJECT_IDENTIFIER = 0x06;
		const UTC_TIME = 0x17;
		const GENERALIZED_TIME = 0x18;
		const SEQUENCE = 0x30;
		const CONTEXT_0_CONSTRUCTED = 0xa0;

		function sliceElement(source: Uint8Array, element: DerElement): Uint8Array {
			return source.slice(element.start - element.headerLength, element.end);
		}

		function fieldAt(fields: readonly DerElement[], index: number): DerElement {
			const field = fields.at(index);
			if (field === undefined) {
				throw new Error(`No DER field at index ${index}`);
			}
			return field;
		}

		/** The direct children of the `index`th field of the SEQUENCE `der` encodes. */
		function childFieldsAt(der: Uint8Array, index: number): readonly DerElement[] {
			return derChildrenOrThrow(der, fieldAt(readDerSequenceOrThrow(der), index));
		}

		/**
		 * RFC 5280 §5.1: `CertificateList ::= SEQUENCE { tbsCertList TBSCertList,
		 * signatureAlgorithm AlgorithmIdentifier, signatureValue BIT STRING }`,
		 * where `AlgorithmIdentifier` opens with an OID and the v2 `TBSCertList`
		 * both CRLs here carry opens with the version and that same identifier.
		 */
		function expectCertificateListStructure(der: Uint8Array): void {
			const root = readDerRootOrThrow(der);
			expect(root.tag).toBe(SEQUENCE);
			expect(root.end).toBe(der.length);
			expect(readDerSequenceOrThrow(der).map((field) => field.tag)).toEqual([
				SEQUENCE,
				SEQUENCE,
				BIT_STRING,
			]);
			expect(fieldAt(childFieldsAt(der, 1), 0).tag).toBe(OBJECT_IDENTIFIER);
			const tbsChildren = childFieldsAt(der, 0);
			expect(tbsChildren.slice(0, 2).map((field) => field.tag)).toEqual([INTEGER, SEQUENCE]);
			// RFC 5280 §5.1.2.1: version 2 is the integer value 1.
			expect(decodeDerIntegerOrThrow(fieldAt(tbsChildren, 0))).toBe(1);
			// RFC 5280 §5.1.1.2: signatureAlgorithm "MUST contain the same algorithm
			// identifier as the signature field in the sequence tbsCertList".
			expect(Array.from(sliceElement(der, fieldAt(tbsChildren, 1)))).toEqual(
				Array.from(sliceElement(der, fieldAt(readDerSequenceOrThrow(der), 1))),
			);
		}

		/** The Figure 8 CRL, and the DER under its label. */
		const figure8 = example('X509 CRL');
		const figure8Der = pemDecodeOrThrow('X509 CRL', figure8);
		const figure8TbsDer = sliceElement(figure8Der, fieldAt(readDerSequenceOrThrow(figure8Der), 0));
		const figure8TbsFields = readDerSequenceOrThrow(figure8TbsDer);

		/** Figure 8's CertificateList with `tbsFields` in place of its TBSCertList fields. */
		function rebuildFigure8(tbsFields: readonly Uint8Array[]): Uint8Array {
			const fields = readDerSequenceOrThrow(figure8Der);
			return derSequence([
				derSequence(tbsFields),
				sliceElement(figure8Der, fieldAt(fields, 1)),
				sliceElement(figure8Der, fieldAt(fields, 2)),
			]);
		}

		/** Figure 8's TBSCertList fields at `indices`, in the order given. */
		function figure8TbsFieldsAt(indices: readonly number[]): readonly Uint8Array[] {
			return indices.map((index) => sliceElement(figure8TbsDer, fieldAt(figure8TbsFields, index)));
		}

		it('parses the Figure 8 X509 CRL example', () => {
			// "Certificate Revocation Lists (CRLs) are encoded using the 'X509 CRL'
			// label."
			const crl = parseCertificateRevocationListPemOrThrow(figure8);
			expect(crl.version).toBe(2);
			expect(crl.issuer.values).toEqual({
				organization: 'VeriSign, Inc.',
				organizationalUnit: 'VeriSign Trust Network',
				commonName: 'Simon Josefsson',
				emailAddress: 'simon@josefsson.org',
			});
			expect(crl.thisUpdate.toISOString()).toBe('2006-12-27T08:02:34.000Z');
			expect(crl.nextUpdate?.toISOString()).toBe('2007-02-07T08:02:35.000Z');
			expect(crl.signatureAlgorithmName).toBe('RSA PKCS#1 v1.5 with SHA-1');
			expect(
				crl.revokedCertificates.map((entry) => [
					entry.serialNumberHex,
					entry.revocationDate.toISOString(),
				]),
			).toEqual([['2e103703df46859d7a550da659618538', '2006-12-27T08:02:34.000Z']]);
		});

		it('reads the Figure 8 data as an RFC 5280 CertificateList', () => {
			// "The encoded data MUST be a BER (DER strongly preferred; see
			// Appendix B) encoded ASN.1 CertificateList structure as described in
			// Section 5 of [RFC5280]."
			expectCertificateListStructure(figure8Der);
		});

		it('reads a version 1 CertificateList under the X509 CRL label', () => {
			// The same MUST reaches RFC 5280 §5, which makes TBSCertList's version
			// OPTIONAL and states that "conforming applications that support CRLs are
			// REQUIRED to process both version 1 and version 2 complete CRLs".
			// Figure 8 without its version field is the same list as a v1 CRL.
			const v1 = rebuildFigure8(figure8TbsFieldsAt([1, 2, 3, 4, 5]));
			expect(
				readDerSequenceOrThrow(sliceElement(v1, fieldAt(readDerSequenceOrThrow(v1), 0)))[0]?.tag,
			).toBe(SEQUENCE);
			const parsed = parseCertificateRevocationListDer(v1);
			expect(parsed.ok).toBe(true);
			if (!parsed.ok) {
				return;
			}
			expect(parsed.value.version).toBe(1);
			const figure8Crl = parseCertificateRevocationListPemOrThrow(figure8);
			expect(parsed.value.issuer.derHex).toBe(figure8Crl.issuer.derHex);
			expect(parsed.value.thisUpdate).toEqual(figure8Crl.thisUpdate);
			expect(parsed.value.nextUpdate).toEqual(figure8Crl.nextUpdate);
			expect(parsed.value.revokedCertificates.map((entry) => entry.serialNumberHex)).toEqual(
				figure8Crl.revokedCertificates.map((entry) => entry.serialNumberHex),
			);
		});

		it('reads a CertificateList that omits nextUpdate and revokedCertificates', () => {
			// The same MUST reaches RFC 5280 §5.1, where nextUpdate and
			// revokedCertificates are OPTIONAL: "the revoked certificate list is
			// optional to support the case where a CA has not revoked any unexpired
			// certificates that it has issued."
			const trimmed = rebuildFigure8(figure8TbsFieldsAt([0, 1, 2, 3]));
			const parsed = parseCertificateRevocationListDer(trimmed);
			expect(parsed.ok).toBe(true);
			if (!parsed.ok) {
				return;
			}
			expect(parsed.value.version).toBe(2);
			expect(parsed.value.nextUpdate).toBeUndefined();
			expect(parsed.value.revokedCertificates).toEqual([]);
			expect(parsed.value.thisUpdate.toISOString()).toBe('2006-12-27T08:02:34.000Z');
		});

		it('rejects data under the X509 CRL label that is not a CertificateList', () => {
			// The same MUST: the label alone does not make the octets a
			// CertificateList, so every other figure relabelled as a CRL has to come
			// back as a typed failure rather than a parse.
			for (const label of examples.keys()) {
				if (label === 'X509 CRL') {
					continue;
				}
				const relabelled = example(label).replaceAll(label, 'X509 CRL');
				expect(Array.from(pemDecodeOrThrow('X509 CRL', relabelled))).toEqual(
					Array.from(pemDecodeOrThrow(label, example(label))),
				);
				const parsed = parseCertificateRevocationListPem(relabelled);
				expect({ label, ok: parsed.ok }).toEqual({ label, ok: false });
				if (!parsed.ok) {
					expect(parsed.code).toBe('malformed');
				}
			}
		});

		it('rejects a CertificateList whose signatureAlgorithm the TBSCertList does not carry', () => {
			// RFC 5280 §5.1.1.2: the signatureAlgorithm field "MUST contain the same
			// algorithm identifier as the signature field in the sequence
			// tbsCertList", and only the inner one is under the signature.
			const fields = readDerSequenceOrThrow(figure8Der);
			const certificateDer = pemDecodeOrThrow('CERTIFICATE', example('CERTIFICATE'));
			const foreignAlgorithm = sliceElement(
				certificateDer,
				fieldAt(readDerSequenceOrThrow(certificateDer), 1),
			);
			const rebuild = (signatureAlgorithm: Uint8Array): Uint8Array =>
				derSequence([
					sliceElement(figure8Der, fieldAt(fields, 0)),
					signatureAlgorithm,
					sliceElement(figure8Der, fieldAt(fields, 2)),
				]);
			const unchanged = rebuild(sliceElement(figure8Der, fieldAt(fields, 1)));
			expect(Array.from(unchanged)).toEqual(Array.from(figure8Der));
			expect(parseCertificateRevocationListDer(unchanged).ok).toBe(true);
			const mismatched = parseCertificateRevocationListDer(rebuild(foreignAlgorithm));
			expect(mismatched.ok).toBe(false);
			if (!mismatched.ok) {
				expect(mismatched.code).toBe('malformed');
			}
		});

		it('reads the CertificateList and nothing beyond it', () => {
			// The encoded data is the CertificateList structure, so octets outside it
			// are not part of the encoding.
			expect(parseCertificateRevocationListDer(figure8Der).ok).toBe(true);
			expect(parseCertificateRevocationListDer(Uint8Array.of(...figure8Der, 0x00)).ok).toBe(false);
			expect(parseCertificateRevocationListDer(figure8Der.slice(0, figure8Der.length - 1)).ok).toBe(
				false,
			);
		});

		it('reads only the definite-length DER form of the CertificateList', () => {
			// "DER strongly preferred; see Appendix B", whose Figure 20 gives X509 CRL
			// reason 1: the signature is computed over the DER encoding, so an
			// indefinite-length BER wrapper of the same content is not the signed
			// structure.
			const root = readDerRootOrThrow(figure8Der);
			const indefinite = Uint8Array.of(
				SEQUENCE,
				0x80,
				...figure8Der.slice(root.start, root.end),
				0x00,
				0x00,
			);
			expect(parseCertificateRevocationListDer(indefinite).ok).toBe(false);
		});

		it('generates the X509 CRL label', async () => {
			// "Generators conforming to this document MUST generate 'X509 CRL' labels
			// and MUST NOT generate 'CRL' labels."
			const ca = await createSelfSignedCertificate({
				subject: { commonName: 'label-conformance CA' },
				extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
			});
			const crl = await createCertificateRevocationList({
				issuer: { commonName: 'label-conformance CA' },
				signerPrivateKey: ca.keyPair.privateKey,
				issuerPublicKey: ca.keyPair.publicKey,
			});
			expect(splitPemBlocksOrThrow(crl.pem).map((b) => b.label)).toEqual(['X509 CRL']);
			expect(crl.pem.startsWith('-----BEGIN X509 CRL-----\n')).toBe(true);
			expect(crl.pem.endsWith('-----END X509 CRL-----\n')).toBe(true);
		});

		it('puts an RFC 5280 CertificateList under each X509 CRL label it generates', async () => {
			// "The encoded data MUST be a BER (DER strongly preferred; see
			// Appendix B) encoded ASN.1 CertificateList structure as described in
			// Section 5 of [RFC5280]", and Figure 20 gives reason 1 for that
			// preference: the signature is computed over the DER of the tbsCertList
			// as it is transmitted.
			const ca = await createSelfSignedCertificate({
				subject: { commonName: 'structure CRL CA' },
				extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
			});
			const crl = await createCertificateRevocationList({
				issuer: { commonName: 'structure CRL CA' },
				signerPrivateKey: ca.keyPair.privateKey,
				issuerPublicKey: ca.keyPair.publicKey,
				crlNumber: 1,
				revokedCertificates: [{ serialNumber: Uint8Array.of(0x2a) }],
			});
			expectCertificateListStructure(crl.der);
			expect(Array.from(pemDecodeOrThrow('X509 CRL', crl.pem))).toEqual(Array.from(crl.der));
			const parsed = parseCertificateRevocationListPemOrThrow(crl.pem);
			expect(Array.from(parsed.tbsCertListDer)).toEqual(
				Array.from(sliceElement(crl.der, fieldAt(readDerSequenceOrThrow(crl.der), 0))),
			);
			expect(
				await verifyCertificateRevocationListSignature(crl.pem, ca.certificate.pem),
			).toMatchObject({ ok: true });
		});

		it('leaves revokedCertificates out of a generated CRL that revokes nothing', async () => {
			// The generated data has to be a CertificateList as described in RFC 5280
			// §5, and §5.1.2.6 says "when there are no revoked certificates, the
			// revoked certificates list MUST be absent."
			const ca = await createSelfSignedCertificate({
				subject: { commonName: 'empty list CRL CA' },
				extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
			});
			for (const revokedCertificates of [undefined, []]) {
				const crl = await createCertificateRevocationList({
					issuer: { commonName: 'empty list CRL CA' },
					signerPrivateKey: ca.keyPair.privateKey,
					issuerPublicKey: ca.keyPair.publicKey,
					crlNumber: 1,
					nextUpdate: new Date('2030-01-01T00:00:00Z'),
					...(revokedCertificates === undefined ? {} : { revokedCertificates }),
				});
				expect(childFieldsAt(crl.der, 0).map((field) => field.tag)).toEqual([
					INTEGER,
					SEQUENCE,
					SEQUENCE,
					UTC_TIME,
					UTC_TIME,
					CONTEXT_0_CONSTRUCTED,
				]);
				expect(parseCertificateRevocationListPemOrThrow(crl.pem).revokedCertificates).toEqual([]);
			}
		});

		it('encodes generated CRL times as UTCTime through 2049 and GeneralizedTime after', async () => {
			// RFC 5280 §5.1.2.4 and §5.1.2.5: thisUpdate and nextUpdate MUST be
			// UTCTime "for dates through the year 2049" and GeneralizedTime "for
			// dates in the year 2050 or later", and §5.1.2.6 puts revocationDate
			// under the same rule. "Conforming applications MUST be able to process
			// dates that are encoded in either UTCTime or GeneralizedTime."
			const ca = await createSelfSignedCertificate({
				subject: { commonName: 'time encoding CRL CA' },
				extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
			});
			const windows = [
				{ thisUpdate: '2049-12-31T23:59:59Z', nextUpdate: '2049-12-31T23:59:59Z', tag: UTC_TIME },
				{
					thisUpdate: '2050-01-01T00:00:00Z',
					nextUpdate: '2051-01-01T00:00:00Z',
					tag: GENERALIZED_TIME,
				},
			] as const;
			for (const window of windows) {
				const crl = await createCertificateRevocationList({
					issuer: { commonName: 'time encoding CRL CA' },
					signerPrivateKey: ca.keyPair.privateKey,
					issuerPublicKey: ca.keyPair.publicKey,
					crlNumber: 1,
					thisUpdate: new Date(window.thisUpdate),
					nextUpdate: new Date(window.nextUpdate),
					revokedCertificates: [
						{ serialNumber: Uint8Array.of(0x2a), revocationDate: new Date(window.thisUpdate) },
					],
				});
				const tbsFields = childFieldsAt(crl.der, 0);
				expect([fieldAt(tbsFields, 3).tag, fieldAt(tbsFields, 4).tag]).toEqual([
					window.tag,
					window.tag,
				]);
				const revokedEntry = fieldAt(derChildrenOrThrow(crl.der, fieldAt(tbsFields, 5)), 0);
				expect(fieldAt(derChildrenOrThrow(crl.der, revokedEntry), 1).tag).toBe(window.tag);
				const parsed = parseCertificateRevocationListPemOrThrow(crl.pem);
				expect(parsed.thisUpdate.toISOString()).toBe(new Date(window.thisUpdate).toISOString());
				expect(parsed.nextUpdate?.toISOString()).toBe(new Date(window.nextUpdate).toISOString());
				expect(parsed.revokedCertificates[0]?.revocationDate.toISOString()).toBe(
					new Date(window.thisUpdate).toISOString(),
				);
			}
		});

		it('refuses to generate a CRL whose issuer distinguished name is empty', async () => {
			// RFC 5280 §5.1.2.3: "the issuer field MUST contain a non-empty X.500
			// distinguished name (DN)", so an empty one cannot be encoded under the
			// X509 CRL label at all.
			const ca = await createSelfSignedCertificate({
				subject: { commonName: 'empty issuer CRL CA' },
				extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
			});
			await expectRejectedErrorCode(
				createCertificateRevocationList({
					issuer: {},
					signerPrivateKey: ca.keyPair.privateKey,
					issuerPublicKey: ca.keyPair.publicKey,
					crlNumber: 1,
				}),
				'issuer_distinguished_name_empty',
			);
			await expectRejectedErrorCode(
				createCertificateRevocationList({
					issuer: [],
					signerPrivateKey: ca.keyPair.privateKey,
					issuerPublicKey: ca.keyPair.publicKey,
					crlNumber: 1,
				}),
				'issuer_distinguished_name_empty',
			);
		});

		it('does not treat CRL as equivalent to X509 CRL', () => {
			// "Historically, the label 'CRL' has rarely been used... Parsers SHOULD
			// NOT treat 'CRL' as equivalent to 'X509 CRL'." Relabelling Figure 8
			// leaves a CertificateList this library parses, so only the label decides.
			const relabelled = figure8.replaceAll('X509 CRL', 'CRL');
			expect(splitPemBlocksOrThrow(relabelled).map((block) => block.label)).toEqual(['CRL']);
			expect(Array.from(pemDecodeOrThrow('CRL', relabelled))).toEqual(Array.from(figure8Der));
			expect(pemDecode('X509 CRL', relabelled).ok).toBe(false);
			expect(parseCertificateRevocationListPem(relabelled).ok).toBe(false);
			expect(() => parseCertificateRevocationListPemOrThrow(relabelled)).toThrow();
			expect(parseCertificateRevocationListDer(figure8Der).ok).toBe(true);
			expect(categorizePemBlocksOrThrow(relabelled).others.map((block) => block.label)).toEqual([
				'CRL',
			]);
		});

		it('takes no CRL-labelled block through the validating entrypoints either', async () => {
			// The same SHOULD NOT: every API that accepts a CRL as text goes through
			// the 'X509 CRL' label, so relabelled Figure 8 fails there too while the
			// same octets under their own label are accepted.
			const relabelled = figure8.replaceAll('X509 CRL', 'CRL');
			const issuer = example('CERTIFICATE');
			expect(await verifyCertificateRevocationListSignature(relabelled, issuer)).toMatchObject({
				ok: false,
				code: 'signature_invalid',
			});
			expect(
				await validateCertificateRevocationList({ crl: relabelled, issuerCertificate: issuer }),
			).toMatchObject({ ok: false, code: 'signature_invalid' });
			expect(
				await validateCertificateRevocationList({ crl: figure8, issuerCertificate: issuer }),
			).toMatchObject({ ok: false, code: 'issuer_mismatch' });
		});
	});

	describe('7. Textual Encoding of PKCS #10 Certification Request Syntax', () => {
		const INTEGER = 0x02;
		const BIT_STRING = 0x03;
		const OBJECT_IDENTIFIER = 0x06;
		const SET = 0x31;
		const SEQUENCE = 0x30;
		const CONTEXT_0_CONSTRUCTED = 0xa0;
		const CONTEXT_0_PRIMITIVE = 0x80;

		function sliceElement(source: Uint8Array, element: DerElement): Uint8Array {
			return source.slice(element.start - element.headerLength, element.end);
		}

		function fieldAt<TField>(fields: readonly TField[], index: number): TField {
			const field = fields.at(index);
			if (field === undefined) {
				throw new Error(`No DER field at index ${index}`);
			}
			return field;
		}

		/**
		 * RFC 2986 §4.2: `CertificationRequest ::= SEQUENCE { certificationRequestInfo
		 * CertificationRequestInfo, signatureAlgorithm AlgorithmIdentifier, signature
		 * BIT STRING }`, over the §4.1 `CertificationRequestInfo ::= SEQUENCE {
		 * version INTEGER { v1(0) }, subject Name, subjectPKInfo SubjectPublicKeyInfo,
		 * attributes [0] Attributes }`.
		 */
		function expectCertificationRequestStructure(der: Uint8Array): void {
			const root = readDerRootOrThrow(der);
			expect(root.tag).toBe(SEQUENCE);
			expect(root.end).toBe(der.length);
			const fields = readDerSequenceOrThrow(der);
			expect(fields.map((field) => field.tag)).toEqual([SEQUENCE, SEQUENCE, BIT_STRING]);
			expect(fieldAt(derChildrenOrThrow(der, fieldAt(fields, 1)), 0).tag).toBe(OBJECT_IDENTIFIER);
			const criFields = derChildrenOrThrow(der, fieldAt(fields, 0));
			expect(criFields.map((field) => field.tag)).toEqual([
				INTEGER,
				SEQUENCE,
				SEQUENCE,
				CONTEXT_0_CONSTRUCTED,
			]);
			// RFC 2986 §4.1: version "shall be 0 for this version of the standard".
			expect(decodeDerIntegerOrThrow(fieldAt(criFields, 0))).toBe(0);
			// RFC 2986 §4.1: `SubjectPublicKeyInfo ::= SEQUENCE { algorithm
			// AlgorithmIdentifier, subjectPublicKey BIT STRING }`.
			expect(derChildrenOrThrow(der, fieldAt(criFields, 2)).map((field) => field.tag)).toEqual([
				SEQUENCE,
				BIT_STRING,
			]);
		}

		/** The Figure 9 certification request, and the DER under its label. */
		const figure9 = example('CERTIFICATE REQUEST');
		const figure9Der = pemDecodeOrThrow('CERTIFICATE REQUEST', figure9);

		function isFigure9Der(der: Uint8Array): boolean {
			return (
				der.length === figure9Der.length && der.every((byte, index) => byte === figure9Der[index])
			);
		}

		/** Figure 9 with its CertificationRequestInfo fields replaced. */
		function rebuildFigure9(criFields: readonly Uint8Array[]): Uint8Array {
			const fields = readDerSequenceOrThrow(figure9Der);
			return derSequence([
				derSequence(criFields),
				sliceElement(figure9Der, fieldAt(fields, 1)),
				sliceElement(figure9Der, fieldAt(fields, 2)),
			]);
		}

		/** The DER of each Figure 9 CertificationRequestInfo field, in order. */
		const figure9CriFields = derChildrenOrThrow(
			figure9Der,
			fieldAt(readDerSequenceOrThrow(figure9Der), 0),
		).map((field) => sliceElement(figure9Der, field));

		/** The DER of each Figure 9 CertificationRequest field, in order. */
		const figure9RequestFields = readDerSequenceOrThrow(figure9Der).map((field) =>
			sliceElement(figure9Der, field),
		);

		/** The DER of each child of a Figure 9 element. */
		function childrenDerOf(der: Uint8Array): Uint8Array[] {
			return derChildrenOrThrow(der, readDerRootOrThrow(der)).map((child) =>
				sliceElement(der, child),
			);
		}

		/** The content octets of a DER element, without its tag and length. */
		function contentOf(der: Uint8Array): Uint8Array {
			return readDerRootOrThrow(der).value;
		}

		/** Figure 9 with its CertificationRequestInfo `attributes [0]` members replaced. */
		function rebuildFigure9Attributes(attributes: readonly Uint8Array[]): Uint8Array {
			return rebuildFigure9([
				...figure9CriFields.slice(0, 3),
				derImplicitConstructedContext(0, concatBytes(attributes)),
			]);
		}

		/** The single Figure 9 attribute, and the DER of its `type` and `values` fields. */
		const figure9Attribute = fieldAt(childrenDerOf(fieldAt(figure9CriFields, 3)), 0);
		const figure9AttributeFields = childrenDerOf(figure9Attribute);

		it('parses the Figure 9 CERTIFICATE REQUEST example', () => {
			// "PKCS #10 Certification Requests are encoded using the 'CERTIFICATE
			// REQUEST' label."
			expect(splitPemBlocksOrThrow(figure9).map((block) => block.label)).toEqual([
				'CERTIFICATE REQUEST',
			]);
			expect(
				categorizePemBlocksOrThrow(figure9).certificateRequests.map((block) => block.label),
			).toEqual(['CERTIFICATE REQUEST']);
			const csr = parseCertificateSigningRequestPemOrThrow(figure9);
			expect(csr.version).toBe(1);
			expect(csr.subject.values).toEqual({
				country: 'SE',
				organization: 'Simon Josefsson Datakonsult AB',
				commonName: 'josefsson.org',
			});
			expect(csr.signatureAlgorithmOid).toBe('1.2.840.10045.4.3.2');
			expect(csr.signatureAlgorithmName).toBe('ECDSA with SHA-256');
			expect(csr.publicKeyAlgorithmOid).toBe('1.2.840.10045.2.1');
			expect(csr.publicKeyParametersOid).toBe('1.3.132.0.33');
			// RFC 2986 §4.1: the attributes carry "information to appear in X.509
			// certificate extensions (e.g. the extensionRequest attribute from PKCS #9)".
			expect(
				csr.requestedExtensions.map((extension) => [extension.oid, extension.critical]),
			).toEqual([
				['2.5.29.17', false],
				['2.5.29.19', true],
				['2.5.29.15', true],
				['2.5.29.37', true],
			]);
			expect(csr.subjectAltNames).toEqual([{ type: 'dns', value: 'josefsson.org' }]);
			expect(csr.basicConstraints).toEqual({ ca: false });
			expect(csr.keyUsage).toEqual({
				flags: ['digitalSignature', 'keyEncipherment'],
				nonZeroPadding: false,
			});
			expect(csr.extendedKeyUsage).toEqual(['serverAuth']);
		});

		it('reads the Figure 9 data as an RFC 2986 CertificationRequest', () => {
			// "The encoded data MUST be a BER (DER strongly preferred; see Appendix B)
			// encoded ASN.1 CertificationRequest structure as described in [RFC2986]."
			expectCertificationRequestStructure(figure9Der);
			const csr = parseCertificateSigningRequestPemOrThrow(figure9);
			const fields = readDerSequenceOrThrow(figure9Der);
			expect(
				decodeDerOidOrThrow(fieldAt(derChildrenOrThrow(figure9Der, fieldAt(fields, 1)), 0)),
			).toBe(csr.signatureAlgorithmOid);
			// RFC 2986 §4.2: the certificationRequestInfo "is the value being signed",
			// and step 1 of the signature process DER encodes it.
			expect(Array.from(csr.certificationRequestInfoDer)).toEqual(
				Array.from(sliceElement(figure9Der, fieldAt(fields, 0))),
			);
			expect(Array.from(csr.subjectPublicKeyInfoDer)).toEqual(
				Array.from(figure9CriFields[2] ?? Uint8Array.of()),
			);
			// RFC 2986 §4.1: the PKCS #9 extensionRequest attribute carries the
			// requested extensions.
			const attributes = derChildrenOrThrow(
				figure9Der,
				fieldAt(derChildrenOrThrow(figure9Der, fieldAt(fields, 0)), 3),
			);
			expect(attributes).toHaveLength(1);
			const attributeFields = derChildrenOrThrow(figure9Der, fieldAt(attributes, 0));
			expect(attributeFields.map((field) => field.tag)).toEqual([OBJECT_IDENTIFIER, SET]);
			expect(decodeDerOidOrThrow(fieldAt(attributeFields, 0))).toBe('1.2.840.113549.1.9.14');
		});

		it('rejects data under the CERTIFICATE REQUEST label that is not a CertificationRequest', () => {
			// The same MUST: the label alone does not make the octets a
			// CertificationRequest. Only Figures 9 and 18 carry one, and they carry the
			// same DER, so every other figure relabelled as a request has to come back
			// as a typed failure.
			for (const label of examples.keys()) {
				const relabelled = example(label).replaceAll(label, 'CERTIFICATE REQUEST');
				const bytes = pemDecodeOrThrow('CERTIFICATE REQUEST', relabelled);
				expect(Array.from(bytes)).toEqual(Array.from(pemDecodeOrThrow(label, example(label))));
				const parsed = parseCertificateSigningRequestPem(relabelled);
				expect({ label, ok: parsed.ok }).toEqual({ label, ok: isFigure9Der(bytes) });
				if (!parsed.ok) {
					expect(parsed.code).toBe('malformed');
				}
			}
		});

		it('reads the CertificationRequest and nothing beyond it', () => {
			// The encoded data is the CertificationRequest structure, so octets outside
			// it are not part of the encoding.
			expect(parseCertificateSigningRequestDer(figure9Der).ok).toBe(true);
			expect(parseCertificateSigningRequestDer(Uint8Array.of(...figure9Der, 0x00)).ok).toBe(false);
			expect(parseCertificateSigningRequestDer(figure9Der.slice(0, figure9Der.length - 1)).ok).toBe(
				false,
			);
		});

		it('reads only the definite-length DER form of the CertificationRequest', () => {
			// "DER strongly preferred; see Appendix B", whose Figure 20 gives
			// CERTIFICATE REQUEST reason 1: the signature is computed over the DER
			// encoding, so an indefinite-length BER wrapper of the same content is not
			// the signed structure.
			const root = readDerRootOrThrow(figure9Der);
			const indefinite = Uint8Array.of(
				SEQUENCE,
				0x80,
				...figure9Der.slice(root.start, root.end),
				0x00,
				0x00,
			);
			expect(parseCertificateSigningRequestDer(indefinite).ok).toBe(false);
		});

		it('requires every RFC 2986 CertificationRequestInfo field', () => {
			// The same MUST, through RFC 2986 §4.1: version, subject, subjectPKInfo,
			// and `attributes [0]` are all components of CertificationRequestInfo, and
			// none of them is OPTIONAL.
			expect(Array.from(rebuildFigure9(figure9CriFields))).toEqual(Array.from(figure9Der));
			expect(parseCertificateSigningRequestDer(rebuildFigure9(figure9CriFields)).ok).toBe(true);
			const mutations = [
				['attributes dropped', figure9CriFields.slice(0, 3)],
				['subjectPKInfo dropped', [...figure9CriFields.slice(0, 2), ...figure9CriFields.slice(3)]],
				[
					// RFC 2986 §4.1: version "shall be 0 for this version of the standard".
					'version 1',
					[Uint8Array.of(INTEGER, 0x01, 0x01), ...figure9CriFields.slice(1)],
				],
				[
					// The [0] tag is IMPLICIT on `SET OF Attribute`, so it is constructed.
					'attributes as SET',
					[...figure9CriFields.slice(0, 3), Uint8Array.of(SET, 0x00)],
				],
				[
					'attributes as primitive [0]',
					[...figure9CriFields.slice(0, 3), Uint8Array.of(CONTEXT_0_PRIMITIVE, 0x00)],
				],
			] as const satisfies readonly (readonly [string, readonly Uint8Array[]])[];
			for (const [name, criFields] of mutations) {
				const parsed = parseCertificateSigningRequestDer(rebuildFigure9(criFields));
				expect({ name, ok: parsed.ok }).toEqual({ name, ok: false });
				if (!parsed.ok) {
					expect(parsed.code).toBe('malformed');
				}
			}
		});

		it('gives every CertificationRequest field the RFC 2986 §4.2 type', () => {
			// The same MUST, through RFC 2986 §4.2: `signatureAlgorithm
			// AlgorithmIdentifier{{ SignatureAlgorithms }}` is a SEQUENCE whose
			// `algorithm` is `ALGORITHM.&id`, an OBJECT IDENTIFIER, and `signature` is a
			// BIT STRING.
			expect(Array.from(derSequence(figure9RequestFields))).toEqual(Array.from(figure9Der));
			const signatureAlgorithm = fieldAt(figure9RequestFields, 1);
			const signature = fieldAt(figure9RequestFields, 2);
			const algorithmOid = fieldAt(childrenDerOf(signatureAlgorithm), 0);
			const mutations = [
				[
					'signatureAlgorithm as SET',
					[fieldAt(figure9RequestFields, 0), derTlv(SET, contentOf(signatureAlgorithm)), signature],
				],
				[
					'signatureAlgorithm algorithm as OCTET STRING',
					[
						fieldAt(figure9RequestFields, 0),
						derSequence([derOctetString(contentOf(algorithmOid))]),
						signature,
					],
				],
				[
					'signature as OCTET STRING',
					[
						fieldAt(figure9RequestFields, 0),
						signatureAlgorithm,
						derOctetString(contentOf(signature)),
					],
				],
				['signature dropped', figure9RequestFields.slice(0, 2)],
				['a fourth field', [...figure9RequestFields, derIntegerFromNumber(0)]],
			] as const satisfies readonly (readonly [string, readonly Uint8Array[]])[];
			for (const [name, fields] of mutations) {
				const parsed = parseCertificateSigningRequestDer(derSequence(fields));
				expect({ name, ok: parsed.ok }).toEqual({ name, ok: false });
				if (!parsed.ok) {
					expect(parsed.code).toBe('malformed');
				}
			}
		});

		it('gives every CertificationRequestInfo field the RFC 2986 §4.1 type', () => {
			// The same MUST, through RFC 2986 §4.1: `subject Name` is the RFC 5280 §4.1.2.4
			// `RDNSequence`, a SEQUENCE OF SET OF `AttributeTypeAndValue ::= SEQUENCE {
			// type AttributeType, value AttributeValue }` whose type is an OBJECT
			// IDENTIFIER, and `subjectPKInfo` is a SubjectPublicKeyInfo SEQUENCE.
			const subject = fieldAt(figure9CriFields, 1);
			const rdns = childrenDerOf(subject);
			const attributeTypeAndValues = childrenDerOf(fieldAt(rdns, 0));
			const attributeTypeAndValue = fieldAt(attributeTypeAndValues, 0);
			const nameType = fieldAt(childrenDerOf(attributeTypeAndValue), 0);
			const nameValue = fieldAt(childrenDerOf(attributeTypeAndValue), 1);
			const rebuildSubject = (firstRdn: Uint8Array): Uint8Array =>
				derSequence([firstRdn, ...rdns.slice(1)]);
			const withSubject = (encoded: Uint8Array): readonly Uint8Array[] => [
				fieldAt(figure9CriFields, 0),
				encoded,
				fieldAt(figure9CriFields, 2),
				fieldAt(figure9CriFields, 3),
			];
			const mutations = [
				['subject as SET', withSubject(derTlv(SET, contentOf(subject)))],
				[
					'RelativeDistinguishedName as SEQUENCE',
					withSubject(rebuildSubject(derSequence([attributeTypeAndValue]))),
				],
				[
					'AttributeTypeAndValue as SET',
					withSubject(rebuildSubject(derSet([derTlv(SET, contentOf(attributeTypeAndValue))]))),
				],
				[
					'AttributeTypeAndValue type as OCTET STRING',
					withSubject(
						rebuildSubject(derSet([derSequence([derOctetString(contentOf(nameType)), nameValue])])),
					),
				],
				[
					'AttributeTypeAndValue with a third field',
					withSubject(
						rebuildSubject(derSet([derSequence([nameType, nameValue, derIntegerFromNumber(0)])])),
					),
				],
				[
					'subjectPKInfo as SET',
					[
						fieldAt(figure9CriFields, 0),
						subject,
						derTlv(SET, contentOf(fieldAt(figure9CriFields, 2))),
						fieldAt(figure9CriFields, 3),
					],
				],
			] as const satisfies readonly (readonly [string, readonly Uint8Array[]])[];
			for (const [name, criFields] of mutations) {
				const parsed = parseCertificateSigningRequestDer(rebuildFigure9(criFields));
				expect({ name, ok: parsed.ok }).toEqual({ name, ok: false });
				if (!parsed.ok) {
					expect(parsed.code).toBe('malformed');
				}
			}
		});

		it('gives every CertificationRequestInfo attribute the RFC 2986 §4.1 type', () => {
			// The same MUST, through RFC 2986 §4.1: `Attributes ::= SET OF Attribute` and
			// `Attribute ::= SEQUENCE { type ATTRIBUTE.&id, values SET SIZE(1..MAX) OF
			// ATTRIBUTE.&Type }`.
			expect(Array.from(rebuildFigure9Attributes([figure9Attribute]))).toEqual(
				Array.from(figure9Der),
			);
			const attributeType = fieldAt(figure9AttributeFields, 0);
			const attributeValues = fieldAt(figure9AttributeFields, 1);
			const mutations = [
				['attribute as SET', [derTlv(SET, contentOf(figure9Attribute))]],
				[
					'attribute type as OCTET STRING',
					[derSequence([derOctetString(contentOf(attributeType)), attributeValues])],
				],
				[
					'attribute values as SEQUENCE',
					[derSequence([attributeType, derTlv(SEQUENCE, contentOf(attributeValues))])],
				],
				['attribute values empty', [derSequence([attributeType, derSet([])])]],
			] as const satisfies readonly (readonly [string, readonly Uint8Array[]])[];
			for (const [name, attributes] of mutations) {
				const parsed = parseCertificateSigningRequestDer(rebuildFigure9Attributes(attributes));
				expect({ name, ok: parsed.ok }).toEqual({ name, ok: false });
				if (!parsed.ok) {
					expect(parsed.code).toBe('malformed');
				}
			}
		});

		it('reads the extensionRequest attribute as RFC 2985 §5.4.2 defines it', () => {
			// The same MUST, through RFC 2986 §4.1: the attributes carry "information to
			// appear in X.509 certificate extensions (e.g. the extensionRequest attribute
			// from PKCS #9)". RFC 2985 §5.4.2 declares it `SINGLE VALUE TRUE`, so one
			// value, and one attribute carrying it.
			const requestedOids = ['2.5.29.17', '2.5.29.19', '2.5.29.15', '2.5.29.37'];
			const otherExtensions = derSequence([
				derSequence([derOid('2.5.29.14'), derOctetString(derOctetString(Uint8Array.of(0x00)))]),
			]);
			const twoValues = derSequence([
				fieldAt(figure9AttributeFields, 0),
				derSet([contentOf(fieldAt(figure9AttributeFields, 1)), otherExtensions]),
			]);
			for (const [name, attributes] of [
				['repeated attribute', [figure9Attribute, figure9Attribute]],
				['two values', [twoValues]],
			] as const satisfies readonly (readonly [string, readonly Uint8Array[]])[]) {
				const parsed = parseCertificateSigningRequestDer(rebuildFigure9Attributes(attributes));
				expect({ name, ok: parsed.ok }).toEqual({ name, ok: false });
				if (!parsed.ok) {
					expect(parsed.code).toBe('malformed');
				}
			}
			// RFC 2985 §5.4.1 defines challengePassword as another CRIAttributes member,
			// so a request carrying one still yields the requested extensions.
			const challengePassword = derSequence([
				derOid('1.2.840.113549.1.9.7'),
				derSet([derUtf8String('rfc7468-section-7')]),
			]);
			const parsed = parseCertificateSigningRequestDer(
				rebuildFigure9Attributes([challengePassword, figure9Attribute]),
			);
			expect(parsed.ok).toBe(true);
			if (parsed.ok) {
				expect(parsed.value.requestedExtensions.map((extension) => extension.oid)).toEqual(
					requestedOids,
				);
			}
		});

		it('generates the CERTIFICATE REQUEST label', async () => {
			// "Generators conforming to this document MUST generate 'CERTIFICATE
			// REQUEST' labels."
			const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
			const csr = await createCertificateSigningRequest({
				subject: { commonName: 'label-conformance.example' },
				publicKey: keyPair.publicKey,
				signerPrivateKey: keyPair.privateKey,
			});
			expect(splitPemBlocksOrThrow(csr.pem).map((b) => b.label)).toEqual(['CERTIFICATE REQUEST']);
			expect(csr.pem.startsWith('-----BEGIN CERTIFICATE REQUEST-----\n')).toBe(true);
			expect(csr.pem.endsWith('-----END CERTIFICATE REQUEST-----\n')).toBe(true);
		});

		it('puts an RFC 2986 CertificationRequest under each CERTIFICATE REQUEST label it generates', async () => {
			// "The encoded data MUST be a BER (DER strongly preferred; see Appendix B)
			// encoded ASN.1 CertificationRequest structure as described in [RFC2986]",
			// and Figure 20 gives reason 1 for that preference: RFC 2986 §4.2 signs the
			// DER encoding of the certificationRequestInfo as it is transmitted.
			const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
			const csr = await createCertificateSigningRequest({
				subject: { commonName: 'structure.example' },
				publicKey: keyPair.publicKey,
				signerPrivateKey: keyPair.privateKey,
				extensions: { subjectAltNames: [{ type: 'dns', value: 'structure.example' }] },
			});
			expectCertificationRequestStructure(csr.der);
			expect(Array.from(pemDecodeOrThrow('CERTIFICATE REQUEST', csr.pem))).toEqual(
				Array.from(csr.der),
			);
			const parsed = parseCertificateSigningRequestPemOrThrow(csr.pem);
			expect(Array.from(parsed.certificationRequestInfoDer)).toEqual(
				Array.from(sliceElement(csr.der, fieldAt(readDerSequenceOrThrow(csr.der), 0))),
			);
			expect(await verifyCertificateSigningRequest(csr.pem)).toMatchObject({ ok: true });
			const foreign = await createCertificateSigningRequest({
				subject: { commonName: 'other-structure.example' },
				publicKey: keyPair.publicKey,
				signerPrivateKey: keyPair.privateKey,
			});
			// RFC 2986 §4.1: `attributes [0]` is not OPTIONAL, so a request without any
			// still carries the field, empty.
			expectCertificationRequestStructure(foreign.der);
			expect(
				derChildrenOrThrow(
					foreign.der,
					fieldAt(
						derChildrenOrThrow(foreign.der, fieldAt(readDerSequenceOrThrow(foreign.der), 0)),
						3,
					),
				),
			).toEqual([]);
			const fields = readDerSequenceOrThrow(csr.der);
			const foreignSignature = derSequence([
				sliceElement(csr.der, fieldAt(fields, 0)),
				sliceElement(csr.der, fieldAt(fields, 1)),
				sliceElement(foreign.der, fieldAt(readDerSequenceOrThrow(foreign.der), 2)),
			]);
			expect(await verifyCertificateSigningRequest(foreignSignature)).toMatchObject({
				ok: false,
				code: 'signature_invalid',
			});
		});

		it('does not treat NEW CERTIFICATE REQUEST as equivalent to CERTIFICATE REQUEST', () => {
			// "The label 'NEW CERTIFICATE REQUEST' is also in wide use... Parsers MAY
			// treat 'NEW CERTIFICATE REQUEST' as equivalent to 'CERTIFICATE REQUEST'."
			// This parser takes the permission's other side, and Figure 18 carries
			// Figure 9's DER, so only the label decides.
			const figure18 = example('NEW CERTIFICATE REQUEST');
			expect(Array.from(pemDecodeOrThrow('NEW CERTIFICATE REQUEST', figure18))).toEqual(
				Array.from(figure9Der),
			);
			expect(splitPemBlocksOrThrow(figure18).map((block) => block.label)).toEqual([
				'NEW CERTIFICATE REQUEST',
			]);
			expect(pemDecode('CERTIFICATE REQUEST', figure18).ok).toBe(false);
			expect(parseCertificateSigningRequestPem(figure18).ok).toBe(false);
			expect(categorizePemBlocksOrThrow(figure18).certificateRequests).toEqual([]);
			expect(categorizePemBlocksOrThrow(figure18).others.map((block) => block.label)).toEqual([
				'NEW CERTIFICATE REQUEST',
			]);
			const relabelled = figure18.replaceAll('NEW CERTIFICATE REQUEST', 'CERTIFICATE REQUEST');
			expect(parseCertificateSigningRequestPemOrThrow(relabelled).subject.values.commonName).toBe(
				'josefsson.org',
			);
		});
	});

	describe('8. Textual Encoding of PKCS #7 Cryptographic Message Syntax', () => {
		const INTEGER = 0x02;
		const OCTET_STRING = 0x04;
		const NULL = 0x05;
		const OBJECT_IDENTIFIER = 0x06;
		const SEQUENCE = 0x30;
		const SET = 0x31;
		const CONTEXT_0_PRIMITIVE = 0x80;
		const CONTEXT_0_CONSTRUCTED = 0xa0;
		const CONTEXT_1_CONSTRUCTED = 0xa1;
		const ID_DATA = '1.2.840.113549.1.7.1';
		const ID_SIGNED_DATA = '1.2.840.113549.1.7.2';

		function fieldAt(fields: readonly DerElement[], index: number): DerElement {
			const field = fields.at(index);
			if (field === undefined) {
				throw new Error(`No DER field at index ${index}`);
			}
			return field;
		}

		/** Tags of the children of `element`, or of the root SEQUENCE when omitted. */
		function childTags(der: Uint8Array, element?: DerElement): readonly number[] {
			const children =
				element === undefined ? readDerSequenceOrThrow(der) : derChildrenOrThrow(der, element);
			return children.map((child) => child.tag);
		}

		/**
		 * RFC 2315 §7: `ContentInfo ::= SEQUENCE { contentType ContentType, content
		 * [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }`, where `ContentType
		 * ::= OBJECT IDENTIFIER`. Returns the contentType OID and the single
		 * element the tagged content field wraps.
		 */
		function expectContentInfoStructure(der: Uint8Array): {
			readonly contentTypeOid: string;
			readonly content: DerElement;
		} {
			const root = readDerRootOrThrow(der);
			expect(root.tag).toBe(SEQUENCE);
			expect(root.end).toBe(der.length);
			const fields = readDerSequenceOrThrow(der);
			expect(fields.map((field) => field.tag)).toEqual([OBJECT_IDENTIFIER, CONTEXT_0_CONSTRUCTED]);
			const content = fieldAt(fields, 1);
			expect(derChildrenOrThrow(der, content)).toHaveLength(1);
			return {
				contentTypeOid: decodeDerOidOrThrow(fieldAt(fields, 0)),
				content: fieldAt(derChildrenOrThrow(der, content), 0),
			};
		}

		/** The DER of `element`, identifier and length octets included. */
		function elementDer(der: Uint8Array, element: DerElement): Uint8Array {
			return der.slice(element.start - element.headerLength, element.end);
		}

		/** Wraps `signedData` in the ContentInfo that RFC 2315 §7 gives id-signedData. */
		function signedDataContentInfo(signedData: Uint8Array): Uint8Array {
			return derSequence([derOid(ID_SIGNED_DATA), derTlv(CONTEXT_0_CONSTRUCTED, signedData)]);
		}

		/** The SignedData fields of a signedData ContentInfo, in declaration order. */
		function signedDataFieldsOf(der: Uint8Array): readonly DerElement[] {
			return derChildrenOrThrow(der, expectContentInfoStructure(der).content);
		}

		/** Rebuilds `der` with the SignedData's `contentInfo` field replaced by `encap`. */
		function withEncapsulatedContentInfo(der: Uint8Array, encap: Uint8Array): Uint8Array {
			return signedDataContentInfo(
				derSequence(
					signedDataFieldsOf(der).map((field, index) =>
						index === 2 ? encap : elementDer(der, field),
					),
				),
			);
		}

		/** The Figure 10 PKCS #7 message, and the DER under its label. */
		const figure10 = example('PKCS7');
		const figure10Der = pemDecodeOrThrow('PKCS7', figure10);

		/**
		 * The RFC's figures that carry a ContentInfo: Figure 10 under `PKCS7`,
		 * Figure 11 under `CMS`, and Figure 19, which repeats Figure 10's octets
		 * under `CERTIFICATE CHAIN`.
		 */
		const contentInfoLabels = ['PKCS7', 'CMS', 'CERTIFICATE CHAIN'] as const;

		it('reads the Figure 10 data as an RFC 2315 ContentInfo', () => {
			// "The encoded data MUST be a BER-encoded ASN.1 ContentInfo structure as
			// described in [RFC2315]."
			const { contentTypeOid } = expectContentInfoStructure(figure10Der);
			expect(contentTypeOid).toBe('1.2.840.113549.1.9.16.1.23');
			expect(pemEncode('PKCS7', figure10Der)).toBe(`${figure10}\n`);
		});

		it('reads the Figure 10 contentType before refusing the content', () => {
			// The same MUST: Figure 10 is a ContentInfo, so refusing it is a verdict
			// on its contentType, which is not `id-signedData` (1.2.840.113549.1.7.2).
			for (const parsed of [
				parsePkcs7SignedDataPem(figure10),
				parsePkcs7SignedDataDer(figure10Der),
				parsePkcs7CertBagPem(figure10),
			]) {
				expect(parsed.ok).toBe(false);
				if (!parsed.ok) {
					expect(parsed.code).toBe('not_signed_data');
				}
			}
		});

		it('tells octets that are not a ContentInfo from a ContentInfo that is not signedData', () => {
			// The same MUST: the label alone does not make the octets a ContentInfo.
			// No figure in the RFC carries signedData, so each one relabelled as
			// PKCS7 has to come back as a typed failure, and only the three that are
			// ContentInfo values get as far as their contentType.
			for (const label of examples.keys()) {
				const relabelled = example(label).replaceAll(label, 'PKCS7');
				const bytes = pemDecodeOrThrow('PKCS7', relabelled);
				expect(Array.from(bytes)).toEqual(Array.from(pemDecodeOrThrow(label, example(label))));
				const isContentInfo = contentInfoLabels.some((known) => known === label);
				if (isContentInfo) {
					expect(childTags(bytes)).toEqual([OBJECT_IDENTIFIER, CONTEXT_0_CONSTRUCTED]);
				}
				const parsed = parsePkcs7SignedDataDer(bytes);
				expect({ label, ok: parsed.ok }).toEqual({ label, ok: false });
				if (!parsed.ok) {
					expect({ label, code: parsed.code }).toEqual({
						label,
						code: isContentInfo ? 'not_signed_data' : 'malformed',
					});
				}
			}
		});

		it('reads a ContentInfo whose optional content is omitted', () => {
			// The same MUST, at the other end of RFC 2315 §7: `content` is OPTIONAL,
			// so octets that stop after the contentType are still a ContentInfo, and
			// the verdict on them is about the content type rather than the shape.
			const omitted = parsePkcs7SignedDataDer(derSequence([derOid(ID_DATA)]));
			expect(omitted.ok).toBe(false);
			if (!omitted.ok) {
				expect(omitted.code).toBe('not_signed_data');
			}
			// A signedData ContentInfo without content carries no SignedData to read.
			const headless = parsePkcs7SignedDataDer(derSequence([derOid(ID_SIGNED_DATA)]));
			expect(headless.ok).toBe(false);
			if (!headless.ok) {
				expect(headless.code).toBe('malformed');
			}
		});

		it('refuses a content field whose context tag is primitive rather than EXPLICIT', () => {
			// The same MUST: RFC 2315 §7 tags `content` `[0] EXPLICIT`, so the tag is
			// constructed and holds the content value as an element. The same octets
			// under a primitive `[0]` are value octets, not a wrapped SignedData.
			const signedData = derSequence([
				derIntegerFromNumber(1),
				derSet([]),
				derSequence([derOid(ID_DATA)]),
				derSet([]),
			]);
			expect(unwrap(parsePkcs7SignedDataDer(signedDataContentInfo(signedData))).version).toBe(1);
			const primitive = parsePkcs7SignedDataDer(
				derSequence([derOid(ID_SIGNED_DATA), derTlv(CONTEXT_0_PRIMITIVE, signedData)]),
			);
			expect(primitive.ok).toBe(false);
			if (!primitive.ok) {
				expect(primitive.code).toBe('malformed');
			}
		});

		it('keeps the RFC 2315 §9.1 order of the optional certificates and crls fields', () => {
			// The same MUST reaches `SignedData ::= SEQUENCE { version Version,
			// digestAlgorithms DigestAlgorithmIdentifiers, contentInfo ContentInfo,
			// certificates [0] IMPLICIT ... OPTIONAL, crls [1] IMPLICIT ... OPTIONAL,
			// signerInfos SignerInfos }`, whose fields a SEQUENCE carries in that order.
			const signedData = (optional: readonly Uint8Array[]): Uint8Array =>
				signedDataContentInfo(
					derSequence([
						derIntegerFromNumber(1),
						derSet([]),
						derSequence([derOid(ID_DATA)]),
						...optional,
						derSet([]),
					]),
				);
			const certificates = derTlv(CONTEXT_0_CONSTRUCTED, Uint8Array.of());
			const crls = derTlv(CONTEXT_1_CONSTRUCTED, Uint8Array.of());
			const ordered = unwrap(parsePkcs7SignedDataDer(signedData([certificates, crls])));
			expect(ordered.certificateChoices).toEqual([]);
			expect(ordered.encapsulatedContentTypeOid).toBe(ID_DATA);
			const swapped = parsePkcs7SignedDataDer(signedData([crls, certificates]));
			expect(swapped.ok).toBe(false);
			if (!swapped.ok) {
				expect(swapped.code).toBe('malformed');
			}
		});

		it('refuses a signed contentInfo that is not the two-field SEQUENCE of RFC 2315 §7', () => {
			// The same MUST, applied to the ContentInfo that SignedData signs:
			// `ContentType ::= OBJECT IDENTIFIER`, and the `[0]` content is the last
			// field, so a non-OID contentType or a third field is not a ContentInfo.
			const eContent = derTlv(CONTEXT_0_CONSTRUCTED, derOctetString(Uint8Array.of(0x2a)));
			const malformedEncaps = [
				derSequence([derOctetString(derOid(ID_DATA)), eContent]),
				derSequence([derOid(ID_DATA), eContent, derTlv(CONTEXT_1_CONSTRUCTED, Uint8Array.of())]),
			] as const satisfies readonly Uint8Array[];
			for (const encap of malformedEncaps) {
				const parsed = parsePkcs7SignedDataDer(
					signedDataContentInfo(
						derSequence([derIntegerFromNumber(1), derSet([]), encap, derSet([])]),
					),
				);
				expect(parsed.ok).toBe(false);
				if (!parsed.ok) {
					expect(parsed.code).toBe('malformed');
				}
			}
		});

		it('reports a typed failure for an indefinite-length BER ContentInfo', () => {
			// The MUST asks for BER, and Figure 20 marks PKCS7 with "*": "indefinite-
			// length encoding enables one-pass processing (streaming) when generating
			// the encoding". This reader takes the definite-length subset and refuses
			// the rest as malformed instead of mis-reading it.
			const root = readDerRootOrThrow(figure10Der);
			const indefinite = Uint8Array.of(
				SEQUENCE,
				0x80,
				...figure10Der.slice(root.start, root.end),
				0x00,
				0x00,
			);
			const parsed = parsePkcs7SignedDataDer(indefinite);
			expect(parsed.ok).toBe(false);
			if (!parsed.ok) {
				expect(parsed.code).toBe('malformed');
			}
		});

		it('puts an RFC 2315 ContentInfo under each PKCS7 label it generates', async () => {
			// "PKCS #7 Cryptographic Message Syntax structures are encoded using the
			// 'PKCS7' label. The encoded data MUST be a BER-encoded ASN.1 ContentInfo
			// structure as described in [RFC2315]."
			const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
			const { certificate } = await createSelfSignedCertificate({
				subject: { commonName: 'pkcs7-contentinfo.example' },
				keyPair,
			});
			const signed = unwrap(
				await createPkcs7SignedData({
					content: new TextEncoder().encode('signed by micro509'),
					signers: [{ certificate: certificate.der, privateKey: keyPair.privateKey }],
				}),
			);
			expect(splitPemBlocksOrThrow(signed.pem).map((block) => block.label)).toEqual(['PKCS7']);
			expect(Array.from(pemDecodeOrThrow('PKCS7', signed.pem))).toEqual(Array.from(signed.der));
			expect(expectContentInfoStructure(signed.der).contentTypeOid).toBe(ID_SIGNED_DATA);
			expect(await verifyPkcs7SignedData(signed.pem)).toMatchObject({ ok: true });
			// The ContentInfo is the encoded data, so octets outside it are not part
			// of the encoding.
			expect(parsePkcs7SignedDataDer(Uint8Array.of(...signed.der, 0x00)).ok).toBe(false);
			expect(parsePkcs7SignedDataDer(signed.der.slice(0, signed.der.length - 1)).ok).toBe(false);
		});

		it('refuses an EXPLICIT content tag holding more than one value', async () => {
			// The same MUST: RFC 2315 §7 gives `content [0] EXPLICIT ANY DEFINED BY
			// contentType`, one value under the tag, and RFC 5652 §5.2 `eContent [0]
			// EXPLICIT OCTET STRING`. RFC 2315 §9.3 digests only the contents octets of
			// that value, so a second value under the same tag leaves the signed octets
			// untouched and two encodings would verify under one signature.
			const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
			const { certificate } = await createSelfSignedCertificate({
				subject: { commonName: 'econtent-tail.example' },
				keyPair,
			});
			const signed = unwrap(
				await createPkcs7SignedData({
					content: new TextEncoder().encode('one value under the tag'),
					signers: [{ certificate: certificate.der, privateKey: keyPair.privateKey }],
				}),
			);
			expect(await verifyPkcs7SignedData(signed.der)).toMatchObject({ ok: true });
			const encapFields = derChildrenOrThrow(
				signed.der,
				fieldAt(signedDataFieldsOf(signed.der), 2),
			);
			const eContent = fieldAt(derChildrenOrThrow(signed.der, fieldAt(encapFields, 1)), 0);
			expect(eContent.tag).toBe(OCTET_STRING);
			const stuffed = withEncapsulatedContentInfo(
				signed.der,
				derSequence([
					elementDer(signed.der, fieldAt(encapFields, 0)),
					derTlv(
						CONTEXT_0_CONSTRUCTED,
						concatBytes([elementDer(signed.der, eContent), derTlv(NULL, Uint8Array.of())]),
					),
				]),
			);
			const parsed = parsePkcs7SignedDataDer(stuffed);
			expect(parsed.ok).toBe(false);
			if (!parsed.ok) {
				expect(parsed.code).toBe('malformed');
			}
			expect(await verifyPkcs7SignedData(stuffed)).toMatchObject({
				ok: false,
				code: 'malformed',
			});
		});

		it('processes a version 0 SignedData as a version 1 value', async () => {
			// The same MUST reaches RFC 2315 §9.1 note 2: "Except for the difference in
			// version number, version 0 SignedData values are acceptable as version 1
			// values. An implementation can therefore process SignedData values of
			// either version as though they were version 1 values. It is suggested that
			// PKCS implementations generate only version 1 SignedData values, but be
			// prepared to process SignedData values of either version."
			const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
			const { certificate } = await createSelfSignedCertificate({
				subject: { commonName: 'pkcs7-version0.example' },
				keyPair,
			});
			const signed = unwrap(
				await createPkcs7SignedData({
					content: new TextEncoder().encode('version 0 is readable'),
					signers: [{ certificate: certificate.der, privateKey: keyPair.privateKey }],
				}),
			);
			const fields = signedDataFieldsOf(signed.der);
			expect(decodeDerIntegerOrThrow(fieldAt(fields, 0))).toBe(1);
			const version0 = signedDataContentInfo(
				derSequence([
					derIntegerFromNumber(0),
					...fields.slice(1).map((field) => elementDer(signed.der, field)),
				]),
			);
			const parsed = unwrap(parsePkcs7SignedDataPem(pemEncode('PKCS7', version0)));
			expect(parsed.version).toBe(0);
			expect(parsed.encapsulatedContentTypeOid).toBe(ID_DATA);
			expect(parsed.signerInfos.map((info) => info.hasSignedAttrs)).toEqual([true]);
			expect(await verifyPkcs7SignedData(version0)).toMatchObject({ ok: true });
		});

		it('encodes a degenerate certificates-only SignedData under the PKCS7 label', async () => {
			// "The label 'CERTIFICATE CHAIN' has been in use to denote a degenerate
			// PKCS #7 structure that contains only a list of certificates (see
			// Section 9 of [RFC2315])": that structure belongs under PKCS7, and
			// RFC 2315 §9.1 note 3 omits the content of the inner ContentInfo.
			const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
			const { certificate } = await createSelfSignedCertificate({
				subject: { commonName: 'pkcs7-bag.example' },
				keyPair,
			});
			const bag = unwrap(createPkcs7CertBag([certificate.der]));
			expect(splitPemBlocksOrThrow(bag.pem).map((block) => block.label)).toEqual(['PKCS7']);
			const { contentTypeOid, content } = expectContentInfoStructure(bag.der);
			expect(contentTypeOid).toBe(ID_SIGNED_DATA);
			// RFC 2315 §9.1: `SignedData ::= SEQUENCE { version Version,
			// digestAlgorithms DigestAlgorithmIdentifiers, contentInfo ContentInfo,
			// certificates [0] IMPLICIT ... OPTIONAL, crls [1] IMPLICIT ... OPTIONAL,
			// signerInfos SignerInfos }`.
			const signedDataFields = derChildrenOrThrow(bag.der, content);
			expect(signedDataFields.map((field) => field.tag)).toEqual([
				INTEGER,
				SET,
				SEQUENCE,
				CONTEXT_0_CONSTRUCTED,
				SET,
			]);
			// RFC 2315 §9.1: version "shall be 1 for this version of the document",
			// and both SET OF fields "may contain zero elements in version 1".
			expect(decodeDerIntegerOrThrow(fieldAt(signedDataFields, 0))).toBe(1);
			expect(derChildrenOrThrow(bag.der, fieldAt(signedDataFields, 1))).toHaveLength(0);
			expect(derChildrenOrThrow(bag.der, fieldAt(signedDataFields, 4))).toHaveLength(0);
			// RFC 2315 §9.1 note 3: with no signers "it is recommended ... that the
			// content type of the ContentInfo value being 'signed' be data, and the
			// content field of the ContentInfo value be omitted".
			const inner = fieldAt(signedDataFields, 2);
			expect(childTags(bag.der, inner)).toEqual([OBJECT_IDENTIFIER]);
			expect(decodeDerOidOrThrow(fieldAt(derChildrenOrThrow(bag.der, inner), 0))).toBe(ID_DATA);
			const parsed = unwrap(parsePkcs7CertBagPem(bag.pem));
			expect(parsed.map((entry) => entry.subject.values.commonName)).toEqual(['pkcs7-bag.example']);
			expect(unwrap(parsePkcs7SignedDataPem(bag.pem)).signerInfos).toEqual([]);
		});

		it('generates the CMS structure rather than the superseded PKCS #7 one', async () => {
			// "PKCS #7 is an old specification that has long been superseded by CMS
			// [RFC5652]. Implementations SHOULD NOT generate PKCS #7 when CMS is an
			// alternative." RFC 5652 §5.2 defines `eContent [0] EXPLICIT OCTET STRING
			// OPTIONAL` where RFC 2315 §7 has `content [0] EXPLICIT ANY DEFINED BY
			// contentType`, and RFC 5652 §5.1 takes version 3 when "encapContentInfo
			// eContentType is other than id-data", a version RFC 2315 §9.1 ("It shall
			// be 1 for this version of the document") never reaches.
			const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
			const { certificate } = await createSelfSignedCertificate({
				subject: { commonName: 'cms-shape.example' },
				keyPair,
			});
			const signer = { certificate: certificate.der, privateKey: keyPair.privateKey };
			const content = new TextEncoder().encode('superseded by CMS');
			const cases = [
				[ID_DATA, 1, undefined],
				['1.2.840.113549.1.9.16.1.4', 3, '1.2.840.113549.1.9.16.1.4'],
			] as const satisfies readonly (readonly [string, number, string | undefined])[];
			for (const [expectedContentTypeOid, expectedVersion, encapsulatedContentTypeOid] of cases) {
				const signed = unwrap(
					await createPkcs7SignedData({
						content,
						signers: [signer],
						...(encapsulatedContentTypeOid === undefined ? {} : { encapsulatedContentTypeOid }),
					}),
				);
				const signedData = expectContentInfoStructure(signed.der).content;
				const signedDataFields = derChildrenOrThrow(signed.der, signedData);
				expect(decodeDerIntegerOrThrow(fieldAt(signedDataFields, 0))).toBe(expectedVersion);
				const encapsulated = fieldAt(signedDataFields, 2);
				expect(childTags(signed.der, encapsulated)).toEqual([
					OBJECT_IDENTIFIER,
					CONTEXT_0_CONSTRUCTED,
				]);
				const encapsulatedFields = derChildrenOrThrow(signed.der, encapsulated);
				expect(decodeDerOidOrThrow(fieldAt(encapsulatedFields, 0))).toBe(expectedContentTypeOid);
				expect(childTags(signed.der, fieldAt(encapsulatedFields, 1))).toEqual([OCTET_STRING]);
				const parsed = unwrap(parsePkcs7SignedDataPem(signed.pem));
				expect(parsed.encapsulatedContentTypeOid).toBe(expectedContentTypeOid);
				expect(Array.from(parsed.encapsulatedContent ?? Uint8Array.of())).toEqual(
					Array.from(content),
				);
				// RFC 5652 §5.3 signs a SET OF authenticated attributes; RFC 2315 §9.2
				// leaves authenticatedAttributes optional.
				expect(parsed.signerInfos.map((info) => info.hasSignedAttrs)).toEqual([true]);
				expect(await verifyPkcs7SignedData(signed.pem)).toMatchObject({ ok: true });
			}
		});

		it('never generates the CERTIFICATE CHAIN label', async () => {
			// "Generators MUST NOT generate the 'CERTIFICATE CHAIN' label."
			const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
			const { certificate } = await createSelfSignedCertificate({
				subject: { commonName: 'pkcs7-label.example' },
				keyPair,
			});
			const emitted = [
				unwrap(createPkcs7CertBag([certificate.der])).pem,
				unwrap(
					await createPkcs7SignedData({
						content: new TextEncoder().encode('labelled'),
						signers: [{ certificate: certificate.der, privateKey: keyPair.privateKey }],
					}),
				).pem,
			];
			for (const pem of emitted) {
				expect(splitPemBlocksOrThrow(pem).map((block) => block.label)).toEqual(['PKCS7']);
				expect(pem.startsWith('-----BEGIN PKCS7-----\n')).toBe(true);
				expect(pem.endsWith('-----END PKCS7-----\n')).toBe(true);
				expect(pem).not.toContain('CERTIFICATE CHAIN');
			}
		});

		it('does not treat CERTIFICATE CHAIN as equivalent to PKCS7', () => {
			// "Parsers SHOULD NOT treat 'CERTIFICATE CHAIN' as equivalent to
			// 'PKCS7'." Figure 19 carries Figure 10's DER, so only the label differs,
			// and this parser takes the discouraged equivalence off the table.
			const figure19 = example('CERTIFICATE CHAIN');
			expect(Array.from(pemDecodeOrThrow('CERTIFICATE CHAIN', figure19))).toEqual(
				Array.from(figure10Der),
			);
			expect(pemDecode('PKCS7', figure19).ok).toBe(false);
			expect(splitPemBlocksOrThrow(figure19).map((block) => block.label)).toEqual([
				'CERTIFICATE CHAIN',
			]);
			expect(categorizePemBlocksOrThrow(figure19).others.map((block) => block.label)).toEqual([
				'CERTIFICATE CHAIN',
			]);
			expect(categorizePemBlocksOrThrow(figure19).certificates).toEqual([]);
		});

		it('refuses a degenerate PKCS #7 structure carrying the CERTIFICATE CHAIN label', async () => {
			// The same SHOULD NOT, against the structure the label denotes: a cert bag
			// that parses under PKCS7 has to stop being readable once relabelled.
			const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
			const { certificate } = await createSelfSignedCertificate({
				subject: { commonName: 'chain-label.example' },
				keyPair,
			});
			const bag = unwrap(createPkcs7CertBag([certificate.der]));
			expect(parsePkcs7CertBagPem(bag.pem).ok).toBe(true);
			const relabelled = bag.pem.replaceAll('PKCS7', 'CERTIFICATE CHAIN');
			expect(Array.from(pemDecodeOrThrow('CERTIFICATE CHAIN', relabelled))).toEqual(
				Array.from(bag.der),
			);
			for (const parsed of [
				parsePkcs7CertBagPem(relabelled),
				parsePkcs7SignedDataPem(relabelled),
			]) {
				expect(parsed.ok).toBe(false);
				if (!parsed.ok) {
					expect(parsed.code).toBe('malformed');
				}
			}
			expect(await verifyPkcs7SignedData(relabelled)).toMatchObject({
				ok: false,
				code: 'malformed',
			});
		});

		it('still splits a CERTIFICATE CHAIN block without malfunctioning', () => {
			// Section 2 requires parsers not to malfunction on data they do not accept.
			const blocks = splitPemBlocksOrThrow(example('CERTIFICATE CHAIN'));
			expect(blocks.map((block) => block.label)).toEqual(['CERTIFICATE CHAIN']);
			expect(categorizePemBlocksOrThrow(example('CERTIFICATE CHAIN')).others).toHaveLength(1);
		});
	});

	describe('9. Textual Encoding of Cryptographic Message Syntax', () => {
		const INTEGER = 0x02;
		const OBJECT_IDENTIFIER = 0x06;
		const OCTET_STRING = 0x04;
		const SEQUENCE = 0x30;
		const SET = 0x31;
		const CONTEXT_0_CONSTRUCTED = 0xa0;
		const INDEFINITE_LENGTH = 0x80;
		const ID_DATA = '1.2.840.113549.1.7.1';
		const ID_SIGNED_DATA = '1.2.840.113549.1.7.2';
		const ID_CONTENT_TYPE_ATTRIBUTE = '1.2.840.113549.1.9.3';
		const ID_MESSAGE_DIGEST_ATTRIBUTE = '1.2.840.113549.1.9.4';
		// RFC 5652 §3 and RFC 3274 §1.1, the eContentTypes Figure 11 and this block use.
		const ID_CT_CONTENT_INFO = '1.2.840.113549.1.9.16.1.6';
		const ID_CT_COMPRESSED_DATA = '1.2.840.113549.1.9.16.1.9';
		// RFC 3274 §2, the compression algorithm Figure 11 names.
		const ID_ALG_ZLIB_COMPRESS = '1.2.840.113549.1.9.16.3.8';
		// RFC 5754 §2 and RFC 8410 §3, the algorithms RFC 8419 §3.1 pairs for Ed25519.
		const ID_SHA512 = '2.16.840.1.101.3.4.2.3';
		const ID_ED25519 = '1.3.101.112';

		/** The Figure 11 CMS message, and the DER under its label. */
		const figure11 = example('CMS');
		const figure11Der = pemDecodeOrThrow('CMS', figure11);

		function fieldAt<Field>(fields: readonly Field[], index: number): Field {
			const field = fields.at(index);
			if (field === undefined) {
				throw new Error(`No DER field at index ${index}`);
			}
			return field;
		}

		/** The complete encoding of `element`, tag and length octets included. */
		function encodingOf(source: Uint8Array, element: DerElement): Uint8Array {
			return source.slice(element.start - element.headerLength, element.end);
		}

		/**
		 * X.690 §10.1: DER takes the definite form, in the fewest length octets
		 * that carry the length, for `element` and everything it contains.
		 */
		function expectMinimalDefiniteLengths(source: Uint8Array, element: DerElement): void {
			const length = element.end - element.start;
			const lengthOctets = length < 0x80 ? 1 : 1 + Math.ceil(length.toString(2).length / 8);
			expect(element.headerLength).toBe(1 + lengthOctets);
			if ((element.tag & 0x20) === 0) return;
			for (const child of derChildrenOrThrow(source, element)) {
				expectMinimalDefiniteLengths(source, child);
			}
		}

		/** X.690 §11.6 ordering over two zero-padded encodings of equal width. */
		function compareOctets(left: readonly number[], right: readonly number[]): number {
			for (const [index, octet] of left.entries()) {
				const other = right[index] ?? 0;
				if (octet !== other) return octet - other;
			}
			return 0;
		}

		/**
		 * RFC 5652 §3: `ContentInfo ::= SEQUENCE { contentType ContentType, content
		 * [0] EXPLICIT ANY DEFINED BY contentType }`. Unlike RFC 2315 §7, neither
		 * field is OPTIONAL. Returns the contentType OID and the single element the
		 * tagged content field wraps.
		 */
		function expectContentInfoStructure(der: Uint8Array): {
			readonly contentTypeOid: string;
			readonly content: DerElement;
		} {
			const root = readDerRootOrThrow(der);
			expect(root.tag).toBe(SEQUENCE);
			expect(root.end).toBe(der.length);
			const fields = readDerSequenceOrThrow(der);
			expect(fields.map((field) => field.tag)).toEqual([OBJECT_IDENTIFIER, CONTEXT_0_CONSTRUCTED]);
			const wrapped = derChildrenOrThrow(der, fieldAt(fields, 1));
			expect(wrapped).toHaveLength(1);
			return {
				contentTypeOid: decodeDerOidOrThrow(fieldAt(fields, 0)),
				content: fieldAt(wrapped, 0),
			};
		}

		/** One decoded `Attribute` from a SignerInfo signedAttrs field. */
		interface SignedAttribute {
			readonly oid: string;
			readonly values: readonly DerElement[];
			readonly encoding: Uint8Array;
		}

		/**
		 * RFC 5652 §5.3: `SignedAttributes ::= SET SIZE (1..MAX) OF Attribute`,
		 * where `Attribute ::= SEQUENCE { attrType OBJECT IDENTIFIER, attrValues SET
		 * OF AttributeValue }`, carried under the IMPLICIT [0] tag.
		 */
		function signedAttributesOf(attrs: Uint8Array): readonly SignedAttribute[] {
			const root = readDerRootOrThrow(attrs);
			expect(root.tag).toBe(CONTEXT_0_CONSTRUCTED);
			expect(root.end).toBe(attrs.length);
			return derChildrenOrThrow(attrs, root).map((attribute) => {
				expect(attribute.tag).toBe(SEQUENCE);
				const fields = derChildrenOrThrow(attrs, attribute);
				expect(fields.map((field) => field.tag)).toEqual([OBJECT_IDENTIFIER, SET]);
				return {
					oid: decodeDerOidOrThrow(fieldAt(fields, 0)),
					values: derChildrenOrThrow(attrs, fieldAt(fields, 1)),
					encoding: encodingOf(attrs, attribute),
				};
			});
		}

		/** The signedAttrs DER of the one SignerInfo in `pem`. */
		function signedAttrsOf(pem: string): Uint8Array {
			const parsed = unwrap(parsePkcs7SignedDataPem(pem));
			expect(parsed.signerInfos.map((info) => info.hasSignedAttrs)).toEqual([true]);
			const attrs = parsed.signerInfos[0]?.signedAttrsDer;
			if (attrs === undefined) {
				throw new Error('SignerInfo carries no signedAttrs');
			}
			return attrs;
		}

		/** A SignedData over `content`, signed by a fresh self-signed certificate. */
		async function signContent(
			commonName: string,
			content: Uint8Array,
			encapsulatedContentTypeOid?: string,
		): Promise<{ readonly der: Uint8Array; readonly pem: string }> {
			const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
			const { certificate } = await createSelfSignedCertificate({
				subject: { commonName },
				keyPair,
			});
			return unwrap(
				await createPkcs7SignedData({
					content,
					signers: [{ certificate: certificate.der, privateKey: keyPair.privateKey }],
					...(encapsulatedContentTypeOid === undefined ? {} : { encapsulatedContentTypeOid }),
				}),
			);
		}

		it('reads Figure 11 as an RFC 5652 ContentInfo', () => {
			// "The encoded data MUST be a BER-encoded ASN.1 ContentInfo structure as
			// described in [RFC5652]." Figure 11 carries id-ct-compressedData, whose
			// RFC 3274 §1.1 `CompressedData ::= SEQUENCE { version CMSVersion,
			// compressionAlgorithm CompressionAlgorithmIdentifier, encapContentInfo
			// EncapsulatedContentInfo }` has a version that "MUST be 0".
			const { contentTypeOid, content } = expectContentInfoStructure(figure11Der);
			expect(contentTypeOid).toBe(ID_CT_COMPRESSED_DATA);
			expect(content.tag).toBe(SEQUENCE);
			const compressedData = derChildrenOrThrow(figure11Der, content);
			expect(compressedData.map((field) => field.tag)).toEqual([INTEGER, SEQUENCE, SEQUENCE]);
			expect(decodeDerIntegerOrThrow(fieldAt(compressedData, 0))).toBe(0);
			// RFC 3274 §2 names ZLIB id-alg-zlibCompress: "This algorithm has no
			// parameters. The parameters field SHOULD be encoded as omitted".
			const compressionAlgorithm = derChildrenOrThrow(figure11Der, fieldAt(compressedData, 1));
			expect(compressionAlgorithm.map((field) => field.tag)).toEqual([OBJECT_IDENTIFIER]);
			expect(decodeDerOidOrThrow(fieldAt(compressionAlgorithm, 0))).toBe(ID_ALG_ZLIB_COMPRESS);
			// RFC 5652 §5.2: `EncapsulatedContentInfo ::= SEQUENCE { eContentType
			// ContentType, eContent [0] EXPLICIT OCTET STRING OPTIONAL }`.
			const encapsulated = derChildrenOrThrow(figure11Der, fieldAt(compressedData, 2));
			expect(encapsulated.map((field) => field.tag)).toEqual([
				OBJECT_IDENTIFIER,
				CONTEXT_0_CONSTRUCTED,
			]);
			expect(decodeDerOidOrThrow(fieldAt(encapsulated, 0))).toBe(ID_DATA);
			const eContent = derChildrenOrThrow(figure11Der, fieldAt(encapsulated, 1));
			expect(eContent.map((field) => field.tag)).toEqual([OCTET_STRING]);
			expect(fieldAt(eContent, 0).end).toBe(figure11Der.length);
			expect(pemEncode('CMS', figure11Der)).toBe(`${figure11}\n`);
		});

		it('reads the Figure 11 contentType through the CMS label', () => {
			// "Cryptographic Message Syntax structures are encoded using the 'CMS'
			// label." Figure 11 is a ContentInfo, so every verdict on it is a verdict
			// on its contentType, which is not id-signedData, and reaching that
			// verdict means the CMS label was read rather than refused.
			expect(pemDecode('PKCS7', figure11).ok).toBe(false);
			expect(splitPemBlocksOrThrow(figure11).map((block) => block.label)).toEqual(['CMS']);
			for (const parsed of [
				parsePkcs7SignedDataPem(figure11),
				parsePkcs7SignedDataDer(figure11Der),
				parsePkcs7CertBagPem(figure11),
			]) {
				expect(parsed.ok).toBe(false);
				if (!parsed.ok) {
					expect(parsed.code).toBe('not_signed_data');
				}
			}
		});

		it('requires the content field RFC 5652 does not make optional', async () => {
			// The same MUST: RFC 5652 §3 has no OPTIONAL on `content`, where RFC 2315
			// §7 does, so octets that stop after the contentType are not a ContentInfo
			// "as described in [RFC5652]", and neither are a ContentInfo plus trailing
			// octets or one cut short.
			const headless = pemEncode('CMS', derSequence([derOid(ID_SIGNED_DATA)]));
			for (const parsed of [parsePkcs7SignedDataPem(headless), parsePkcs7CertBagPem(headless)]) {
				expect(parsed.ok).toBe(false);
				if (!parsed.ok) {
					expect(parsed.code).toBe('malformed');
				}
			}
			const signed = await signContent('cms-bounds.example', new TextEncoder().encode('bounded'));
			expect(parsePkcs7SignedDataPem(pemEncode('CMS', signed.der)).ok).toBe(true);
			expect(parsePkcs7SignedDataDer(Uint8Array.of(...signed.der, 0x00)).ok).toBe(false);
			expect(parsePkcs7SignedDataDer(signed.der.slice(0, signed.der.length - 1)).ok).toBe(false);
		});

		it('reports a typed failure for an indefinite-length BER CMS ContentInfo', () => {
			// The MUST asks for BER, and Figure 20 marks CMS with "*": "Cryptographic
			// Message Syntax is designed for content of any length; indefinite-length
			// encoding enables one-pass processing (streaming) when generating the
			// encoding." This reader takes the definite-length subset and refuses the
			// rest as malformed instead of mis-reading it.
			const root = readDerRootOrThrow(figure11Der);
			const indefinite = Uint8Array.of(
				SEQUENCE,
				INDEFINITE_LENGTH,
				...figure11Der.slice(root.start, root.end),
				0x00,
				0x00,
			);
			const parsed = parsePkcs7SignedDataPem(pemEncode('CMS', indefinite));
			expect(parsed.ok).toBe(false);
			if (!parsed.ok) {
				expect(parsed.code).toBe('malformed');
			}
		});

		it('armors a SignedData only RFC 5652 describes under the CMS label', async () => {
			// "Implementations SHOULD generate CMS when it is an alternative,
			// promoting interoperability and forwards-compatibility." RFC 5652 §5.1
			// takes version 3 when "encapContentInfo eContentType is other than
			// id-data", which RFC 2315 §9.1 ("It shall be 1 for this version of the
			// document") never reaches, so §8's PKCS7 label is not available to it.
			const content = new TextEncoder().encode('successor to PKCS #7');
			const cmsOnly = await signContent('cms-label.example', content, '1.2.840.113549.1.9.16.1.9');
			expect(splitPemBlocksOrThrow(cmsOnly.pem).map((block) => block.label)).toEqual(['CMS']);
			expect(pemDecode('PKCS7', cmsOnly.pem).ok).toBe(false);
			expect(Array.from(pemDecodeOrThrow('CMS', cmsOnly.pem))).toEqual(Array.from(cmsOnly.der));
			const { contentTypeOid, content: signedData } = expectContentInfoStructure(cmsOnly.der);
			expect(contentTypeOid).toBe(ID_SIGNED_DATA);
			expect(decodeDerIntegerOrThrow(fieldAt(derChildrenOrThrow(cmsOnly.der, signedData), 0))).toBe(
				3,
			);
			const parsed = unwrap(parsePkcs7SignedDataPem(cmsOnly.pem));
			expect(parsed.encapsulatedContentTypeOid).toBe('1.2.840.113549.1.9.16.1.9');
			expect(await verifyPkcs7SignedData(cmsOnly.pem)).toMatchObject({ ok: true });
			// A version 1 SignedData is also an RFC 2315 structure, so §8's label
			// still describes it, and one file holding both is not one ContentInfo.
			const dual = await signContent('pkcs7-label.example', content);
			expect(splitPemBlocksOrThrow(dual.pem).map((block) => block.label)).toEqual(['PKCS7']);
			const dualSignedData = expectContentInfoStructure(dual.der).content;
			expect(
				decodeDerIntegerOrThrow(fieldAt(derChildrenOrThrow(dual.der, dualSignedData), 0)),
			).toBe(1);
			expect(unwrap(parsePkcs7SignedDataPem(dual.pem)).encapsulatedContentTypeOid).toBe(ID_DATA);
			const both = parsePkcs7SignedDataPem(`${cmsOnly.pem}${dual.pem}`);
			expect(both.ok).toBe(false);
			if (!both.ok) {
				expect(both.code).toBe('malformed');
			}
		});

		it('DER-encodes the signed attributes inside the CMS structure', async () => {
			// Figure 20's "*" leaves CMS free of the DER requirement except that
			// "only certain parts -- namely, signed and authenticated attributes --
			// need to be DER encoded", which RFC 5652 §5.4 states as the digest being
			// "the message digest of the complete DER encoding of the SignedAttrs
			// value". X.690 §11.6 orders a DER SET OF by its members' encodings, and
			// RFC 5652 §11.1 pins the content-type attribute to the eContentType.
			for (const eContentTypeOid of [ID_DATA, ID_CT_COMPRESSED_DATA]) {
				const signed = await signContent(
					'cms-attrs.example',
					new TextEncoder().encode('signed attributes'),
					eContentTypeOid,
				);
				const attrs = signedAttrsOf(signed.pem);
				expectMinimalDefiniteLengths(attrs, readDerRootOrThrow(attrs));
				const attributes = signedAttributesOf(attrs);
				expect(attributes.map((attribute) => attribute.oid)).toEqual([
					ID_CONTENT_TYPE_ATTRIBUTE,
					ID_MESSAGE_DIGEST_ATTRIBUTE,
				]);
				// X.690 §11.6: ascending order, "the encodings being compared as octet
				// strings with the shorter components being padded at their trailing end
				// with 0-octets".
				const width = Math.max(...attributes.map((attribute) => attribute.encoding.length));
				const padded = attributes.map((attribute) => {
					const wide = new Uint8Array(width);
					wide.set(attribute.encoding);
					return Array.from(wide);
				});
				expect([...padded].sort((left, right) => compareOctets(left, right))).toEqual(padded);
				// RFC 5652 §11.1: the content-type attribute "MUST match the
				// encapContentInfo eContentType", and each attribute holds one value.
				expect(attributes.map((attribute) => attribute.values.length)).toEqual([1, 1]);
				const contentType = decodeDerOidOrThrow(fieldAt(fieldAt(attributes, 0).values, 0));
				expect(contentType).toBe(eContentTypeOid);
				expect(contentType).toBe(
					unwrap(parsePkcs7SignedDataPem(signed.pem)).encapsulatedContentTypeOid,
				);
				expect(fieldAt(fieldAt(attributes, 1).values, 0).tag).toBe(OCTET_STRING);
			}
		});

		it('signs the EXPLICIT SET OF encoding of the signed attributes, not the IMPLICIT [0] one', async () => {
			// RFC 5652 §5.4: "A separate encoding of the signedAttrs field is
			// performed for message digest calculation. The IMPLICIT [0] tag in the
			// signedAttrs is not used for the DER encoding, rather an EXPLICIT SET OF
			// tag is used. That is, the DER encoding of the EXPLICIT SET OF tag,
			// rather than of the IMPLICIT [0] tag, MUST be included in the message
			// digest calculation along with the length and content octets of the
			// SignedAttributes value." RFC 8419 §3.1: "The SignerInfo signature field
			// contains the octet string resulting from the EdDSA private key signing
			// operation", so the signature verifies directly against each candidate
			// encoding.
			const keyPair = await generateKeyPair({ kind: 'ed25519' });
			const { certificate } = await createSelfSignedCertificate({
				subject: { commonName: 'cms-retag.example' },
				keyPair,
			});
			const signed = unwrap(
				await createPkcs7SignedData({
					content: new TextEncoder().encode('re-tagged for signing'),
					signers: [{ certificate: certificate.der, privateKey: keyPair.privateKey }],
					encapsulatedContentTypeOid: ID_CT_COMPRESSED_DATA,
				}),
			);
			expect(splitPemBlocksOrThrow(signed.pem).map((block) => block.label)).toEqual(['CMS']);
			const parsed = unwrap(parsePkcs7SignedDataPem(signed.pem));
			const signerCertificate = fieldAt(parsed.certificateChoices, 0);
			if (signerCertificate.type !== 'certificate') {
				throw new Error('SignedData carries no X.509 signer certificate');
			}
			const publicKey = await getSubjectPublicKeyOrThrow(signerCertificate.certificate);
			// RFC 8419 §3.1: "When signing with Ed25519, the digestAlgorithm MUST be
			// id-sha512", and "The SignerInfo signatureAlgorithm field MUST contain
			// either id-Ed25519 or id-Ed448 ... The algorithm parameters field MUST be
			// absent."
			const signerInfo = fieldAt(parsed.signerInfos, 0);
			expect(signerInfo.digestAlgorithmOid).toBe(ID_SHA512);
			expect(signerInfo.signatureAlgorithmOid).toBe(ID_ED25519);
			expect(signerInfo.signatureAlgorithmParametersDer).toBeUndefined();
			const implicitAttrs = signedAttrsOf(signed.pem);
			expect(implicitAttrs[0]).toBe(CONTEXT_0_CONSTRUCTED);
			const explicitAttrs = Uint8Array.of(SET, ...implicitAttrs.slice(1));
			const signature = Uint8Array.from(signerInfo.signature);
			expect(
				await globalThis.crypto.subtle.verify(
					'Ed25519',
					publicKey,
					signature,
					Uint8Array.from(explicitAttrs),
				),
			).toBe(true);
			expect(
				await globalThis.crypto.subtle.verify(
					'Ed25519',
					publicKey,
					signature,
					Uint8Array.from(implicitAttrs),
				),
			).toBe(false);
			expect(await verifyPkcs7SignedData(signed.pem)).toMatchObject({ ok: true });
		});

		it('omits eContent for an external signature and signs as though it were present', async () => {
			// RFC 5652 §5.2: "The optional omission of the eContent within the
			// EncapsulatedContentInfo field makes it possible to construct 'external
			// signatures'. ... If the eContent value within EncapsulatedContentInfo is
			// absent, then the signatureValue is calculated and the eContentType is
			// assigned as though the eContent value was present."
			const content = new TextEncoder().encode('external signature');
			const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
			const { certificate } = await createSelfSignedCertificate({
				subject: { commonName: 'cms-detached.example' },
				keyPair,
			});
			const signer = { certificate: certificate.der, privateKey: keyPair.privateKey };
			const attached = unwrap(
				await createPkcs7SignedData({
					content,
					signers: [signer],
					encapsulatedContentTypeOid: ID_CT_COMPRESSED_DATA,
				}),
			);
			const detached = unwrap(
				await createPkcs7SignedData({
					content,
					signers: [signer],
					encapsulatedContentTypeOid: ID_CT_COMPRESSED_DATA,
					detached: true,
				}),
			);
			expect(splitPemBlocksOrThrow(detached.pem).map((block) => block.label)).toEqual(['CMS']);
			const signedData = expectContentInfoStructure(detached.der).content;
			const encapsulated = derChildrenOrThrow(
				detached.der,
				fieldAt(derChildrenOrThrow(detached.der, signedData), 2),
			);
			expect(encapsulated.map((field) => field.tag)).toEqual([OBJECT_IDENTIFIER]);
			expect(decodeDerOidOrThrow(fieldAt(encapsulated, 0))).toBe(ID_CT_COMPRESSED_DATA);
			const parsed = unwrap(parsePkcs7SignedDataPem(detached.pem));
			expect(parsed.encapsulatedContent).toBeUndefined();
			expect(parsed.encapsulatedContentTypeOid).toBe(ID_CT_COMPRESSED_DATA);
			expect(Array.from(signedAttrsOf(detached.pem))).toEqual(
				Array.from(signedAttrsOf(attached.pem)),
			);
			expect(await verifyPkcs7SignedData(detached.pem)).toMatchObject({
				ok: false,
				code: 'detached_content_required',
			});
			expect(await verifyPkcs7SignedData(detached.pem, { content })).toMatchObject({ ok: true });
			expect(
				await verifyPkcs7SignedData(detached.pem, {
					content: new TextEncoder().encode('other bytes'),
				}),
			).toMatchObject({ ok: false, code: 'message_digest_mismatch' });
		});

		it('digests the whole encapsulated encoding the way CMS does', async () => {
			// "CMS is the IETF successor to PKCS #7. Section 1.1.1 of [RFC5652]
			// describes the changes since PKCS #7 v1.5", which points at §5.2.1:
			// "There are incompatibilities between the CMS and PKCS #7 SignedData
			// types when the encapsulated content is not formatted using the Data
			// type." CMS carries the content in `eContent [0] EXPLICIT OCTET STRING`
			// and digests "the entire Receipt SEQUENCE encoding (including tag,
			// length and value octets)", where PKCS #7's `content [0] EXPLICIT ANY`
			// digests "only the value octets".
			const signed = await signContent('cms-digest.example', figure11Der, ID_CT_CONTENT_INFO);
			const parsed = unwrap(parsePkcs7SignedDataPem(signed.pem));
			expect(parsed.encapsulatedContentTypeOid).toBe(ID_CT_CONTENT_INFO);
			expect(Array.from(parsed.encapsulatedContent ?? Uint8Array.of())).toEqual(
				Array.from(figure11Der),
			);
			const digested = fieldAt(fieldAt(signedAttributesOf(signedAttrsOf(signed.pem)), 1).values, 0);
			const wholeEncoding = new Uint8Array(
				await globalThis.crypto.subtle.digest('SHA-256', Uint8Array.from(figure11Der)),
			);
			const valueOctets = new Uint8Array(
				await globalThis.crypto.subtle.digest(
					'SHA-256',
					Uint8Array.from(readDerRootOrThrow(figure11Der).value),
				),
			);
			expect(Array.from(digested.value)).toEqual(Array.from(wholeEncoding));
			expect(Array.from(digested.value)).not.toEqual(Array.from(valueOctets));
			expect(await verifyPkcs7SignedData(signed.pem)).toMatchObject({ ok: true });
		});
	});

	describe('10. One Asymmetric Key and the Textual Encoding of PKCS #8 Private Key Info', () => {
		const figure12 = example('PRIVATE KEY');
		const figure12Der = pemDecodeOrThrow('PRIVATE KEY', figure12);

		function nthField(fields: readonly DerElement[], index: number): DerElement {
			const field = fields[index];
			if (field === undefined) throw new Error(`no DER field at index ${index}`);
			return field;
		}

		/**
		 * A generated v1 PrivateKeyInfo, everything in it after the version INTEGER,
		 * and the `publicKey [1]` of its own key pair.
		 *
		 * RFC 5958 §2 tags `publicKey [1]` IMPLICIT over `PublicKey ::= BIT STRING`,
		 * so the field content is the `subjectPublicKey` BIT STRING content of the
		 * matching SubjectPublicKeyInfo, unused-bit count included.
		 */
		async function generatedKey(): Promise<{
			readonly v1: Uint8Array;
			readonly body: Uint8Array;
			readonly publicKey: Uint8Array;
		}> {
			const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
			const v1 = await keyPair.exportPkcs8Der();
			const subjectPublicKey = nthField(
				readDerSequenceOrThrow(await exportSpkiDer(keyPair.publicKey)),
				1,
			);
			return {
				v1,
				body: v1.slice(nthField(readDerSequenceOrThrow(v1), 0).end),
				publicKey: derTlv(0x81, subjectPublicKey.value),
			};
		}

		it('reads Figure 12 as the PrivateKeyInfo structure PKCS #8 describes', () => {
			// "The encoded data MUST be a BER (DER preferred; see Appendix B) encoded
			// ASN.1 PrivateKeyInfo structure as described in PKCS #8 [RFC5208]".
			// RFC 5208 §5: PrivateKeyInfo ::= SEQUENCE { version Version,
			// privateKeyAlgorithm PrivateKeyAlgorithmIdentifier, privateKey
			// PrivateKey, attributes [0] IMPLICIT Attributes OPTIONAL }, with
			// PrivateKey ::= OCTET STRING.
			const fields = readDerSequenceOrThrow(figure12Der);
			expect(fields.map((field) => field.tag)).toEqual([0x02, 0x30, 0x04]);
			const algorithm = derChildrenOrThrow(figure12Der, nthField(fields, 1));
			expect(algorithm.map((field) => field.tag)).toEqual([0x06, 0x06]);
			expect(decodeDerOidOrThrow(nthField(algorithm, 0))).toBe('1.2.840.10045.2.1');
			expect(decodeDerOidOrThrow(nthField(algorithm, 1))).toBe('1.3.132.0.10');
			// RFC 5208 §5: "privateKey is an octet string whose contents are the
			// value of the private key. The interpretation of the contents is
			// defined in the registration of the private-key algorithm." RFC 5958 §2
			// registers id-ecPublicKey's as "ECPrivateKey as defined in [RFC5915]",
			// whose version is ecPrivkeyVer1(1).
			const ecPrivateKey = readDerSequenceOrThrow(nthField(fields, 2).value);
			expect(decodeDerIntegerOrThrow(nthField(ecPrivateKey, 0))).toBe(1);
			expect(nthField(ecPrivateKey, 1).value).toHaveLength(32);
		});

		it('distinguishes v1 PrivateKeyInfo from v2 OneAsymmetricKey by version number', async () => {
			// "The two are semantically identical and can be distinguished by version
			// number." RFC 5958 §2: "If publicKey is present, then version is set to
			// v2 else version is set to v1", over Version ::= INTEGER { v1(0), v2(1) }.
			// Figure 12 carries neither v2 field, and declares v1.
			const figure12Fields = readDerSequenceOrThrow(figure12Der);
			expect(figure12Fields).toHaveLength(3);
			expect(decodeDerIntegerOrThrow(nthField(figure12Fields, 0))).toBe(0);

			const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
			const exported = await keyPair.exportPkcs8Der();
			const exportedFields = readDerSequenceOrThrow(exported);
			expect(exportedFields).toHaveLength(3);
			expect(decodeDerIntegerOrThrow(nthField(exportedFields, 0))).toBe(0);

			// Everything after the version INTEGER, so the two rebuilds differ in
			// nothing but the version number.
			const body = exported.slice(nthField(exportedFields, 0).end);
			const ecdsa = { kind: 'ecdsa', curve: 'P-256' } as const;
			expect((await importPkcs8Der(derSequence([derIntegerFromNumber(0), body]), ecdsa)).ok).toBe(
				true,
			);
			// An accepted structure is checked against the requested algorithm next,
			// and reports the mismatch under its own message. Reaching the malformed
			// one instead pins the refusal on the version number.
			const restamped = derSequence([derIntegerFromNumber(1), body]);
			const rejected = await importPkcs8Der(restamped, { kind: 'rsa' });
			expect(rejected.ok).toBe(false);
			if (!rejected.ok) {
				expect(rejected.code).toBe('malformed');
				expect(rejected.message).toBe('Malformed PKCS#8 private key');
			}
			const mismatched = await importPkcs8Der(derSequence([derIntegerFromNumber(0), body]), {
				kind: 'rsa',
			});
			expect(mismatched.ok).toBe(false);
			if (!mismatched.ok) {
				expect(mismatched.message).toBe(
					'PKCS#8 private key algorithm does not match requested import algorithm',
				);
			}

			// The pairing runs the other way too: a structure carrying publicKey [1]
			// declares v2, so the same fields stamped v1 are no PrivateKeyInfo either.
			const { body: freshBody, publicKey } = await generatedKey();
			const understamped = await importPkcs8Der(
				derSequence([derIntegerFromNumber(0), freshBody, publicKey]),
			);
			expect(understamped.ok).toBe(false);
			if (!understamped.ok) {
				expect(understamped.message).toBe('Malformed PKCS#8 private key');
			}
		});

		it('reads a v2 OneAsymmetricKey under the label a v1 PrivateKeyInfo uses', async () => {
			// "The encoded data MUST be a BER (DER preferred; see Appendix B) encoded
			// ASN.1 PrivateKeyInfo structure as described in PKCS #8 [RFC5208], or a
			// OneAsymmetricKey structure as described in [RFC5958]. The two are
			// semantically identical and can be distinguished by version number."
			// RFC 5958 §2 adds "[[2: publicKey [1] PublicKey OPTIONAL ]]" and sets
			// the version to v2 when the field is present.
			const { v1, body, publicKey } = await generatedKey();
			const v2 = derSequence([derIntegerFromNumber(1), body, publicKey]);
			const imported = await importPkcs8Pem(pemEncode('PRIVATE KEY', v2));
			expect(imported.ok).toBe(true);
			if (imported.ok) {
				// Semantically identical: the v2 printing reads back as the same key
				// the v1 printing carries.
				expect(Array.from(await exportPkcs8Der(imported.value))).toEqual(Array.from(v1));
			}

			// RFC 5958 §2: publicKey "contains the public key encoded in a BIT
			// STRING", so one that is not the private key's own is not this key's
			// OneAsymmetricKey.
			const foreign = (await generatedKey()).publicKey;
			const crossed = await importPkcs8Der(derSequence([derIntegerFromNumber(1), body, foreign]));
			expect(crossed.ok).toBe(false);
			if (!crossed.ok) {
				expect(crossed.message).toBe('PKCS#8 publicKey does not match the private key');
			}
		});

		it('reads the optional attributes field PKCS #8 gives PrivateKeyInfo', async () => {
			// RFC 5208 §5: "PrivateKeyInfo ::= SEQUENCE { [...] attributes [0]
			// IMPLICIT Attributes OPTIONAL }" over "Attributes ::= SET OF Attribute",
			// which RFC 5958 §2 leaves a v1 field and opens to "Attributes from
			// [RFC2985]". RFC 2985 §5.5.1 types friendlyName (1.2.840.113549.1.9.20)
			// as a single BMPString value.
			const { v1, body } = await generatedKey();
			const friendlyName = derSequence([
				derOid('1.2.840.113549.1.9.20'),
				derSet([derTlv(0x1e, Uint8Array.of(0x00, 0x6b))]),
			]);
			const withAttributes = derSequence([
				derIntegerFromNumber(0),
				body,
				derTlv(0xa0, friendlyName),
			]);
			const imported = await importPkcs8Der(withAttributes);
			expect(imported.ok).toBe(true);
			if (imported.ok) {
				expect(Array.from(await exportPkcs8Der(imported.value))).toEqual(Array.from(v1));
			}
		});

		it('reads the PrivateKeyInfo and nothing beyond it', async () => {
			// The encoded data is the PrivateKeyInfo structure, so octets outside it
			// are not part of the encoding.
			const { v1 } = await generatedKey();
			expect((await importPkcs8Der(v1)).ok).toBe(true);
			expect((await importPkcs8Der(Uint8Array.of(...v1, 0x00))).ok).toBe(false);
			expect((await importPkcs8Der(v1.slice(0, v1.length - 1))).ok).toBe(false);
		});

		it('reads only the definite-length form of the PrivateKeyInfo', async () => {
			// "DER preferred; see Appendix B", whose Figure 20 gives PRIVATE KEY
			// reason 3: "the content is small. DER always encodes data values in
			// definite-length form (where the length is stated at the beginning of
			// the encoding); thus, a parser can anticipate memory or resource usage
			// up front."
			const { v1 } = await generatedKey();
			const root = readDerRootOrThrow(v1);
			const indefinite = Uint8Array.of(0x30, 0x80, ...v1.slice(root.start, root.end), 0x00, 0x00);
			expect((await importPkcs8Der(v1)).ok).toBe(true);
			expect((await importPkcs8Der(indefinite)).ok).toBe(false);
		});

		it('reads the privateKeyAlgorithm of Figure 12 before refusing the key', async () => {
			// Figure 12 carries secp256k1 (1.3.132.0.10), which WebCrypto does not
			// implement, so no supported PrivateKeyImportInput describes this key.
			// Reaching "unsupported algorithm" rather than "malformed" means the
			// PrivateKeyInfo was decoded and its privateKeyAlgorithm read.
			const inferred = await importPkcs8Pem(figure12);
			expect(inferred.ok).toBe(false);
			if (!inferred.ok) {
				expect(inferred.code).toBe('malformed');
				expect(inferred.message).toBe('Unsupported PKCS#8 private key algorithm');
			}
		});

		it('refuses to import it under a curve it is not on', async () => {
			let message: string | undefined;
			try {
				await importPkcs8PemOrThrow(figure12, { kind: 'ecdsa', curve: 'P-256' });
			} catch (error) {
				message = error instanceof Error ? error.message : String(error);
			}
			expect(message).toContain('does not match requested import algorithm');
		});

		it('refuses a PRIVATE KEY block that does not hold a PrivateKeyInfo', async () => {
			// The label alone does not license the payload: the encoded data "MUST be
			// [...] PrivateKeyInfo [...] or a OneAsymmetricKey structure".
			const relabelled = pemEncode(
				'PRIVATE KEY',
				pemDecodeOrThrow('CERTIFICATE', example('CERTIFICATE')),
			);
			const imported = await importPkcs8Pem(relabelled);
			expect(imported.ok).toBe(false);
			if (!imported.ok) {
				expect(imported.code).toBe('malformed');
				expect(imported.message).toBe('Malformed PKCS#8 private key');
			}
		});

		it('reads unencrypted private-key information under the "PRIVATE KEY" label only', () => {
			// "Unencrypted PKCS #8 Private Key Information Syntax structures
			// (PrivateKeyInfo) [...] are encoded using the "PRIVATE KEY" label."
			expect(categorizePemBlocksOrThrow(figure12).privateKeys.map((block) => block.label)).toEqual([
				'PRIVATE KEY',
			]);
			expect(pemDecode('PRIVATE KEY', figure12).ok).toBe(true);
			for (const other of ['ENCRYPTED PRIVATE KEY', 'PUBLIC KEY', 'CERTIFICATE']) {
				expect(pemDecode('PRIVATE KEY', example(other)).ok).toBe(false);
				expect(pemDecode(other, figure12).ok).toBe(false);
			}
		});

		it('generates the PRIVATE KEY label over a PrivateKeyInfo', async () => {
			const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
			const pem = await keyPair.exportPkcs8Pem();
			expect(splitPemBlocksOrThrow(pem).map((b) => b.label)).toEqual(['PRIVATE KEY']);
			// The label carries what the section says it carries: one whole
			// definite-length PrivateKeyInfo declaring v1.
			const der = pemDecodeOrThrow('PRIVATE KEY', pem);
			const fields = readDerSequenceOrThrow(der);
			expect(fields.map((field) => field.tag)).toEqual([0x02, 0x30, 0x04]);
			expect(decodeDerIntegerOrThrow(nthField(fields, 0))).toBe(0);
			expect(readDerRootOrThrow(der).end).toBe(der.length);
		});
	});

	describe('11. Textual Encoding of PKCS #8 Encrypted Private Key Info', () => {
		const INTEGER = 0x02;
		const OCTET_STRING = 0x04;
		const OBJECT_IDENTIFIER = 0x06;
		const SEQUENCE = 0x30;

		const PBES2 = '1.2.840.113549.1.5.13';
		const PBKDF2 = '1.2.840.113549.1.5.12';
		const DES_EDE3_CBC = '1.2.840.113549.3.7';
		const AES_128_CBC = '2.16.840.1.101.3.4.1.2';
		const AES_256_CBC = '2.16.840.1.101.3.4.1.42';
		const PBE_WITH_MD5_AND_DES_CBC = '1.2.840.113549.1.5.3';

		const figure13 = example('ENCRYPTED PRIVATE KEY');
		const figure13Der = pemDecodeOrThrow('ENCRYPTED PRIVATE KEY', figure13);

		function nthField(fields: readonly DerElement[], index: number): DerElement {
			const field = fields[index];
			if (field === undefined) throw new Error(`no DER field at index ${index}`);
			return field;
		}

		/** The direct children of the element reached by following `path` from the root SEQUENCE. */
		function fieldsAt(der: Uint8Array, path: readonly number[]): readonly DerElement[] {
			let fields = readDerSequenceOrThrow(der);
			for (const index of path) fields = derChildrenOrThrow(der, nthField(fields, index));
			return fields;
		}

		function fieldAt(der: Uint8Array, path: readonly number[], index: number): DerElement {
			return nthField(fieldsAt(der, path), index);
		}

		/** A copy of an element's contents, detached from the buffer it was read out of. */
		function contentsOf(element: DerElement): Uint8Array {
			return new Uint8Array(element.value);
		}

		/** A copy of an element's whole encoding, tag and length included. */
		function encodingOf(der: Uint8Array, element: DerElement): Uint8Array {
			return der.slice(element.start - element.headerLength, element.end);
		}

		// Figure 13's own PBKDF2 salt and iteration count, over which only the
		// content-encryption scheme and the parameters under test are varied.
		const figure13Salt = contentsOf(fieldAt(figure13Der, [0, 1, 0, 1], 0));
		const figure13Iv = contentsOf(fieldAt(figure13Der, [0, 1, 1], 1));
		const figure13EncryptedData = contentsOf(fieldAt(figure13Der, [], 1));

		/** An EncryptedPrivateKeyInfo carrying Figure 13's ciphertext under chosen PBES2 parameters. */
		function pbes2Envelope(
			schemeOid: string,
			iv: Uint8Array,
			iterations: number,
			encryptedData: Uint8Array = figure13EncryptedData,
		): Uint8Array {
			return derSequence([
				derSequence([
					derOid(PBES2),
					derSequence([
						derSequence([
							derOid(PBKDF2),
							derSequence([derOctetString(figure13Salt), derIntegerFromNumber(iterations)]),
						]),
						derSequence([derOid(schemeOid), derOctetString(iv)]),
					]),
				]),
				derOctetString(encryptedData),
			]);
		}

		const password = 'rfc7468 figure 13';
		const salt = Uint8Array.from({ length: 16 }, (_, index) => index + 1);
		const iv = Uint8Array.from({ length: 16 }, (_, index) => 0xf0 - index);
		const iterations = 2048;

		/** A PBES2 envelope this library wrote, with every KDF and cipher input pinned. */
		async function generatedEnvelope(): Promise<{
			readonly pem: string;
			readonly der: Uint8Array;
			readonly pkcs8: Uint8Array;
		}> {
			const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
			const pem = await exportEncryptedPkcs8Pem(keyPair.privateKey, {
				password,
				salt,
				iv,
				iterations,
				cipher: 'AES-256-CBC',
				prf: 'HMAC-SHA-256',
			});
			return {
				pem,
				der: pemDecodeOrThrow('ENCRYPTED PRIVATE KEY', pem),
				pkcs8: await exportPkcs8Der(keyPair.privateKey),
			};
		}

		/** A 256-bit AES-CBC key derived by WebCrypto directly, so no claim here rests on this library. */
		async function pbkdf2AesKey(
			pbkdf2Salt: Uint8Array,
			hash: 'SHA-1' | 'SHA-256',
			usage: 'encrypt' | 'decrypt',
		): Promise<CryptoKey> {
			const material = await crypto.subtle.importKey(
				'raw',
				new TextEncoder().encode(password),
				'PBKDF2',
				false,
				['deriveKey'],
			);
			return crypto.subtle.deriveKey(
				{ name: 'PBKDF2', salt: new Uint8Array(pbkdf2Salt), iterations, hash },
				material,
				{ name: 'AES-CBC', length: 256 },
				false,
				[usage],
			);
		}

		/** PBKDF2 + AES-CBC run against WebCrypto directly, so the plaintext claim is not self-attested. */
		async function decryptWithWebCrypto(encryptedData: Uint8Array): Promise<Uint8Array> {
			const key = await pbkdf2AesKey(salt, 'SHA-256', 'decrypt');
			const ciphertext = new Uint8Array(encryptedData);
			return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, ciphertext));
		}

		/** A PKCS #8 private key encrypted outside this library, over Figure 13's own salt. */
		async function encryptWithWebCrypto(
			plaintext: Uint8Array,
			hash: 'SHA-1' | 'SHA-256',
		): Promise<Uint8Array> {
			const key = await pbkdf2AesKey(figure13Salt, hash, 'encrypt');
			return new Uint8Array(
				await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, new Uint8Array(plaintext)),
			);
		}

		it('reads Figure 13 as the EncryptedPrivateKeyInfo structure RFC 5958 describes', () => {
			// "The encoded data MUST be a BER (DER preferred; see Appendix B) encoded
			// ASN.1 EncryptedPrivateKeyInfo structure as described in PKCS #8 [RFC5208]
			// and [RFC5958]." RFC 5958 §3: EncryptedPrivateKeyInfo ::= SEQUENCE {
			// encryptionAlgorithm EncryptionAlgorithmIdentifier, encryptedData
			// EncryptedData }, with EncryptedData ::= OCTET STRING.
			expect(fieldsAt(figure13Der, []).map((field) => field.tag)).toEqual([SEQUENCE, OCTET_STRING]);
			expect(fieldsAt(figure13Der, [0]).map((field) => field.tag)).toEqual([
				OBJECT_IDENTIFIER,
				SEQUENCE,
			]);
			expect(decodeDerOidOrThrow(fieldAt(figure13Der, [0], 0))).toBe(PBES2);
			// RFC 8018 §A.4 PBES2-params: SEQUENCE { keyDerivationFunc
			// AlgorithmIdentifier, encryptionScheme AlgorithmIdentifier }, over the
			// PBKDF2 parameters of §A.2 and, here, the DES-EDE3-CBC scheme of §B.2.2.
			expect(decodeDerOidOrThrow(fieldAt(figure13Der, [0, 1, 0], 0))).toBe(PBKDF2);
			expect(fieldsAt(figure13Der, [0, 1, 0, 1]).map((field) => field.tag)).toEqual([
				OCTET_STRING,
				INTEGER,
			]);
			expect(figure13Salt).toHaveLength(8);
			expect(decodeDerIntegerOrThrow(fieldAt(figure13Der, [0, 1, 0, 1], 1))).toBe(2048);
			expect(decodeDerOidOrThrow(fieldAt(figure13Der, [0, 1, 1], 0))).toBe(DES_EDE3_CBC);
			expect(figure13Iv).toHaveLength(8);
			// DES-EDE3-CBC has an 8-octet block, and CBC ciphertext is a whole number
			// of blocks.
			expect(figure13EncryptedData.length % 8).toBe(0);
			expect(figure13EncryptedData.length).toBeGreaterThan(0);
		});

		it('reads the envelope of Figure 13 before refusing its content encryption', async () => {
			// The RFC prints no password for Figure 13, and its encryptionAlgorithm
			// names DES-EDE3-CBC, which WebCrypto does not implement, so the example
			// cannot be decrypted here at any password. Naming the content encryption
			// rather than the envelope means the EncryptedPrivateKeyInfo, the PBES2
			// AlgorithmIdentifier, and the PBKDF2 parameters were all decoded first.
			for (const attempt of ['', 'password']) {
				const imported = await importEncryptedPkcs8Pem(figure13, attempt);
				expect(imported.ok).toBe(false);
				if (!imported.ok) {
					expect(imported.code).toBe('malformed');
					expect(imported.message).toBe('Unsupported content encryption scheme');
				}
			}
		});

		it('reports unusable PBES2 parameters as a typed failure rather than throwing', async () => {
			// "Data in this format often originates from untrusted sources, thus parsers
			// must be prepared to handle unexpected data without causing security
			// vulnerabilities" (Section 14). Figure 13's parameters carry an 8-octet IV
			// and would carry any iteration count an encoder wrote; under a scheme this
			// library does implement, both reach the AES-CBC parameter checks, and an
			// exception out of a Result-returning import is a crash, not a verdict.
			for (const [title, envelope] of [
				['an IV shorter than the AES-CBC block', pbes2Envelope(AES_256_CBC, figure13Iv, 2048)],
				['an iteration count below one', pbes2Envelope(AES_256_CBC, new Uint8Array(16), 0)],
			] as const satisfies readonly (readonly [string, Uint8Array])[]) {
				const imported = await importEncryptedPkcs8Der(envelope, password);
				expect({ title, ok: imported.ok }).toEqual({ title, ok: false });
				if (!imported.ok) {
					expect(imported.code).toBe('malformed');
				}
			}
		});

		it('refuses data under the ENCRYPTED PRIVATE KEY label that is not an EncryptedPrivateKeyInfo', async () => {
			// The same MUST: the label alone does not make the octets an
			// EncryptedPrivateKeyInfo, so every other figure carried under it has to
			// come back as a typed failure rather than an import.
			for (const label of examples.keys()) {
				if (label === 'ENCRYPTED PRIVATE KEY') continue;
				const payload = pemDecodeOrThrow(label, example(label));
				const relabelled = pemEncode('ENCRYPTED PRIVATE KEY', payload);
				expect(Array.from(pemDecodeOrThrow('ENCRYPTED PRIVATE KEY', relabelled))).toEqual(
					Array.from(payload),
				);
				const imported = await importEncryptedPkcs8Pem(relabelled, password);
				expect({ label, ok: imported.ok }).toEqual({ label, ok: false });
				if (!imported.ok) {
					expect(imported.code).toBe('malformed');
				}
			}
		});

		it('encrypts the PrivateKeyInfo itself under the ENCRYPTED PRIVATE KEY label', async () => {
			// "Encrypted PKCS #8 Private Key Information Syntax structures
			// (EncryptedPrivateKeyInfo) [...] are encoded using the "ENCRYPTED PRIVATE
			// KEY" label", over the structure RFC 5958 §3 defines: "encryptedData is
			// the result of encrypting the private-key information (i.e., the
			// PrivateKeyInfo)", whose encoding step says "Generators SHOULD use DER".
			const { pem, der, pkcs8 } = await generatedEnvelope();
			expect(splitPemBlocksOrThrow(pem).map((block) => block.label)).toEqual([
				'ENCRYPTED PRIVATE KEY',
			]);
			expect(fieldsAt(der, []).map((field) => field.tag)).toEqual([SEQUENCE, OCTET_STRING]);
			expect(decodeDerOidOrThrow(fieldAt(der, [0], 0))).toBe(PBES2);
			expect(decodeDerOidOrThrow(fieldAt(der, [0, 1, 0], 0))).toBe(PBKDF2);
			expect(decodeDerOidOrThrow(fieldAt(der, [0, 1, 1], 0))).toBe(AES_256_CBC);
			// Decrypted against WebCrypto directly, the encryptedData is the very
			// PrivateKeyInfo the unencrypted export writes.
			const plaintext = await decryptWithWebCrypto(contentsOf(fieldAt(der, [], 1)));
			expect(Array.from(plaintext)).toEqual(Array.from(pkcs8));
			expect(readDerSequenceOrThrow(plaintext).map((field) => field.tag)).toEqual([
				INTEGER,
				SEQUENCE,
				OCTET_STRING,
			]);
			const imported = await importEncryptedPkcs8Pem(pem, password);
			expect(imported.ok).toBe(true);
			if (imported.ok) expect(imported.value.type).toBe('private');
		});

		it('reads the EncryptedPrivateKeyInfo and nothing beyond it', async () => {
			// The encoded data is the EncryptedPrivateKeyInfo structure, so octets
			// outside it are not part of the encoding.
			const { der } = await generatedEnvelope();
			expect((await importEncryptedPkcs8Der(der, password)).ok).toBe(true);
			expect((await importEncryptedPkcs8Der(Uint8Array.of(...der, 0x00), password)).ok).toBe(false);
			expect((await importEncryptedPkcs8Der(der.slice(0, der.length - 1), password)).ok).toBe(
				false,
			);
		});

		it('reads only the definite-length form of the EncryptedPrivateKeyInfo', async () => {
			// "DER preferred; see Appendix B", whose Figure 20 gives ENCRYPTED PRIVATE
			// KEY reason 3: "the content is small. DER always encodes data values in
			// definite-length form [...]; thus, a parser can anticipate memory or
			// resource usage up front."
			const { der } = await generatedEnvelope();
			const root = readDerRootOrThrow(der);
			const indefinite = Uint8Array.of(SEQUENCE, 0x80, ...der.slice(root.start, root.end), 0, 0);
			expect((await importEncryptedPkcs8Der(der, password)).ok).toBe(true);
			expect((await importEncryptedPkcs8Der(indefinite, password)).ok).toBe(false);
		});

		it('carries the EncryptedPrivateKeyInfo under the "ENCRYPTED PRIVATE KEY" label only', async () => {
			// "Encrypted PKCS #8 Private Key Information Syntax structures
			// (EncryptedPrivateKeyInfo), called the same in [RFC5958], are encoded
			// using the "ENCRYPTED PRIVATE KEY" label."
			const { pem, der } = await generatedEnvelope();
			expect((await importEncryptedPkcs8Pem(pem, password)).ok).toBe(true);
			for (const label of ['PRIVATE KEY', 'RSA PRIVATE KEY', 'Encrypted Private Key', 'PKCS7']) {
				const relabelled = pemEncode(label, der);
				expect({ label, ok: pemDecode('ENCRYPTED PRIVATE KEY', relabelled).ok }).toEqual({
					label,
					ok: false,
				});
				const imported = await importEncryptedPkcs8Pem(relabelled, password);
				expect({ label, ok: imported.ok }).toEqual({ label, ok: false });
				if (!imported.ok) {
					expect(imported.code).toBe('malformed');
				}
			}
			// The pairing runs the other way too: what this label carries is an
			// EncryptedPrivateKeyInfo, so Section 10's reader has to refuse it rather
			// than take ciphertext for a privateKey OCTET STRING.
			const asPlain = await importPkcs8Der(der);
			expect(asPlain.ok).toBe(false);
			if (!asPlain.ok) {
				expect(asPlain.code).toBe('malformed');
				expect(asPlain.message).toBe('Malformed PKCS#8 private key');
			}
			expect((await importPkcs8Pem(figure13)).ok).toBe(false);
		});

		it('reports a wrong password over a readable envelope as its own typed failure', async () => {
			// RFC 5958 §3: "encryptedData is the result of encrypting the private-key
			// information (i.e., the PrivateKeyInfo)", and Section 14: "parsers must be
			// prepared to handle unexpected data without causing security
			// vulnerabilities". Every password but the one that wrote the envelope has
			// to come back as a verdict, and the wrong-password verdict is its own.
			const { der, pkcs8 } = await generatedEnvelope();
			const imported = await importEncryptedPkcs8Der(der, password);
			expect(imported.ok).toBe(true);
			if (imported.ok) {
				expect(Array.from(await exportPkcs8Der(imported.value))).toEqual(Array.from(pkcs8));
			}
			for (const attempt of ['', 'Rfc7468 figure 13', `${password} `]) {
				const refused = await importEncryptedPkcs8Der(der, attempt);
				expect({ attempt, ok: refused.ok }).toEqual({ attempt, ok: false });
				if (!refused.ok) {
					expect(refused.code).toBe('invalid_password');
				}
			}
			// Corrupting the first ciphertext block leaves the last block, and with it
			// the padding, intact: AES-CBC decryption succeeds and only the decrypted
			// structure gives the tampering away, so the encryptedData has to be
			// checked for being private-key information rather than merely unpadding.
			const ciphertext = contentsOf(fieldAt(der, [], 1));
			const tampered = new Uint8Array(ciphertext);
			tampered[0] = (tampered[0] ?? 0) ^ 0xff;
			const rebuilt = (data: Uint8Array): Uint8Array =>
				derSequence([encodingOf(der, fieldAt(der, [], 0)), derOctetString(data)]);
			expect((await importEncryptedPkcs8Der(rebuilt(ciphertext), password)).ok).toBe(true);
			const corrupted = await importEncryptedPkcs8Der(rebuilt(tampered), password);
			expect(corrupted.ok).toBe(false);
			if (!corrupted.ok) {
				expect(corrupted.code).toBe('invalid_password');
			}
		});

		it('derives under the PBKDF2 PRF default that Figure 13 relies on', async () => {
			// Figure 13's PBKDF2-params carry a salt and an iterationCount and nothing
			// else, and RFC 8018 §A.2 ends PBKDF2-params with "prf AlgorithmIdentifier
			// {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1". A reader that took its own
			// preferred PRF for the absent field would derive a different key from the
			// same password, so the omission is only readable one way.
			expect(fieldsAt(figure13Der, [0, 1, 0, 1]).map((field) => field.tag)).toEqual([
				OCTET_STRING,
				INTEGER,
			]);
			const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
			const pkcs8 = await exportPkcs8Der(keyPair.privateKey);
			const withSha1 = pbes2Envelope(
				AES_256_CBC,
				iv,
				iterations,
				await encryptWithWebCrypto(pkcs8, 'SHA-1'),
			);
			const imported = await importEncryptedPkcs8Der(withSha1, password);
			expect(imported.ok).toBe(true);
			if (imported.ok) {
				expect(Array.from(await exportPkcs8Der(imported.value))).toEqual(Array.from(pkcs8));
			}
			const withSha256 = pbes2Envelope(
				AES_256_CBC,
				iv,
				iterations,
				await encryptWithWebCrypto(pkcs8, 'SHA-256'),
			);
			const refused = await importEncryptedPkcs8Der(withSha256, password);
			expect(refused.ok).toBe(false);
			if (!refused.ok) {
				expect(refused.code).toBe('invalid_password');
			}
		});

		it('decrypts under the encryptionAlgorithm the envelope names, or refuses it', async () => {
			// RFC 5958 §3: "encryptionAlgorithm identifies the algorithm under which
			// the private-key information is encrypted". RFC 5208 §6 names PKCS #5's
			// pbeWithMD5AndDES-CBC as one such algorithm; RFC 8018 §A.3 assigns it
			// {pkcs-5 3} over "PBEParameter ::= SEQUENCE { salt OCTET STRING (SIZE(8)),
			// iterationCount INTEGER }". This library implements none of PBES1, and an
			// algorithm it cannot run is a refusal rather than a guess at PBES2.
			const { der } = await generatedEnvelope();
			const legacy = derSequence([
				derSequence([
					derOid(PBE_WITH_MD5_AND_DES_CBC),
					derSequence([derOctetString(figure13Salt), derIntegerFromNumber(iterations)]),
				]),
				derOctetString(contentsOf(fieldAt(der, [], 1))),
			]);
			const refused = await importEncryptedPkcs8Der(legacy, password);
			expect(refused.ok).toBe(false);
			if (!refused.ok) {
				expect(refused.code).toBe('malformed');
				expect(refused.message).toBe('Unsupported encryption algorithm');
			}
			// The encryptionAlgorithm identifies the content encryption too: the same
			// PBKDF2 inputs under a different AES-CBC scheme derive a different key, so
			// a restamped scheme OID cannot open what the named one wrote.
			const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
			const pkcs8 = await exportPkcs8Der(keyPair.privateKey);
			const ciphertext = await encryptWithWebCrypto(pkcs8, 'SHA-1');
			expect(
				(
					await importEncryptedPkcs8Der(
						pbes2Envelope(AES_256_CBC, iv, iterations, ciphertext),
						password,
					)
				).ok,
			).toBe(true);
			const restamped = await importEncryptedPkcs8Der(
				pbes2Envelope(AES_128_CBC, iv, iterations, ciphertext),
				password,
			);
			expect(restamped.ok).toBe(false);
			if (!restamped.ok) {
				expect(restamped.code).toBe('invalid_password');
			}
		});
	});

	describe('12. Textual Encoding of Attribute Certificates', () => {
		// "Attribute certificates are encoded using the "ATTRIBUTE CERTIFICATE"
		// label. The encoded data MUST be a BER (DER strongly preferred; see
		// Appendix B) encoded ASN.1 AttributeCertificate structure as described in
		// [RFC5755]."
		const INTEGER = 0x02;
		const BIT_STRING = 0x03;
		const OBJECT_IDENTIFIER = 0x06;
		const NULL = 0x05;
		const GENERALIZED_TIME = 0x18;
		const SEQUENCE = 0x30;
		const SET = 0x31;
		const DNS_NAME = 0x82;
		const UNIFORM_RESOURCE_IDENTIFIER = 0x86;
		const IP_ADDRESS = 0x87;
		const REGISTERED_ID = 0x88;
		const CONTEXT_0 = 0xa0;
		const V2_ATTR_CERT = 0xa2;
		const X400_ADDRESS = 0xa3;
		const DIRECTORY_NAME = 0xa4;
		const EDI_PARTY_NAME = 0xa5;
		const label = 'ATTRIBUTE CERTIFICATE';
		const pem = example(label);
		const der = pemDecodeOrThrow(label, pem);

		function fieldAt(elements: readonly DerElement[], index: number): DerElement {
			const element = elements.at(index);
			if (element === undefined) throw new Error(`AttributeCertificate has no field ${index}`);
			return element;
		}

		function fieldsOf(parent: DerElement): readonly DerElement[] {
			return derChildrenOrThrow(der, parent);
		}

		function tagsOf(elements: readonly DerElement[]): readonly number[] {
			return elements.map((element) => element.tag);
		}

		/** The bytes of `element` including its own tag and length octets. */
		function encodingOf(element: DerElement): Uint8Array {
			return der.slice(element.start - element.headerLength, element.end);
		}

		const attributeCertificate = readDerSequenceOrThrow(der);
		const acinfo = fieldsOf(fieldAt(attributeCertificate, 0));
		const holder = fieldAt(acinfo, 1);
		const issuer = fieldAt(acinfo, 2);
		const signature = fieldAt(acinfo, 3);
		const serialNumber = fieldAt(acinfo, 4);
		const validityPeriod = fieldAt(acinfo, 5);
		const attributes = fieldAt(acinfo, 6);

		it('reads the Figure 14 example under the ATTRIBUTE CERTIFICATE label alone', () => {
			expect(pemEncode(label, der)).toBe(`${pem}\n`);
			for (const other of ['CERTIFICATE', 'X509 CRL', 'PKCS7', 'attribute certificate']) {
				expect(pemDecode(other, pem).ok).toBe(false);
			}
			expect(pemDecode(label, example('CERTIFICATE')).ok).toBe(false);
		});

		it('reads the Figure 14 data as the RFC 5755 AttributeCertificate structure', () => {
			// RFC 5755 §4.1: AttributeCertificate ::= SEQUENCE { acinfo
			// AttributeCertificateInfo, signatureAlgorithm AlgorithmIdentifier,
			// signatureValue BIT STRING }, and AttributeCertificateInfo ::= SEQUENCE {
			// version AttCertVersion, holder Holder, issuer AttCertIssuer, signature
			// AlgorithmIdentifier, serialNumber CertificateSerialNumber,
			// attrCertValidityPeriod AttCertValidityPeriod, attributes SEQUENCE OF
			// Attribute, issuerUniqueID UniqueIdentifier OPTIONAL, extensions
			// Extensions OPTIONAL }. Figure 14 stops at attributes: §4.2.8 says
			// issuerUniqueID "MUST NOT be used unless it is also used in the AC issuer's
			// PKC", and §4.2.9 that "An AC that has no extensions conforms to the
			// profile".
			expect(tagsOf(attributeCertificate)).toEqual([SEQUENCE, SEQUENCE, BIT_STRING]);
			expect(tagsOf(acinfo)).toEqual([
				INTEGER,
				SEQUENCE,
				CONTEXT_0,
				SEQUENCE,
				INTEGER,
				SEQUENCE,
				SEQUENCE,
			]);
			// §4.2.1: "The version field MUST have the value of v2", and AttCertVersion
			// ::= INTEGER { v2(1) }.
			expect(decodeDerIntegerOrThrow(fieldAt(acinfo, 0))).toBe(1);
		});

		it('reads the holder as one baseCertificateID over a non-empty issuer name', () => {
			// §4.1: Holder ::= SEQUENCE { baseCertificateID [0] IssuerSerial OPTIONAL,
			// entityName [1] GeneralNames OPTIONAL, objectDigestInfo [2]
			// ObjectDigestInfo OPTIONAL }, and IssuerSerial ::= SEQUENCE { issuer
			// GeneralNames, serial CertificateSerialNumber, issuerUID UniqueIdentifier
			// OPTIONAL }. §4.2.2 "RECOMMENDS that only one of the options be used", and
			// under baseCertificateID "The PKC issuer MUST have a non-empty
			// distinguished name that is to be present as the single value of the
			// holder.baseCertificateID.issuer construct in the directoryName field",
			// where an empty name is one whose "DER encoding [...] has the value
			// '3000'H". The issuerUID "MUST only be used if the holder's PKC contains
			// an issuerUniqueID field".
			expect(tagsOf(fieldsOf(holder))).toEqual([CONTEXT_0]);
			const baseCertificateId = fieldsOf(fieldAt(fieldsOf(holder), 0));
			expect(tagsOf(baseCertificateId)).toEqual([SEQUENCE, INTEGER]);
			expect(tagsOf(fieldsOf(fieldAt(baseCertificateId, 0)))).toEqual([DIRECTORY_NAME]);
			const holderIssuer = parseGeneralNames(der, fieldAt(baseCertificateId, 0));
			const holderName = holderIssuer.at(0);
			if (holderIssuer.length !== 1 || holderName?.type !== 'directoryName') {
				throw new Error('Holder issuer is not a single directoryName');
			}
			expect(holderName.derHex).not.toBe('3000');
			expect(
				distinguishedNameToString(parseDistinguishedNameDer(hexToBytes(holderName.derHex))),
			).toBe(
				'CN=Scott Staller/emailAddress=sstaller@ic.sunysb.edu,O=CSE592,L=Stony Brook,ST=New York,C=US',
			);
			expect(decodeDerIntegerOrThrow(fieldAt(baseCertificateId, 1))).toBe(1192583316754);
		});

		it('reads the v2Form issuer as one non-empty directoryName', () => {
			// §4.2.3: "ACs conforming to this profile MUST use the v2Form choice, which
			// MUST contain one and only one GeneralName in the issuerName, which MUST
			// contain a non-empty distinguished name in the directoryName field [...]
			// ACs conforming to this profile MUST omit the baseCertificateID and
			// objectDigestInfo fields."
			expect(issuer.tag).toBe(CONTEXT_0);
			const v2Form = fieldsOf(issuer);
			expect(tagsOf(v2Form)).toEqual([SEQUENCE]);
			const issuerName = fieldAt(v2Form, 0);
			expect(tagsOf(fieldsOf(issuerName))).toEqual([DIRECTORY_NAME]);
			const issuerNames = parseGeneralNames(der, issuerName);
			const directoryName = issuerNames.at(0);
			if (issuerNames.length !== 1 || directoryName?.type !== 'directoryName') {
				throw new Error('AC issuer is not a single directoryName');
			}
			const rdnSequence = parseDistinguishedNameDer(hexToBytes(directoryName.derHex));
			expect(rdnSequence.rdns.length).toBeGreaterThan(0);
			expect(
				rdnSequence.rdns.flatMap((rdn) => rdn.attributes.map((attribute) => attribute.value)),
			).toEqual([
				'US',
				'New York',
				'Stony Brook',
				'CSE592',
				'Scott Staller/emailAddress=sstaller@ic.sunysb.edu',
			]);
		});

		it('decodes every GeneralName alternative an AC has to support', () => {
			// §4.2: "Conforming implementations MUST be able to support the dNSName,
			// directoryName, uniformResourceIdentifier, and iPAddress options [...]
			// Conforming implementations MUST NOT use the x400Address, ediPartyName, or
			// registeredID options."
			const text = (value: string): Uint8Array => new TextEncoder().encode(value);
			const name = derSequence([
				derSet([derSequence([derOid('2.5.4.3'), derUtf8String('ac.example')])]),
			]);
			const supported = derSequence([
				derTlv(DNS_NAME, text('ac.example')),
				derImplicitConstructedContext(4, name),
				derTlv(UNIFORM_RESOURCE_IDENTIFIER, text('http://ac.example/index.html')),
				derTlv(IP_ADDRESS, Uint8Array.of(192, 0, 2, 1)),
			]);
			expect(parseGeneralNames(supported, readDerRootOrThrow(supported))).toEqual([
				{ type: 'dns', value: 'ac.example' },
				{ type: 'directoryName', derHex: toHex(name) },
				{ type: 'uri', value: 'http://ac.example/index.html' },
				{ type: 'ip', value: '192.0.2.1' },
			]);
			const unused = derSequence([
				derTlv(X400_ADDRESS, new Uint8Array()),
				derTlv(EDI_PARTY_NAME, new Uint8Array()),
				derTlv(REGISTERED_ID, readDerRootOrThrow(derOid('2.5.4.3')).value),
			]);
			expect(
				parseGeneralNames(unused, readDerRootOrThrow(unused)).map((alternative) =>
					alternative.type === 'unknown' ? alternative.tag : alternative.type,
				),
			).toEqual([X400_ADDRESS, EDI_PARTY_NAME, REGISTERED_ID]);
		});

		it('reads one PKIXALGS signing algorithm from both AlgorithmIdentifier fields', () => {
			// §4.2.4: the signature field "Contains the algorithm identifier used to
			// validate the AC signature. This MUST be one of the signing algorithms
			// defined in [PKIXALGS]", which §10.1 resolves to RFC 3279, RFC 4055, RFC
			// 5480, and RFC 5756. RFC 3279 §2.2.1 assigns sha-1WithRSAEncryption
			// 1.2.840.113549.1.1.5, and "the parameters component of that type SHALL
			// be the ASN.1 type NULL".
			const signatureAlgorithm = fieldAt(attributeCertificate, 1);
			expect(decodeDerOidOrThrow(fieldAt(fieldsOf(signature), 0))).toBe('1.2.840.113549.1.1.5');
			expect(encodingOf(signature)).toEqual(encodingOf(signatureAlgorithm));
			expect(tagsOf(fieldsOf(signatureAlgorithm))).toEqual([OBJECT_IDENTIFIER, NULL]);
			expect(decodeDerBitStringOrThrow(fieldAt(attributeCertificate, 2)).unusedBits).toBe(0);
		});

		it('reads a serial number of more than four and no more than twenty octets', () => {
			// §4.2.5: "AC issuers MUST force the serialNumber to be a positive integer,
			// that is, the sign bit in the DER encoding of the INTEGER value MUST be
			// zero [...] AC users MUST be able to handle serialNumber values longer
			// than 4 octets. Conformant ACs MUST NOT contain serialNumber values longer
			// than 20 octets."
			expect(serialNumber.length).toBeGreaterThan(4);
			expect(serialNumber.length).toBeLessThanOrEqual(20);
			expect((serialNumber.value.at(0) ?? 0xff) & 0x80).toBe(0);
			expect(decodeDerIntegerOrThrow(serialNumber)).toBe(1192583316810);
			// Twenty octets exceed Number.MAX_SAFE_INTEGER, so the octets carry such a
			// serial and the number decoder fails rather than rounding it.
			const longest = readDerRootOrThrow(derInteger(Uint8Array.of(0x7f, ...new Uint8Array(19))));
			expect(longest.value.length).toBe(20);
			expect(toHex(longest.value)).toBe(`7f${'00'.repeat(19)}`);
			const rounded = decodeDerInteger(longest);
			expect(rounded.ok ? 'ok' : rounded.code).toBe('malformed');
		});

		it('reads the validity period as UTC GeneralizedTime carrying whole seconds', () => {
			// §4.2.6: AttCertValidityPeriod ::= SEQUENCE { notBeforeTime
			// GeneralizedTime, notAfterTime GeneralizedTime }, whose values "MUST be
			// expressed in Coordinated universal time (UTC) [...] and MUST include
			// seconds (i.e., times are YYYYMMDDHHMMSSZ), even when the number of
			// seconds is zero. GeneralizedTime values MUST NOT include fractional
			// seconds." Figure 14 starts in 3907, and "AC users MUST be able to handle
			// an AC which, at the time of processing, has parts of its validity period
			// or all its validity period in the past or in the future".
			const period = fieldsOf(validityPeriod);
			expect(tagsOf(period)).toEqual([GENERALIZED_TIME, GENERALIZED_TIME]);
			expect(period.map((time) => decodeDerTimeOrThrow(time).toISOString())).toEqual([
				'3907-02-01T05:00:00.000Z',
				'3911-01-31T05:00:00.000Z',
			]);
			const generalizedTime = (text: string): DerElement => {
				const value = new TextEncoder().encode(text);
				return readDerRootOrThrow(Uint8Array.of(GENERALIZED_TIME, value.length, ...value));
			};
			expect(decodeDerTime(generalizedTime('39070201050000Z')).ok).toBe(true);
			for (const rejected of ['390702010500Z', '39070201050000.5Z', '39070201050000-0500']) {
				expect(decodeDerTime(generalizedTime(rejected)).ok).toBe(false);
			}
		});

		it('reads every attribute as a uniquely typed, non-empty SET of values', () => {
			// §4.1: Attribute ::= SEQUENCE { type AttributeType, values SET OF
			// AttributeValue -- at least one value is required }, AttributeType ::=
			// OBJECT IDENTIFIER. §4.2.7: "each AttributeType OBJECT IDENTIFIER in the
			// sequence MUST be unique [...] An AC MUST contain at least one attribute.
			// That is, the SEQUENCE OF Attributes MUST NOT be of zero length."
			const parsed = fieldsOf(attributes).map((attribute) => {
				const parts = fieldsOf(attribute);
				expect(tagsOf(parts)).toEqual([OBJECT_IDENTIFIER, SET]);
				return {
					type: decodeDerOidOrThrow(fieldAt(parts, 0)),
					values: fieldsOf(fieldAt(parts, 1)),
				};
			});
			expect(parsed.length).toBeGreaterThan(0);
			expect(new Set(parsed.map(({ type }) => type)).size).toBe(parsed.length);
			for (const { values } of parsed) {
				expect(values.length).toBeGreaterThan(0);
			}
			expect(parsed.map(({ type }) => type)).toEqual(['2.5.24.72']);
			// The single value holds one RFC 5280 §4.2.1.6 GeneralName, whose
			// uniformResourceIdentifier alternative is [6] IMPLICIT IA5String.
			const onlyAttribute = parsed.at(0);
			if (onlyAttribute === undefined) throw new Error('unreachable');
			const value = fieldAt(onlyAttribute.values, 0);
			expect(tagsOf(fieldsOf(value))).toEqual([UNIFORM_RESOURCE_IDENTIFIER]);
			expect(parseGeneralNames(der, value)).toEqual([
				{ type: 'uri', value: 'http://iderashn.org/index.html' },
			]);
		});

		it('orders the values of a multi-valued attribute by their encodings', () => {
			// §4.2.7: "AC users MUST be able to handle multiple values for all attribute
			// types." §4.1: "the DER encoding [...] of the SET OF values requires
			// ordering of the encodings of the values [...] it is much more significant
			// in this context, since the inclusion of multiple values is much more
			// common in ACs."
			const generalNames = (uri: string): Uint8Array =>
				derSequence([derTlv(UNIFORM_RESOURCE_IDENTIFIER, new TextEncoder().encode(uri))]);
			const shorter = 'http://iderashn.org/a.html';
			const longer = 'http://iderashn.org/index.html';
			const attribute = derSequence([
				derOid('2.5.24.72'),
				derSet([generalNames(longer), generalNames(shorter)]),
			]);
			const parts = derChildrenOrThrow(attribute, readDerRootOrThrow(attribute));
			expect(tagsOf(parts)).toEqual([OBJECT_IDENTIFIER, SET]);
			const values = derChildrenOrThrow(attribute, fieldAt(parts, 1));
			expect(values.map((value) => parseGeneralNames(attribute, value))).toEqual([
				[{ type: 'uri', value: shorter }],
				[{ type: 'uri', value: longer }],
			]);
		});

		it('reads the AttributeCertificate and nothing beyond it', () => {
			expect(readDerRoot(der).ok).toBe(true);
			expect(readDerRoot(Uint8Array.of(...der, 0x00)).ok).toBe(false);
			expect(readDerRoot(der.slice(0, der.length - 1)).ok).toBe(false);
		});

		it('reads only the definite-length form of the AttributeCertificate', () => {
			// "DER strongly preferred; see Appendix B", whose Figure 20 gives ATTRIBUTE
			// CERTIFICATE reasons 1 and ~3: a signature "is (supposed to be) computed
			// over the DER encoding", and "DER always encodes data values in
			// definite-length form".
			const root = readDerRootOrThrow(der);
			const indefinite = Uint8Array.of(SEQUENCE, 0x80, ...der.slice(root.start, root.end), 0, 0);
			expect(readDerRoot(indefinite).ok).toBe(false);
		});

		it('does not read an attribute certificate as a structure another label carries', async () => {
			// Every other label in Figure 4 names a different ASN.1 type, so an
			// AttributeCertificate is not one of them; each reader reports a typed
			// failure rather than a partial reading.
			const readings = [
				parseCertificateDer(der),
				parseCertificateRevocationListDer(der),
				parseCertificateSigningRequestDer(der),
				parsePkcs7SignedDataDer(der),
				await importSpkiDer(der),
				await importPkcs8Der(der),
			];
			expect(readings.map((reading) => (reading.ok ? 'ok' : reading.code))).toEqual([
				'malformed',
				'malformed',
				'malformed',
				'malformed',
				'malformed',
				'malformed',
			]);
		});

		it('carries the Figure 14 attribute certificate as the CMS v2AttrCert choice', async () => {
			// RFC 5652 §10.2.2: CertificateChoices ::= CHOICE { ... v2AttrCert [2]
			// IMPLICIT AttributeCertificateV2 ... }, and its §12.1 module states
			// AttributeCertificateV2 ::= AttributeCertificate, the RFC 5755 structure
			// this label carries.
			const signer = await createSelfSignedCertificate({ subject: { commonName: 'CMS Signer' } });
			const v2AttrCert = Uint8Array.from(der);
			v2AttrCert[0] = V2_ATTR_CERT;
			const parsedSigner = unwrap(parseCertificatePem(signer.certificate.pem));
			const parsed = parsePkcs7SignedDataDer(
				createSyntheticPkcs7SignedData(parsedSigner, [v2AttrCert]),
			);
			expect(parsed.ok).toBe(true);
			if (!parsed.ok) throw new Error('unreachable');
			expect(parsed.value.certificateChoices.map((choice) => choice.type)).toEqual([
				'certificate',
				'attributeCertificateV2',
			]);
			const carried = parsed.value.certificateChoices.at(1);
			if (carried?.type !== 'attributeCertificateV2') throw new Error('unreachable');
			expect(carried.der.slice(1)).toEqual(der.slice(1));
		});
	});

	describe('13. Textual Encoding of Subject Public Key Info', () => {
		const BIT_STRING = 0x03;
		const OBJECT_IDENTIFIER = 0x06;
		const SEQUENCE = 0x30;

		const ID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
		const SECP384R1 = '1.3.132.0.34';
		const UNCOMPRESSED_EC_POINT = 0x04;
		const P384_COORDINATE_BYTES = 48;

		const figure15 = example('PUBLIC KEY');
		const figure15Der = pemDecodeOrThrow('PUBLIC KEY', figure15);

		function nthField(fields: readonly DerElement[], index: number): DerElement {
			const field = fields[index];
			if (field === undefined) throw new Error(`no DER field at index ${index}`);
			return field;
		}

		it('reads Figure 15 as the SubjectPublicKeyInfo structure RFC 5280 describes', () => {
			// "The encoded data MUST be a BER (DER preferred; see Appendix B) encoded
			// ASN.1 SubjectPublicKeyInfo structure as described in Section 4.1.2.7 of
			// [RFC5280]." RFC 5280 §4.1: SubjectPublicKeyInfo ::= SEQUENCE {
			// algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }, whose
			// §4.1.1.2 AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT
			// IDENTIFIER, parameters ANY DEFINED BY algorithm OPTIONAL } is the
			// structure §4.1.2.7 says identifies the algorithm.
			const root = readDerRootOrThrow(figure15Der);
			expect(root.tag).toBe(SEQUENCE);
			expect(root.end).toBe(figure15Der.length);
			const fields = readDerSequenceOrThrow(figure15Der);
			expect(fields.map((field) => field.tag)).toEqual([SEQUENCE, BIT_STRING]);
			const algorithm = derChildrenOrThrow(figure15Der, nthField(fields, 0));
			expect(algorithm.map((field) => field.tag)).toEqual([OBJECT_IDENTIFIER, OBJECT_IDENTIFIER]);
			expect(decodeDerOidOrThrow(nthField(algorithm, 0))).toBe(ID_EC_PUBLIC_KEY);
			expect(decodeDerOidOrThrow(nthField(algorithm, 1))).toBe(SECP384R1);
			// RFC 5480 §2.2 maps the ECPoint OCTET STRING onto subjectPublicKey and
			// indicates "the uncompressed form [...] by 0x04"; its §2.1.1 assigns
			// 1.3.132.0.34 to secp384r1, which [FIPS186-3] calls P-384.
			const subjectPublicKey = decodeDerBitStringOrThrow(nthField(fields, 1));
			expect(subjectPublicKey.unusedBits).toBe(0);
			expect(subjectPublicKey.bytes.at(0)).toBe(UNCOMPRESSED_EC_POINT);
			expect(subjectPublicKey.bytes).toHaveLength(1 + 2 * P384_COORDINATE_BYTES);
		});

		it('imports Figure 15 on the curve its own AlgorithmIdentifier names', async () => {
			// The AlgorithmIdentifier is what "identif[ies] the algorithm with which
			// the key is used" (RFC 5280 §4.1.2.7), so inferring the import
			// parameters from the encoded data has to land on P-384, and re-exporting
			// has to reproduce Figure 15 octet for octet.
			const inferred = await importSpkiPemOrThrow(figure15);
			expect(inferred.type).toBe('public');
			expect(Array.from(await exportSpkiDer(inferred))).toEqual(Array.from(figure15Der));
			expect(await exportSpkiPem(inferred)).toBe(`${figure15}\n`);

			const requested = await importSpkiPemOrThrow(figure15, { kind: 'ecdsa', curve: 'P-384' });
			expect(Array.from(await exportSpkiDer(requested))).toEqual(Array.from(figure15Der));
		});

		it('refuses to import Figure 15 under a curve it is not on', async () => {
			const rejected = await importSpkiPem(figure15, { kind: 'ecdsa', curve: 'P-256' });
			expect(rejected.ok).toBe(false);
			if (!rejected.ok) {
				expect(rejected.code).toBe('malformed');
				expect(rejected.message).toBe(
					'SubjectPublicKeyInfo algorithm does not match requested import algorithm',
				);
			}
		});

		it('refuses a PUBLIC KEY block that does not hold a SubjectPublicKeyInfo', async () => {
			// The label alone does not license the payload: the encoded data "MUST be
			// [...] ASN.1 SubjectPublicKeyInfo". Figure 6's certificate under the
			// PUBLIC KEY label is a well-formed DER SEQUENCE and still not one.
			const relabelled = pemEncode(
				'PUBLIC KEY',
				pemDecodeOrThrow('CERTIFICATE', example('CERTIFICATE')),
			);
			const imported = await importSpkiPem(relabelled);
			expect(imported.ok).toBe(false);
			if (!imported.ok) {
				expect(imported.code).toBe('malformed');
				expect(imported.message).toBe('Malformed SubjectPublicKeyInfo');
			}
		});

		it('refuses data that is more, or less, than one SubjectPublicKeyInfo', async () => {
			// A SubjectPublicKeyInfo with a stray octet appended is not one, and
			// neither is one whose subjectPublicKey BIT STRING claims unused bits:
			// RFC 5480 §2.2 fills that BIT STRING with whole ECPoint octets.
			const trailing = new Uint8Array(figure15Der.length + 1);
			trailing.set(figure15Der);
			const truncated = figure15Der.slice(0, -1);
			const unusedBitsOffset = nthField(readDerSequenceOrThrow(figure15Der), 1).start;
			expect(figure15Der.at(unusedBitsOffset)).toBe(0);
			const paddedBitString = Uint8Array.from(figure15Der);
			paddedBitString[unusedBitsOffset] = 1;

			for (const malformed of [trailing, truncated, paddedBitString]) {
				const imported = await importSpkiDer(malformed);
				expect(imported.ok).toBe(false);
				if (!imported.ok) {
					expect(imported.code).toBe('malformed');
					expect(imported.message).toBe('Malformed SubjectPublicKeyInfo');
				}
			}
		});

		it('reads public keys under the "PUBLIC KEY" label only', () => {
			// "Public keys are encoded using the 'PUBLIC KEY' label."
			expect(categorizePemBlocksOrThrow(figure15).publicKeys.map((block) => block.label)).toEqual([
				'PUBLIC KEY',
			]);
			expect(pemDecode('PUBLIC KEY', figure15).ok).toBe(true);
			for (const other of ['PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'CERTIFICATE', 'X509 CRL']) {
				expect(pemDecode('PUBLIC KEY', example(other)).ok).toBe(false);
				expect(pemDecode(other, figure15).ok).toBe(false);
			}
		});

		it('generates the PUBLIC KEY label for every public key it exports', async () => {
			// The clause covers public keys, not one algorithm's public keys, so each
			// generated key pair's SPKI export carries this label and nothing else.
			for (const algorithm of [{ kind: 'ecdsa', curve: 'P-384' }, { kind: 'ed25519' }] as const) {
				const keyPair = await generateKeyPair(algorithm);
				const pem = await keyPair.exportSpkiPem();
				expect(splitPemBlocksOrThrow(pem).map((block) => block.label)).toEqual(['PUBLIC KEY']);
				expect(pem).toBe(await exportSpkiPem(keyPair.publicKey));
				expect(Array.from(pemDecodeOrThrow('PUBLIC KEY', pem))).toEqual(
					Array.from(await keyPair.exportSpkiDer()),
				);
				expect(
					readDerSequenceOrThrow(pemDecodeOrThrow('PUBLIC KEY', pem)).map((field) => field.tag),
				).toEqual([SEQUENCE, BIT_STRING]);
			}
		});

		it('carries Figure 15 as the subjectPublicKeyInfo field of a certificate', async () => {
			// Section 4.1.2.7 of [RFC5280] is a certificate field, so this label
			// encodes exactly the structure a certificate embeds: issuing to Figure
			// 15's key puts those octets in the certificate, and reading them back
			// out returns the same textual encoding.
			const issuer = await createSelfSignedCertificate({
				subject: { commonName: 'spki CA' },
				extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] },
			});
			const issued = await createCertificate({
				subject: { commonName: 'spki.example' },
				issuer: { commonName: 'spki CA' },
				publicKey: await importSpkiPemOrThrow(figure15),
				signerPrivateKey: issuer.keyPair.privateKey,
			});
			const parsed = parseCertificatePemOrThrow(issued.pem);
			expect(Array.from(parsed.subjectPublicKeyInfoDer)).toEqual(Array.from(figure15Der));
			expect(parsed.publicKeyAlgorithmOid).toBe(ID_EC_PUBLIC_KEY);
			expect(parsed.publicKeyParametersOid).toBe(SECP384R1);
			expect(await exportSpkiPem(await getSubjectPublicKeyOrThrow(parsed))).toBe(`${figure15}\n`);
		});
	});

	describe('14. Security Considerations', () => {
		const NUL = '\u0000';
		const HT = '\u0009';
		const VT = '\u000B';
		const FF = '\u000C';
		const CR = '\u000D';
		const SP = '\u0020';
		const NBSP = '\u00A0';
		const SOFT_HYPHEN = '\u00AD';
		const ZERO_WIDTH_SPACE = '\u200B';
		const IDEOGRAPHIC_SPACE = '\u3000';

		const figure6 = example('CERTIFICATE');
		const figure6Der = pemDecodeOrThrow('CERTIFICATE', figure6);
		const figure6Base64 = figure6.split('\n').slice(1, -1).join('');

		/** A `textualmsg` carrying `body` under a one-character label. */
		function message(body: string): string {
			return `-----BEGIN X-----\n${body}\n-----END X-----\n`;
		}

		async function sha256Hex(bytes: Uint8Array): Promise<string> {
			return toHex(
				new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', Uint8Array.from(bytes))),
			);
		}

		/** Every Result-returning entry point that takes textual encoding from a caller. */
		const entryPoints = [
			['pemDecode', (input: string) => pemDecode('CERTIFICATE', input)],
			['splitPemBlocks', splitPemBlocks],
			['categorizePemBlocks', categorizePemBlocks],
			['parseCertificatePem', parseCertificatePem],
			['parseCertificateChainPem', parseCertificateChainPem],
			['parseCertificateRevocationListPem', parseCertificateRevocationListPem],
			['parseCertificateSigningRequestPem', parseCertificateSigningRequestPem],
			['parsePkcs7SignedDataPem', parsePkcs7SignedDataPem],
		] as const satisfies readonly (readonly [
			string,
			(input: string) => { readonly ok: boolean; readonly code?: string },
		])[];

		/** Documents that no label licenses, each broken in a different place. */
		const unexpectedData = [
			['a truncated pre-encapsulation boundary', '-----BEGIN'],
			['an empty label and no post-encapsulation boundary', '-----BEGIN -----'],
			['a post-encapsulation boundary with no opener', '-----END CERTIFICATE-----'],
			['an unclosed block', '-----BEGIN CERTIFICATE-----'],
			[
				'boundaries with nothing between them',
				'-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----',
			],
			[
				'boundaries carrying different labels',
				figure6.replace('-----END CERTIFICATE', '-----END X509 CERTIFICATE'),
			],
			[
				'a second pre-encapsulation boundary inside the body',
				figure6.replace('MIICLDCC', '-----BEGIN CERTIFICATE-----\nMIICLDCC'),
			],
			[
				'a pre-encapsulation boundary after the last block',
				`${figure6}\n-----BEGIN CERTIFICATE-----`,
			],
			['six hyphen-minuses on the opener', figure6.replace('-----BEGIN', '------BEGIN')],
			['a NUL smuggled into the body', figure6.replace('MIIC', `MI${NUL}IC`)],
		] as const satisfies readonly (readonly [string, string])[];

		it.each(entryPoints)(
			'answers unexpected data through %s with a typed failure',
			(_name, parse) => {
				// "Data in this format often originates from untrusted sources, thus
				// parsers must be prepared to handle unexpected data without causing
				// security vulnerabilities."
				for (const [description, document] of unexpectedData) {
					const result = parse(document);
					expect([description, result.ok]).toEqual([description, false]);
					if (!result.ok) {
						expect([description, result.code]).toEqual([description, 'malformed']);
					}
				}
			},
		);

		it('bounds the work an untrusted document can demand', () => {
			// The same clause, against the three shapes that buy an attacker work per
			// byte: Appendix B notes DER "always encodes data values in definite-length
			// form (where the length is stated at the beginning of the encoding); thus,
			// a parser can anticipate memory or resource usage up front."
			const start = performance.now();

			const declaresPetabytes = Uint8Array.of(0x30, 0x86, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff);
			const overlongLength = parseCertificateDer(declaresPetabytes);
			expect(overlongLength.ok).toBe(false);
			if (!overlongLength.ok) {
				expect(overlongLength.message).toBe('DER element exceeds input length');
			}

			let nested: Uint8Array = Uint8Array.of(0x05, 0x00);
			for (let depth = 0; depth < 200; depth += 1) {
				nested = derSequence([nested]);
			}
			const tooDeep = parseCertificateDer(nested);
			expect(tooDeep.ok).toBe(false);
			if (!tooDeep.ok) {
				expect(tooDeep.message).toBe('DER exceeds max depth of 64');
			}

			const unclosed = parseCertificateChainPem('-----BEGIN CERTIFICATE-----\n'.repeat(100_000));
			expect(unclosed.ok).toBe(false);

			expect(performance.now() - start).toBeLessThan(1000);
		});

		it('gives every accepted spelling of Figure 6 one fingerprint', async () => {
			// "Implementers building implementations that rely on canonical
			// representation or the ability to fingerprint a particular data object
			// need to understand that this document does not define canonical
			// encodings. The first ambiguity is introduced by permitting the text-
			// encoded representation instead of the binary BER or DER encodings [...]
			// Variations of whitespace [...] can create further ambiguities. [...] If
			// canonical encodings are desired, the encoded structure must be decoded
			// and processed into a canonical form (namely, DER encoding)."
			const lines = figure6.split('\n');
			const spellings = [
				figure6,
				figure6.replaceAll('\n', `${CR}\n`),
				figure6.replaceAll('\n', CR),
				`-----BEGIN CERTIFICATE-----\n${(figure6Base64.match(/.{1,40}/g) ?? []).join('\n')}\n-----END CERTIFICATE-----`,
				`-----BEGIN CERTIFICATE-----\n${figure6Base64}\n-----END CERTIFICATE-----`,
				lines.map((line) => `${line}${SP}${HT}`).join('\n'),
				lines.map((line) => `${HT}${SP}${line}`).join('\n'),
				`Subject: CN=GnuTLS certificate authority\n${figure6}`,
				figure6.replace('-----\n', '-----\n\n'),
				figure6.replaceAll('MI', `M${SP}I`),
			];
			expect(new Set(spellings).size).toBe(spellings.length);

			const textDigests = new Set<string>();
			const derDigests = new Set<string>();
			for (const spelling of spellings) {
				textDigests.add(await sha256Hex(new TextEncoder().encode(spelling)));
				const decoded = pemDecodeOrThrow('CERTIFICATE', spelling);
				expect(Array.from(decoded)).toEqual(Array.from(figure6Der));
				derDigests.add(await sha256Hex(decoded));
				expect(pemEncode('CERTIFICATE', decoded)).toBe(`${figure6}\n`);
				expect(Array.from(parseCertificatePemOrThrow(spelling).der)).toEqual(
					Array.from(figure6Der),
				);
			}
			expect(textDigests.size).toBe(spellings.length);
			expect(derDigests.size).toBe(1);
		});

		it('refuses the base64 spellings that would carry data past the DER', () => {
			// "Variations of whitespace and non-base64 alphabetic characters can create
			// further ambiguities. Data encoding ambiguities also create opportunities
			// for side channels." Section 2 takes the encapsulated data as "base64-
			// encoded data according to Section 4 of [RFC4648]", where a short final
			// quantum is completed with "bits with value zero" and pad characters, so
			// each of these spells octets the RFC 4648 encoder never emits.
			expect(Array.from(pemDecodeOrThrow('X', message('AQ==')))).toEqual([1]);
			expect(Array.from(pemDecodeOrThrow('X', message('AQI=')))).toEqual([1, 2]);
			for (const body of ['AR==', 'AS==', 'Ab==', 'A/==', 'AQJ=', 'AQK=', 'AQ', 'AQI']) {
				expect([body, pemDecode('X', message(body)).ok]).toEqual([body, false]);
			}
			// Three other spellings of Figure 6's own final quantum hold its certificate.
			expect(figure6Base64.slice(-4)).toBe('Ipo=');
			for (const quantum of ['Ipp=', 'Ipq=', 'Ipr=']) {
				const respelled = `-----BEGIN CERTIFICATE-----\n${figure6Base64.slice(0, -4)}${quantum}\n-----END CERTIFICATE-----`;
				expect([quantum, parseCertificatePem(respelled).ok]).toEqual([quantum, false]);
			}
			for (const character of [
				NUL,
				VT,
				FF,
				NBSP,
				SOFT_HYPHEN,
				ZERO_WIDTH_SPACE,
				IDEOGRAPHIC_SPACE,
				'*',
				'_',
				'-',
			]) {
				const smuggled = `-----BEGIN CERTIFICATE-----\n${figure6Base64.slice(0, 8)}${character}${figure6Base64.slice(8)}\n-----END CERTIFICATE-----`;
				expect([character, pemDecode('CERTIFICATE', smuggled).ok]).toEqual([character, false]);
			}
		});

		it('keeps one encoding under two labels from becoming one meaning', () => {
			// "[F]urther ambiguities arise when multiple labels are treated as similar."
			const aliased = pemEncode('X509 CERTIFICATE', figure6Der);
			const blocks = splitPemBlocksOrThrow(aliased);
			expect(blocks.map((block) => block.label)).toEqual(['X509 CERTIFICATE']);
			expect(Array.from(blocks[0]?.bytes ?? [])).toEqual(Array.from(figure6Der));

			expect(pemDecode('CERTIFICATE', aliased).ok).toBe(false);
			expect(parseCertificatePem(aliased).ok).toBe(false);
			const categorized = categorizePemBlocksOrThrow(aliased);
			expect(categorized.certificates).toEqual([]);
			expect(categorized.others.map((block) => block.label)).toEqual(['X509 CERTIFICATE']);

			const bundle = unwrap(parseCertificateChainPem(`${aliased}${figure6}\n`));
			expect(bundle.map((certificate) => certificate.subject.values.commonName)).toEqual([
				'GnuTLS certificate authority',
			]);
		});
	});

	describe('15. References', () => {
		describe('15.1. Normative References', () => {
			// [RFC4648] and [RFC5234] carry the rules of the textual encoding itself:
			// Section 2 takes the encapsulated data as "base64-encoded data according to
			// Section 4 of [RFC4648]", and Section 3 gives "[t]he ABNF [RFC5234] of the
			// textual encoding". The alphabet, the pad character, the treatment of
			// characters outside the alphabet, and the meaning of every rule name and
			// operator in Figures 1 to 3 are stated only in the referenced text.
			// [RFC5280], [RFC2986], [RFC2315], [RFC5652], [RFC5755], and [RFC5958] carry
			// the structures under each label and are exercised in Sections 5 to 13;
			// [X.690] carries the encoding of those structures and is exercised wherever
			// this suite holds a parser to the definite-length DER form. [RFC2119] fixes
			// the force of the key words and has no encoding of its own.
			const table1 = rfc4648.slice(
				rfc4648.indexOf('Table 1: The Base 64 Alphabet'),
				rfc4648.indexOf('Special processing is performed'),
			);
			const encodings = new Map<number, string>();
			for (const entry of table1.matchAll(/(\d+) ([A-Za-z0-9+/])(?=\s)/g)) {
				encodings.set(Number(entry[1]), entry[2] ?? '');
			}
			const pad = /\(pad\) (\S)/.exec(table1)?.[1] ?? '';
			const alphabet = Array.from(
				{ length: encodings.size },
				(_, value) => encodings.get(value) ?? '',
			).join('');

			const coreRules = rfc5234.slice(rfc5234.lastIndexOf('B.1.  Core Rules'));

			/** The right-hand side of an RFC 5234 Appendix B.1 core rule, comment stripped. */
			function coreRuleDefinition(name: string): string {
				const definition = new RegExp(`^ +${name} +=  ([^;\\n]+)`, 'm').exec(coreRules)?.[1];
				if (definition === undefined) {
					throw new Error(`RFC 5234 Appendix B.1 has no ${name} rule`);
				}
				return definition.trim();
			}

			/** The code points of a `%xHH` or `%xHH-HH` terminal, or nothing for a rule name. */
			function terminalValues(alternative: string): readonly number[] | undefined {
				const range = /^%x([0-9A-F]{2})(?:-([0-9A-F]{2}))?$/.exec(alternative);
				const first = range?.[1];
				if (first === undefined) {
					return undefined;
				}
				const last = range?.[2];
				const start = Number.parseInt(first, 16);
				const end = last === undefined ? start : Number.parseInt(last, 16);
				return Array.from({ length: end - start + 1 }, (_, offset) => start + offset);
			}

			/** The US-ASCII code points an RFC 5234 Appendix B.1 core rule matches. */
			function coreRule(name: string): readonly number[] {
				return coreRuleDefinition(name)
					.split(' / ')
					.flatMap((alternative) => terminalValues(alternative) ?? coreRule(alternative));
			}

			/** The one US-ASCII string an RFC 5234 Appendix B.1 core rule matches. */
			function coreRuleText(name: string): string {
				const definition = coreRuleDefinition(name);
				if (definition.includes(' / ')) {
					throw new Error(`RFC 5234 Appendix B.1 ${name} matches more than one string`);
				}
				return definition
					.split(' ')
					.map((term) => {
						const values = terminalValues(term);
						if (values === undefined) {
							return coreRuleText(term);
						}
						if (values.length !== 1) {
							throw new Error(`RFC 5234 Appendix B.1 ${name} spans a range of values`);
						}
						return String.fromCodePoint(...values);
					})
					.join('');
			}

			/** A `textualmsg` carrying `body` under a one-character label. */
			function message(body: string): string {
				return `-----BEGIN X-----\n${body}\n-----END X-----\n`;
			}

			/** The base64 group Section 4 of [RFC4648] prints for a final quantum. */
			function quantum(bytes: readonly number[]): string {
				const first = bytes[0] ?? 0;
				const second = bytes[1];
				const third = bytes[2];
				const indices = [first >> 2, ((first & 0b11) << 4) | ((second ?? 0) >> 4)];
				if (second !== undefined) {
					indices.push(((second & 0b1111) << 2) | ((third ?? 0) >> 6));
				}
				if (third !== undefined) {
					indices.push(third & 0b111111);
				}
				return (
					indices.map((index) => encodings.get(index) ?? '').join('') +
					pad.repeat(4 - indices.length)
				);
			}

			/** `length` octets of content whose quanta all differ. */
			function filler(length: number): Uint8Array {
				const bytes = new Uint8Array(length);
				for (let index = 0; index < length; index += 1) {
					bytes[index] = (index * 53) % 256;
				}
				return bytes;
			}

			it('encodes each 6-bit group as Table 1 of [RFC4648] encodes it', () => {
				// "Each 6-bit group is used as an index into an array of 64 printable
				// characters. The character referenced by the index is placed in the
				// output string." A three-octet quantum whose leading six bits hold a
				// value and whose remaining eighteen are zero prints that value's
				// encoding followed by three A.
				expect(encodings.size).toBe(64);
				expect(pad).toBe('=');
				expect(alphabet).toHaveLength(64);
				for (const [value, character] of encodings) {
					const quantum = Uint8Array.of(value << 2, 0, 0);
					expect([value, pemEncode('X', quantum)]).toEqual([value, message(`${character}AAA`)]);
					expect([value, Array.from(pemDecodeOrThrow('X', message(`${character}AAA`)))]).toEqual([
						value,
						Array.from(quantum),
					]);
				}
			});

			it('draws base64char from the ALPHA and DIGIT of [RFC5234]', () => {
				// base64char = ALPHA / DIGIT / "+" / "/", over "ALPHA = %x41-5A / %x61-7A"
				// and "DIGIT = %x30-39". The two normative references have to agree: the
				// 64 characters of Table 1 are exactly that class, and every one of them
				// carries data through this parser.
				const base64char = [
					...coreRule('ALPHA'),
					...coreRule('DIGIT'),
					'+'.codePointAt(0) ?? 0,
					'/'.codePointAt(0) ?? 0,
				].map((code) => String.fromCodePoint(code));
				expect(base64char.slice().sort()).toEqual(alphabet.split('').sort());
				for (const character of base64char) {
					expect([character, pemDecode('X', message(`${character}QID`)).ok]).toEqual([
						character,
						true,
					]);
				}
			});

			it('rejects encoded data holding characters outside the base alphabet', () => {
				// [RFC4648] Section 3.3: "Implementations MUST reject the encoded data if
				// it contains characters outside the base alphabet when interpreting
				// base-encoded data, unless the specification referring to this document
				// explicitly states otherwise. Such specifications may instead state, as
				// MIME does, that characters outside the base encoding alphabet should
				// simply be ignored." The "SHOULD ignore whitespace and other non-base64
				// characters" of Section 2 sits in the sentence about the data before the
				// encapsulation boundaries, which Section 5.2 names explanatory text;
				// inside the boundaries base64text admits base64char and the *WSP eol of
				// base64line and nothing further, so the reject stands there. Standing
				// one character of a four-character group in for another keeps the group
				// whole, so what survives is a membership test on the alphabet and on
				// nothing else.
				const sweep = [
					...Array.from({ length: 0x300 }, (_, code) => code),
					0x200b,
					0x2028,
					0x2029,
					0x3000,
					0xfeff,
				];
				const substituted = sweep.filter(
					(code) => pemDecode('X', message(`AQ${String.fromCodePoint(code)}D`)).ok,
				);
				expect(substituted.map((code) => String.fromCodePoint(code)).sort()).toEqual(
					alphabet.split('').sort(),
				);
			});

			it('ignores the whitespace this document adds to the encoded data and nothing else', () => {
				// The same clause, on the other half of its "unless the specification
				// referring to this document explicitly states otherwise": base64line is
				// "1*base64char *WSP eol", so this document adds the WSP, CR, and LF of
				// [RFC5234] to the encoded data and adds nothing else. A character the
				// parser ignores leaves the octets the group carried unchanged.
				const ignorable = new Set([...coreRule('WSP'), ...coreRule('CR'), ...coreRule('LF')]);
				const sweep = [
					...Array.from({ length: 0x300 }, (_, code) => code),
					0x200b,
					0x2028,
					0x2029,
					0x3000,
					0xfeff,
				];
				const transparent = sweep.filter((code) => {
					const decoded = pemDecode('X', message(`AQID${String.fromCodePoint(code)}BAUG`));
					return decoded.ok && decoded.value.length === 6;
				});
				expect(transparent).toEqual(sweep.filter((code) => ignorable.has(code)));
			});

			it('completes every final quantum with the pad character', () => {
				// [RFC4648] Section 3.2: "Implementations MUST include appropriate pad
				// characters at the end of encoded data unless the specification
				// referring to this document explicitly states otherwise." This document
				// states otherwise nowhere, so an 8- or 16-bit final quantum is printed
				// with the two or one "=" that Section 4 cases (2) and (3) give it, and
				// dropping them leaves data no parser may read back.
				for (let length = 1; length <= 24; length += 1) {
					const content = new Uint8Array(length);
					for (let index = 0; index < length; index += 1) {
						content[index] = (index * 37) % 256;
					}
					const body = pemEncode('X', content).split('\n')[1] ?? '';
					const expected = (3 - (length % 3)) % 3;
					expect([length, body.split(pad).length - 1]).toEqual([length, expected]);
					expect([length, body.endsWith(pad.repeat(expected))]).toEqual([length, true]);
					expect([length, Array.from(pemDecodeOrThrow('X', message(body)))]).toEqual([
						length,
						Array.from(content),
					]);
					if (expected > 0) {
						const unpadded = body.slice(0, -expected);
						expect([length, pemDecode('X', message(unpadded)).ok]).toEqual([length, false]);
					}
				}
			});

			it('spells every final quantum as Section 4 of [RFC4648] spells it', () => {
				// "The encoding process represents 24-bit groups of input bits as output
				// strings of 4 encoded characters. [...] When fewer than 24 input bits are
				// available in an input group, bits with value zero are added (on the
				// right) to form an integral number of 6-bit groups." Section 3.5 makes
				// that fill mandatory rather than incidental: "These pad bits MUST be set
				// to zero by conforming encoders", without which "there is no canonical
				// representation of base-encoded data, and multiple base-encoded strings
				// can be decoded to the same binary data."
				for (let first = 0; first <= 0xff; first += 1) {
					for (const bytes of [
						[first],
						[first, (first * 7) % 256],
						[first, 0xff - first, (first * 13) % 256],
					]) {
						const body = pemEncode('X', Uint8Array.from(bytes)).split('\n')[1] ?? '';
						expect([bytes, body]).toEqual([bytes, quantum(bytes)]);
						expect([bytes, Array.from(pemDecodeOrThrow('X', message(body)))]).toEqual([
							bytes,
							bytes,
						]);
					}
				}
			});

			it('breaks the encoded data only where this document directs a break', () => {
				// [RFC4648] Section 3.1: "Implementations MUST NOT add line feeds to
				// base-encoded data unless the specification referring to this document
				// explicitly directs base encoders to add line feeds after a specific
				// number of characters." Section 2 directs 64 and no other number, so
				// neither the 76 of MIME nor a four-character group boundary buys a break
				// of its own, and a body that fits one line gets one line.
				for (let length = 0; length <= 120; length += 1) {
					const bytes = filler(length);
					const lines = pemEncode('X', bytes).split('\n').slice(1, -2);
					const encoded = 4 * Math.ceil(length / 3);
					const full = Array.from({ length: Math.floor(encoded / 64) }, () => 64);
					const remainder = encoded % 64;
					const expected = encoded === 0 ? [0] : [...full, ...(remainder === 0 ? [] : [remainder])];
					expect([length, lines.map((line) => line.length)]).toEqual([length, expected]);
					expect([length, Array.from(pemDecodeOrThrow('X', message(lines.join('\n'))))]).toEqual([
						length,
						Array.from(bytes),
					]);
				}
			});

			it('reads the boundary keywords in the one case the figures print', () => {
				// [RFC5234] Section 2.3: "ABNF strings are case insensitive", so the
				// "-----BEGIN " and "-----END " literals of Figure 1 generate lowercase
				// spellings of both boundaries as well. Nothing in this document restates
				// them as case sensitive, and nothing obliges a parser to read every
				// string the grammar generates: Section 14 counts each further spelling of
				// one document as an ambiguity, and every figure here prints the keywords
				// uppercase. A line spelled otherwise stays the data before the
				// encapsulation boundaries that Section 2 permits.
				const printed = new Set(
					Array.from(rfc.matchAll(/-----(begin|end) /gi), (match) => match[1] ?? ''),
				);
				expect(Array.from(printed).sort()).toEqual(['BEGIN', 'END']);
				expect(pemEncode('X', Uint8Array.of(1, 2, 3))).toBe(
					'-----BEGIN X-----\nAQID\n-----END X-----\n',
				);

				const boundaries = (begin: string, end: string): string =>
					`-----${begin} X-----\nAQID\n-----${end} X-----\n`;
				expect(Array.from(pemDecodeOrThrow('X', boundaries('BEGIN', 'END')))).toEqual([1, 2, 3]);
				const miscased = [
					['begin', 'END'],
					['BEGIN', 'end'],
					['Begin', 'End'],
					['begin', 'end'],
				] as const satisfies readonly (readonly [string, string])[];
				for (const [begin, end] of miscased) {
					const document = boundaries(begin, end);
					expect([document, pemDecode('X', document).ok]).toEqual([document, false]);
				}
				expect(splitPemBlocksOrThrow(boundaries('begin', 'end'))).toEqual([]);
			});

			it('takes each eol Figure 1 names from the core rules of [RFC5234]', () => {
				// eol = CRLF / CR / LF, over "CRLF = CR LF", "CR = %x0D", and "LF = %x0A".
				// A CR LF pair is one of the three line endings, not a CR eol followed by
				// a line that base64line, which requires 1*base64char, could not hold.
				const alternatives = (/^ +eol +=\s+([^;\n]+)/m.exec(rfc)?.[1] ?? '').trim().split(' / ');
				expect(alternatives).toEqual(['CRLF', 'CR', 'LF']);
				const spellings = alternatives.map((name) => coreRuleText(name));
				expect(spellings).toEqual(['\r\n', '\r', '\n']);

				for (const eol of spellings) {
					const document = `-----BEGIN X-----${eol}AQID${eol}BAUG${eol}-----END X-----${eol}`;
					expect([eol, Array.from(pemDecodeOrThrow('X', document))]).toEqual([
						eol,
						[1, 2, 3, 4, 5, 6],
					]);
					// base64finl = *base64char (base64pad *WSP eol base64pad / *2base64pad)
					const split = `-----BEGIN X-----${eol}AQ${pad}${eol}${pad}${eol}-----END X-----${eol}`;
					expect([eol, Array.from(pemDecodeOrThrow('X', split))]).toEqual([eol, [1]]);
				}
			});

			it('separates the words of a label with the SP of [RFC5234] and no other blank', () => {
				// label = [ labelchar *( ["-" / SP] labelchar ) ], over "SP = %x20" and
				// "WSP = SP / HTAB": the separator is that one character, so the HTAB the
				// other half of WSP contributes joins no two labelchar.
				const sp = coreRuleText('SP');
				const htab = coreRuleText('HTAB');
				expect([sp, htab]).toEqual([' ', '\t']);
				expect(
					coreRule('WSP')
						.map((code) => String.fromCodePoint(code))
						.sort(),
				).toEqual([sp, htab].sort());

				expect(pemEncode(`X${sp}Y`, Uint8Array.of(1, 2, 3))).toBe(
					`-----BEGIN X${sp}Y-----\nAQID\n-----END X${sp}Y-----\n`,
				);
				expect(
					Array.from(pemDecodeOrThrow(`X${sp}Y`, pemEncode(`X${sp}Y`, Uint8Array.of(1)))),
				).toEqual([1]);
				expect(() => pemEncode(`X${htab}Y`, Uint8Array.of(1))).toThrow('Invalid PEM label');
				const tabbed = `-----BEGIN X${htab}Y-----\nAQID\n-----END X${htab}Y-----\n`;
				expect(pemDecode(`X${htab}Y`, tabbed).ok).toBe(false);
				expect(splitPemBlocks(tabbed).ok).toBe(false);
			});
		});

		describe('15.2. Informative References', () => {
			// [RFC1421] and [RFC934] carry the format this one descends from, and every
			// sentence that cites them says what this format does not take from it:
			// the encapsulated headers of Section 2, the dash-stuffed boundary, and the
			// <encbinbody> line shape Section 3 replaces. [RFC4880] and [RFC4716] carry
			// the two variations named beside them. [P7v1.6] and [RFC7292] carry the
			// module Figure 5 footnotes, and [RFC2585] the registration Section 5.3
			// leaves untouched. [RFC5208] carries PrivateKeyInfo and
			// EncryptedPrivateKeyInfo, which Sections 10 and 11 bind and exercise.
			const figure6 = example('CERTIFICATE');
			const figure6Der = pemDecodeOrThrow('CERTIFICATE', figure6);
			const figure6Body = pemEncode('CERTIFICATE', figure6Der).split('\n').slice(1, -2).join('');

			/** The text of a vendored RFC this bibliography lists. */
			async function referenced(number: number): Promise<string> {
				return await Bun.file(`${rfcDir}/rfc${number}.txt`).text();
			}

			/** The `index`th field of a DER SEQUENCE. */
			function nthField(fields: readonly DerElement[], index: number): DerElement {
				const field = fields[index];
				if (field === undefined) {
					throw new Error(`no DER field at index ${index}`);
				}
				return field;
			}

			/** A dotted object identifier from an ASN.1 `{name(arc) ...}` arc list. */
			function dottedOid(arcs: string): string {
				return arcs
					.trim()
					.split(/\s+/)
					.filter((token) => token !== '')
					.map((token) => /\((\d+)\)$/.exec(token)?.[1] ?? token)
					.join('.');
			}

			/** The repetition bounds and element name of one RFC 1421 Section 9 production. */
			async function encbinGrammar(): Promise<{
				readonly fullLineGroups: number;
				readonly finalLineGroups: readonly [number, number];
				readonly groupChars: number;
			}> {
				const rfc1421 = await referenced(1421);
				const grammar = rfc1421.slice(rfc1421.indexOf('9.  Descriptive Grammar'));
				const body =
					/<encbinbody> ::= \*\((\d+)\*(\d+)<encbingrp> CRLF\) \[(\d+)\*(\d+)<encbingrp>/.exec(
						grammar,
					);
				const group = /<encbingrp> ::= (\d+)\*(\d+)<encbinchar>/.exec(grammar);
				expect([body?.[1], body?.[2], body?.[3], body?.[4]]).toEqual(['16', '16', '1', '16']);
				expect([group?.[1], group?.[2]]).toEqual(['4', '4']);
				return {
					fullLineGroups: Number(body?.[2]),
					finalLineGroups: [Number(body?.[3]), Number(body?.[4])],
					groupChars: Number(group?.[2]),
				};
			}

			it('wraps the encoded data as the <encbinbody> of [RFC1421] wraps it', async () => {
				// Section 2: "Generators MUST wrap the base64-encoded lines so that each
				// line consists of exactly 64 characters except for the final line, which
				// will encode the remainder of the data (within the 64-character line
				// boundary), and they MUST NOT emit extraneous whitespace. [...] These
				// requirements are consistent with PEM [RFC1421]." RFC 1421 Section 9:
				// "<encbinbody> ::= *(16*16<encbingrp> CRLF) [1*16<encbingrp> CRLF]" over
				// "<encbingrp> ::= 4*4<encbinchar>" and "<encbinchar> ::= ALPHA / DIGIT /
				// "+" / "/" / "="", so consistency means full lines of sixteen groups and
				// a final line of one to sixteen, every group four characters wide.
				const { fullLineGroups, finalLineGroups, groupChars } = await encbinGrammar();
				for (let length = 1; length <= 96; length += 1) {
					const content = new Uint8Array(length);
					for (let index = 0; index < length; index += 1) {
						content[index] = (index * 53) % 256;
					}
					const lines = pemEncode('CERTIFICATE', content).split('\n').slice(1, -2);
					const finalLine = lines.at(-1) ?? '';
					const fullLines = lines.slice(0, -1);
					expect([length, fullLines.map((line) => line.length)]).toEqual([
						length,
						fullLines.map(() => fullLineGroups * groupChars),
					]);
					expect([length, finalLine.length % groupChars]).toEqual([length, 0]);
					expect([
						length,
						finalLine.length / groupChars >= finalLineGroups[0],
						finalLine.length / groupChars <= finalLineGroups[1],
					]).toEqual([length, true, true]);
					expect([length, lines.every((line) => /^[A-Za-z0-9+/=]+$/.test(line))]).toEqual([
						length,
						true,
					]);
					expect([
						length,
						Array.from(pemDecodeOrThrow('CERTIFICATE', pemEncode('CERTIFICATE', content))),
					]).toEqual([length, Array.from(content)]);
				}
			});

			it('reads the base64line widths <encbinbody> cannot spell', async () => {
				// Section 3, on base64text: "we could also use <encbinbody> from RFC 1421,
				// which requires 16 groups of 4 chars, which means exactly 64 chars per
				// line, except the final line, but this is more accurate." base64line is
				// "1*base64char *WSP eol", so a line holding a number of characters no
				// run of <encbingrp> can spell still carries encoded data here.
				const { groupChars } = await encbinGrammar();
				for (const width of [1, 3, 5, 7, 17, 63, 65]) {
					expect([width, width % groupChars === 0]).toEqual([width, false]);
					const wrapped = figure6Body.match(new RegExp(`.{1,${width}}`, 'g'))?.join('\n') ?? '';
					const document = `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----\n`;
					expect([width, Array.from(pemDecodeOrThrow('CERTIFICATE', document))]).toEqual([
						width,
						Array.from(figure6Der),
					]);
				}
			});

			it('takes no encapsulated header field of [RFC1421] inside the boundaries', async () => {
				// Section 2: "Unlike legacy PEM encoding [RFC1421], OpenPGP ASCII armor,
				// and the OpenSSH key file format, textual encoding does *not* define or
				// permit headers to be encoded alongside the data." RFC 1421 Section 9
				// spells every field of <pemhdr> as a name, a colon, and a body, and
				// Section 4.6 puts them between the pre-encapsulation boundary and the
				// encapsulated text, where this grammar has base64text and nothing else.
				const rfc1421 = await referenced(1421);
				const grammar = rfc1421.slice(rfc1421.indexOf('9.  Descriptive Grammar'));
				const fields = Array.from(
					new Set(Array.from(grammar.matchAll(/"([A-Za-z][A-Za-z-]*)" ":"/g), (m) => m[1] ?? '')),
				);
				expect(fields).toEqual([
					'Proc-Type',
					'Content-Domain',
					'DEK-Info',
					'Originator-ID-Asymmetric',
					'Originator-ID-Symmetric',
					'Recipient-ID-Asymmetric',
					'Recipient-ID-Symmetric',
					'Originator-Certificate',
					'Issuer-Certificate',
					'MIC-Info',
					'Key-Info',
					'CRL',
				]);
				for (const field of fields) {
					const document = `-----BEGIN CERTIFICATE-----\n${field}: 4,ENCRYPTED\n\n${figure6Body}\n-----END CERTIFICATE-----\n`;
					const decoded = pemDecode('CERTIFICATE', document);
					expect([field, decoded.ok]).toEqual([field, false]);
					if (!decoded.ok) {
						expect([field, decoded.code]).toEqual([field, 'malformed']);
					}
					const split = splitPemBlocks(document);
					expect([field, split.ok]).toEqual([field, false]);
					if (!split.ok) {
						expect([field, split.code]).toEqual([field, 'malformed']);
					}
					expect([field, parseCertificatePem(document).ok]).toEqual([field, false]);
				}
				// The empty area the same sentence permits is all that is left when the
				// header line goes: "Empty space can appear between the pre-encapsulation
				// boundary and the base64".
				const headerless = `-----BEGIN CERTIFICATE-----\n\n${figure6Body}\n-----END CERTIFICATE-----\n`;
				expect(Array.from(pemDecodeOrThrow('CERTIFICATE', headerless))).toEqual(
					Array.from(figure6Der),
				);
			});

			it('does not burst the dash-stuffed lines of [RFC934]', async () => {
				// Section 1: the tradition "can be traced back to Privacy-Enhanced Mail
				// (PEM) [RFC1421], based on a proposal by Marshall Rose in Message
				// Encapsulation [RFC934]". RFC 934 defines "an encapsulation boundary
				// (EB) [...] as a line in the message which starts with a dash (decimal
				// code 45, "-")" and stuffs one that occurs inside a forwarded text with
				// "a dash followed by a space (decimal code 32, " ")", after which "the
				// bursting agent does not treat the line as an encapsulation boundary,
				// and outputs the remainder of the line instead". Section 2 keeps neither
				// rule: a boundary here is "-----BEGIN " label "-----", so a stuffed copy
				// of Figure 6 is data before the encapsulation boundaries and stays data.
				const rfc934 = (await referenced(934)).replace(/\s+/g, ' ');
				const dash = /starts with a dash \((?:decimal code )?(\d+), "(.)"\)/.exec(rfc934);
				const blank = /followed by a space \((?:decimal code )?(\d+), "(.)"\)/.exec(rfc934);
				expect([dash?.[1], dash?.[2], blank?.[1], blank?.[2]]).toEqual(['45', '-', '32', ' ']);
				const stuffing = `${String.fromCharCode(Number(dash?.[1]))}${String.fromCharCode(
					Number(blank?.[1]),
				)}`;
				expect(stuffing).toBe('- ');

				const stuffed = figure6
					.split('\n')
					.map((line) => (line.startsWith('-') ? `${stuffing}${line}` : line))
					.join('\n');
				expect(splitPemBlocksOrThrow(stuffed)).toEqual([]);
				expect(pemDecode('CERTIFICATE', stuffed).ok).toBe(false);
				const bundle = `${stuffed}\n${figure6}`;
				expect(splitPemBlocksOrThrow(bundle).map((block) => block.label)).toEqual(['CERTIFICATE']);
				expect(parseCertificatePemOrThrow(bundle).subject.values.commonName).toBe(
					'GnuTLS certificate authority',
				);

				const stuffedBody = figure6
					.split('\n')
					.map((line, index) => (index === 1 ? `${stuffing}${line}` : line))
					.join('\n');
				expect(pemDecode('CERTIFICATE', stuffedBody).ok).toBe(false);

				// RFC 934 also folds one boundary into two messages: "For two adjacent
				// encapsulated messages, the post-EB of the first message is also the
				// pre-EB of the second message", and "two or more adjacent EBs are
				// equivalent to one EB". Each instance here closes with its own posteb,
				// so two adjacent instances carry two posteb and two preeb.
				const adjacent = `${figure6}\n${example('X509 CRL')}`;
				expect(splitPemBlocksOrThrow(adjacent).map((block) => block.label)).toEqual([
					'CERTIFICATE',
					'X509 CRL',
				]);
				expect(adjacent.split('\n').filter((line) => line.startsWith('-----END ')).length).toBe(2);
			});

			it('finds no textual encoding in the key files of [RFC4716]', async () => {
				// Section 1: "Variations include OpenPGP ASCII armor [RFC4880] and OpenSSH
				// key file format [RFC4716]." RFC 4716 Section 3.2: "The first line of a
				// conforming key file MUST be a begin marker, which is the literal text:
				// ---- BEGIN SSH2 PUBLIC KEY ----", four hyphen-minuses and a blank on
				// either side of the text, where Section 2 has "exactly five hyphen-minus
				// [...] on both ends of the encapsulation boundaries, no more, no less"
				// and "exactly one space character (SP) separating the "BEGIN" or "END"
				// from the label". Neither marker is an encapsulation boundary here, so a
				// key file is data and a certificate beside it still reads.
				const rfc4716 = await referenced(4716);
				const begin = /is the literal text:\s+(---- BEGIN SSH2 PUBLIC KEY ----)/.exec(rfc4716)?.[1];
				const end = /is the literal text:\s+(---- END SSH2 PUBLIC KEY ----)/.exec(rfc4716)?.[1];
				expect([begin, end]).toEqual([
					'---- BEGIN SSH2 PUBLIC KEY ----',
					'---- END SSH2 PUBLIC KEY ----',
				]);
				const examplesRegion = rfc4716.slice(rfc4716.indexOf('The following are some examples'));
				const keyFiles = Array.from(
					examplesRegion.matchAll(
						/^ {3}---- BEGIN SSH2 PUBLIC KEY ----$[\s\S]*?^ {3}---- END SSH2 PUBLIC KEY ----$/gm,
					),
					(match) => match[0].replace(/^ {3}/gm, ''),
				);
				expect(keyFiles).toHaveLength(4);
				for (const keyFile of keyFiles) {
					expect(keyFile.split('\n').at(0)).toBe(begin);
					expect(keyFile.split('\n').at(-1)).toBe(end);
					expect(splitPemBlocksOrThrow(keyFile)).toEqual([]);
					expect(pemDecode('SSH2 PUBLIC KEY', keyFile).ok).toBe(false);
					const bundle = `${keyFile}\n${figure6}`;
					expect(splitPemBlocksOrThrow(bundle).map((block) => block.label)).toEqual([
						'CERTIFICATE',
					]);
					expect(parseCertificatePemOrThrow(bundle).subject.values.commonName).toBe(
						'GnuTLS certificate authority',
					);
				}
			});

			it('reads no ASCII armor of [RFC4880] as a textual encoding', async () => {
				// RFC 4880 Section 6.2 concatenates armor from "An Armor Header Line,
				// appropriate for the type of data [...] Armor Headers [...] A blank
				// (zero-length, or containing only whitespace) line [...] The
				// ASCII-Armored data [...] An Armor Checksum [...] The Armor Tail", the
				// checksum being "a 24-bit Cyclic Redundancy Check (CRC) converted to
				// four characters of radix-64 encoding [...] preceded by an equal sign
				// (=)". The header line and the tail of the Section 6.6 example are a
				// preeb and a posteb this grammar admits, and the two parts between them
				// that this document does not define are what keeps the message out:
				// Section 2 permits no headers, and base64finl closes the encoded data
				// with at most two "=".
				const rfc4880 = await referenced(4880);
				const tail = '-----END PGP MESSAGE-----';
				const start = rfc4880.indexOf('   -----BEGIN PGP MESSAGE-----');
				const armor = rfc4880
					.slice(start, rfc4880.indexOf(tail, start) + tail.length)
					.replace(/^ {3}/gm, '');
				const lines = armor.split('\n');
				const blank = lines.indexOf('');
				const checksum = lines.findIndex((line) => line.startsWith('='));
				expect([lines.at(0), lines.at(1), lines.at(checksum), lines.at(-1)]).toEqual([
					'-----BEGIN PGP MESSAGE-----',
					'Version: OpenPrivacy 0.99',
					'=njUN',
					tail,
				]);
				expect([blank, checksum]).toEqual([2, 5]);
				expect(pemDecode('PGP MESSAGE', armor).ok).toBe(false);

				// Section 2: "Parsers MUST handle non-conforming data gracefully."
				const split = splitPemBlocks(armor);
				expect(split.ok).toBe(false);
				if (!split.ok) {
					expect(split.code).toBe('malformed');
				}

				const withoutHeaders = [lines.at(0), ...lines.slice(blank + 1)].join('\n');
				expect(pemDecode('PGP MESSAGE', withoutHeaders).ok).toBe(false);
				const withoutChecksum = [
					lines.at(0),
					...lines.slice(blank + 1, checksum),
					...lines.slice(checksum + 1),
				].join('\n');
				const armored = pemDecodeOrThrow('PGP MESSAGE', withoutChecksum);
				expect(pemEncode('PGP MESSAGE', armored)).toBe(`${withoutChecksum}\n`);
			});

			it('writes the ContentInfo of the module [P7v1.6] added and [RFC7292] carries forward', async () => {
				// Figure 5's footnote on id-pkcs7: "* This OID does not actually appear in
				// PKCS #7 v1.5 [RFC2315]. It was defined in the ASN.1 module to PKCS #7
				// v1.6 [P7v1.6], and has been carried forward through PKCS #12 [RFC7292]."
				// RFC 7292 Appendix D imports "ContentInfo, DigestInfo FROM PKCS-7 {iso(1)
				// member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-7(7) modules(0)
				// pkcs-7(1)}", which is the module Figure 5 assigns to id-pkcs7.
				const rfc7292 = (await referenced(7292)).replace(/\s+/g, ' ');
				const imported = /ContentInfo, DigestInfo FROM PKCS-7 \{([^}]*)\}/.exec(rfc7292)?.[1];
				expect(imported).toBeDefined();
				const moduleOid = dottedOid(imported ?? '');
				const figure5 = rfc.slice(rfc.indexOf('id-pkixmod OBJECT'), rfc.indexOf('Figure 5:'));
				const idPkcs = dottedOid(
					/id-pkcs {4}OBJECT IDENTIFIER ::= \{([^}]*)\}/.exec(figure5.replace(/\n/g, ' '))?.[1] ??
						'',
				);
				const idPkcs7 = /id-pkcs7 {3}OBJECT IDENTIFIER ::= \{id-pkcs ([^}]*)\}/.exec(figure5)?.[1];
				expect(moduleOid).toBe(`${idPkcs}.${dottedOid(idPkcs7 ?? '')}`);
				expect(decodeDerOidOrThrow(readDerRootOrThrow(derOid(moduleOid)))).toBe(moduleOid);

				// RFC 2315 Section 14: "pkcs-7 OBJECT IDENTIFIER ::= { iso(1)
				// member-body(2) US(840) rsadsi(113549) pkcs(1) 7 }", with "data OBJECT
				// IDENTIFIER ::= { pkcs-7 1 }" and "signedData OBJECT IDENTIFIER ::=
				// { pkcs-7 2 }" under it. The module hangs off that same arc, and the
				// ContentInfo it declares is what this library writes for the PKCS7 label
				// of Section 8 and for the authSafe of a PKCS #12 PFX.
				const rfc2315 = (await Bun.file(`${rfcDir}/rfc2315.txt`).text()).replace(/\s+/g, ' ');
				const pkcs7Arc = dottedOid(
					/pkcs-7 OBJECT IDENTIFIER ::= \{([^}]*)\}/.exec(rfc2315)?.[1] ?? '',
				);
				expect(pkcs7Arc).toBe('1.2.840.113549.1.7');
				expect(moduleOid.split('.').slice(0, -2).join('.')).toBe(pkcs7Arc);

				const { certificate } = await createSelfSignedCertificate({
					subject: { commonName: 'pkcs7-module.example' },
				});
				const bag = unwrap(createPkcs7CertBag([certificate.der]));
				const bagFields = readDerSequenceOrThrow(bag.der);
				expect(bagFields).toHaveLength(2);
				expect(decodeDerOidOrThrow(nthField(bagFields, 0))).toBe(`${pkcs7Arc}.2`);

				const pfx = unwrap(await createPfx({ certificates: [{ certificate: certificate.der }] }));
				const pfxFields = readDerSequenceOrThrow(pfx.der);
				expect(decodeDerIntegerOrThrow(nthField(pfxFields, 0))).toBe(3);
				const authSafe = derChildrenOrThrow(pfx.der, nthField(pfxFields, 1));
				expect(decodeDerOidOrThrow(nthField(authSafe, 0))).toBe(`${pkcs7Arc}.1`);
			});

			it('accepts exactly one DER CRL where a ".crl" payload is expected', () => {
				// Section 5.3 "does not disturb the official application/pkix-cert
				// registration [RFC2585] in any way", and the sentence it quotes registers
				// the CRL half as well. RFC 2585 Section 2: "Likewise, the names of files
				// that contain CRLs should have a suffix of '.crl'. Each '.crl' file
				// contains exactly one CRL, encoded in DER format."
				const figure8 = example('X509 CRL');
				const figure8Der = pemDecodeOrThrow('X509 CRL', figure8);
				expect(parseCertificateRevocationListDer(figure8Der).ok).toBe(true);
				for (const der of [
					concatBytes([figure8Der, figure8Der]),
					new TextEncoder().encode(figure8),
				]) {
					const parsed = parseCertificateRevocationListDer(der);
					expect(parsed.ok).toBe(false);
					if (!parsed.ok) {
						expect(parsed.code).toBe('malformed');
					}
				}
			});

			it.todo('[X.509SG] is Peter Gutmann\'s "X.509 Style Guide", the one entry here that is neither an RFC nor vendored: Section 1 cites it for a section "base64 Encoding" that "describes the formats and contains suggestions similar to what is in this document", which is commentary on this document rather than a rule this library can be held to', () => {});
		});
	});

	describe('Appendix A. Non-conforming Examples', () => {
		it.each(['X509 CERTIFICATE', 'X.509 CERTIFICATE', 'NEW CERTIFICATE REQUEST'])(
			'splits the non-conforming %s label without malfunctioning',
			(label) => {
				expect(splitPemBlocksOrThrow(example(label)).map((block) => block.label)).toEqual([label]);
			},
		);

		it('splits the non-conforming CERTIFICATE CHAIN label without malfunctioning', () => {
			expect(splitPemBlocksOrThrow(example('CERTIFICATE CHAIN')).map((b) => b.label)).toEqual([
				'CERTIFICATE CHAIN',
			]);
		});
	});

	describe('Appendix B. DER Expectations', () => {
		/** The labels Figure 20 guides, read out of its table. */
		const derGuideLabels = (() => {
			const lines = rfc.split('\n');
			const head = lines.findIndex(
				(line) => line.includes('Sec. Label') && line.includes('Reasons'),
			);
			if (head < 0) throw new Error('rfc7468.txt has no Figure 20 table');
			const labels: string[] = [];
			for (const line of lines.slice(head + 2)) {
				const label = /^ +\d+ {2}([A-Z]\S*(?: \S+)*) {2,}[1-3*~ ]+$/.exec(line)?.[1];
				if (label === undefined) break;
				labels.push(label);
			}
			return labels;
		})();

		it.each(derGuideLabels)('reads the %s figure in definite-length form only', (label) => {
			// "DER always encodes data values in definite-length form (where the length
			// is stated at the beginning of the encoding); thus, a parser can anticipate
			// memory or resource usage up front."
			const der = pemDecodeOrThrow(label, example(label));
			const contents = readDerRootOrThrow(der).value;
			const indefinite = concatBytes([Uint8Array.of(0x30, 0x80), contents, new Uint8Array(2)]);
			expect(readDerRoot(indefinite)).toMatchObject({ ok: false, code: 'malformed' });
			expect(readDerRoot(der.slice(0, der.length - 1))).toMatchObject({
				ok: false,
				code: 'malformed',
			});
		});
	});
});
