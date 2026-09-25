import { describe, expect, it } from 'bun:test';
import {
	createCertificateRevocationList,
	createOcspRequest,
	createOcspResponse,
	createSelfSignedCertificate,
	type IssuingDistributionPoint,
	parseCertificateDer,
	parseCertificateRevocationListDer,
	parseOcspRequestDer,
	pemDecodeOrThrow,
	unwrap,
} from '#micro509';
import { toHex } from '#micro509/internal/asn1/asn1';
import {
	explicitContext,
	octetString,
	readSequenceChildren,
	sequence,
	tlv,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { encodeBasicConstraints, encodeExtension } from '#micro509/x509';
import {
	childrenOf,
	decodeObjectIdentifier,
	FAR_FUTURE_NEXT_UPDATE,
	rfcDir,
	sliceElement,
} from '#test/helpers';

const rfc5280Lines = (await Bun.file(`${rfcDir}/rfc5280.txt`).text()).split('\n');

const printed = (from: number, to: number): string =>
	rfc5280Lines
		.slice(from - 1, to)
		.join(' ')
		.replace(/\s+/g, ' ')
		.trim();

const IDP_DISTRIBUTION_POINT = {
	type: 'fullName',
	fullName: [{ type: 'uri', value: 'http://example.test/der.crl' }],
} as const;

async function crlCa() {
	return createSelfSignedCertificate({
		subject: { commonName: 'DER CRL CA' },
		extensions: {
			basicConstraints: { ca: true },
			keyUsage: ['keyCertSign', 'cRLSign'],
		},
	});
}

async function crlDerWithIdp(
	issuingDistributionPoint: IssuingDistributionPoint,
): Promise<Uint8Array> {
	const ca = await crlCa();
	const crl = await createCertificateRevocationList({
		issuer: { commonName: 'DER CRL CA' },
		signerPrivateKey: ca.keyPair.privateKey,
		issuerPublicKey: ca.keyPair.publicKey,
		issuingDistributionPoint,
		nextUpdate: FAR_FUTURE_NEXT_UPDATE,
	});
	return new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem));
}

function crlExtensionEntries(crlDer: Uint8Array): readonly Uint8Array[] {
	const tbs = sliceElement(crlDer, readSequenceChildren(crlDer)[0] ?? missing('tbsCertList'));
	const wrapper = readSequenceChildren(tbs).find((child) => child.tag === 0xa0);
	const list = childrenOf(tbs, wrapper ?? missing('crlExtensions'))[0];
	return childrenOf(tbs, list ?? missing('Extensions')).map((entry) => sliceElement(tbs, entry));
}

function extensionOid(entry: Uint8Array): string {
	return decodeObjectIdentifier((readSequenceChildren(entry)[0] ?? missing('extnID')).value);
}

function idpExtensionValue(crlDer: Uint8Array): Uint8Array {
	const entry = crlExtensionEntries(crlDer).find(
		(candidate) => extensionOid(candidate) === OIDS.issuingDistributionPoint,
	);
	const fields = readSequenceChildren(entry ?? missing('issuingDistributionPoint'));
	return (fields[fields.length - 1] ?? missing('extnValue')).value;
}

function withIdpPayload(crlDer: Uint8Array, payload: Uint8Array): Uint8Array {
	const [tbsElement, algorithm, signature] = readSequenceChildren(crlDer);
	const tbs = sliceElement(crlDer, tbsElement ?? missing('tbsCertList'));
	const rebuiltEntries = crlExtensionEntries(crlDer).map((entry) => {
		if (extensionOid(entry) !== OIDS.issuingDistributionPoint) return entry;
		const fields = readSequenceChildren(entry).map((field) => sliceElement(entry, field));
		return sequence([...fields.slice(0, -1), octetString(payload)]);
	});
	const rebuiltTbs = sequence(
		readSequenceChildren(tbs).map((child) =>
			child.tag === 0xa0 ? explicitContext(0, sequence(rebuiltEntries)) : sliceElement(tbs, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(crlDer, algorithm ?? missing('signatureAlgorithm')),
		sliceElement(crlDer, signature ?? missing('signatureValue')),
	]);
}

function missing(label: string): never {
	throw new Error(`missing ${label}`);
}

describe('X.690 11.1 (paraphrase): a DER BOOLEAN is one octet, TRUE is 0xFF and FALSE is 0x00', () => {
	it('an issuingDistributionPoint indirectCRL of 0xFF parses as true', async () => {
		const crlDer = await crlDerWithIdp({ indirectCrl: true });
		const parsed = unwrap(
			parseCertificateRevocationListDer(
				withIdpPayload(crlDer, sequence([tlv(0x84, Uint8Array.of(0xff))])),
			),
		);
		expect(parsed.issuingDistributionPoint?.indirectCrl).toBe(true);
	});

	it('an issuingDistributionPoint indirectCRL of 0x01 is malformed', async () => {
		const crlDer = await crlDerWithIdp({ indirectCrl: true });
		const result = parseCertificateRevocationListDer(
			withIdpPayload(crlDer, sequence([tlv(0x84, Uint8Array.of(0x01))])),
		);
		expect(result.ok ? 'ok' : result.code).toBe('malformed');
	});

	it('an issuingDistributionPoint onlyContainsUserCerts with empty content is malformed', async () => {
		const crlDer = await crlDerWithIdp({ indirectCrl: true });
		const result = parseCertificateRevocationListDer(
			withIdpPayload(crlDer, sequence([tlv(0x81, new Uint8Array(0))])),
		);
		expect(result.ok ? 'ok' : result.code).toBe('malformed');
	});
});

describe('RFC 5280 Appendix B L7515-7519 and X.690 11.5 (paraphrase): DER omits a component whose value equals its DEFAULT', () => {
	it('prints the Appendix B sentences this suite enforces', () => {
		expect(printed(7515, 7517)).toContain(
			'Implementers should note that the DER encoding of SET or SEQUENCE components whose value is the DEFAULT omit the component from the encoded certificate or CRL.',
		);
		expect(printed(7517, 7519)).toContain(
			'For example, a BasicConstraints extension whose cA value is FALSE would omit the cA boolean from the encoded certificate.',
		);
	});

	it('encodeExtension omits critical when it is FALSE and encodes TRUE as 01 01 ff', () => {
		const extnValue = Uint8Array.of(0x30, 0x00);
		expect(toHex(encodeExtension(OIDS.basicConstraints, extnValue))).toBe('30090603551d1304023000');
		expect(toHex(encodeExtension(OIDS.basicConstraints, extnValue, false))).toBe(
			'30090603551d1304023000',
		);
		expect(toHex(encodeExtension(OIDS.basicConstraints, extnValue, true))).toBe(
			'300c0603551d130101ff04023000',
		);
	});

	it('encodeBasicConstraints({ ca: false }) omits cA and produces 30 00', () => {
		expect(toHex(encodeBasicConstraints({ ca: false }))).toBe('3000');
		expect(toHex(encodeBasicConstraints({ ca: true }))).toBe('30030101ff');
	});

	it('an issuingDistributionPoint with every BOOLEAN false encodes only the distributionPoint', async () => {
		const withFalseFlags = idpExtensionValue(
			await crlDerWithIdp({
				distributionPoint: IDP_DISTRIBUTION_POINT,
				onlyContainsUserCerts: false,
				onlyContainsCACerts: false,
				indirectCrl: false,
				onlyContainsAttributeCerts: false,
			}),
		);
		const withoutFlags = idpExtensionValue(
			await crlDerWithIdp({ distributionPoint: IDP_DISTRIBUTION_POINT }),
		);
		expect(readSequenceChildren(withFalseFlags).map((field) => field.tag)).toEqual([0xa0]);
		expect(toHex(withFalseFlags)).toBe(toHex(withoutFlags));
	});

	it('createOcspRequest omits the TBSRequest version v1', async () => {
		const ca = await crlCa();
		const request = await createOcspRequest({
			requests: [{ certificate: ca.certificate.pem, issuerCertificate: ca.certificate.pem }],
		});
		const tbsRequest = sliceElement(
			request.der,
			readSequenceChildren(request.der)[0] ?? missing('tbsRequest'),
		);
		expect(readSequenceChildren(tbsRequest).map((field) => field.tag)).toEqual([0x30]);
	});

	it('createOcspResponse omits the ResponseData version v1', async () => {
		const ca = await crlCa();
		const response = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			responses: [
				{
					certificate: ca.certificate.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'good',
					thisUpdate: new Date('2025-01-01T00:00:00Z'),
				},
			],
		});
		const responseBytes = readSequenceChildren(response.der)[1] ?? missing('responseBytes');
		const responseBytesSequence =
			childrenOf(response.der, responseBytes)[0] ?? missing('ResponseBytes');
		const basicResponse = (
			childrenOf(response.der, responseBytesSequence)[1] ?? missing('response')
		).value;
		const responseData = sliceElement(
			basicResponse,
			readSequenceChildren(basicResponse)[0] ?? missing('tbsResponseData'),
		);
		expect(readSequenceChildren(responseData).map((field) => field.tag)).toEqual([
			0xa2, 0x18, 0x30,
		]);
	});
});

describe('X.509 §7.2.1 NOTE 2 (paraphrase): accepting non-DER input is local policy, so parsers tolerate an explicit DEFAULT version', () => {
	it('parseCertificateDer accepts an explicit [0] version v1', async () => {
		const ca = await crlCa();
		const [tbsElement, algorithm, signature] = readSequenceChildren(ca.certificate.der);
		const tbs = sliceElement(ca.certificate.der, tbsElement ?? missing('tbsCertificate'));
		const v1Fields = readSequenceChildren(tbs)
			.filter((field) => field.tag !== 0xa3)
			.map((field) =>
				field.tag === 0xa0
					? explicitContext(0, tlv(0x02, Uint8Array.of(0x00)))
					: sliceElement(tbs, field),
			);
		const certificate = sequence([
			sequence(v1Fields),
			sliceElement(ca.certificate.der, algorithm ?? missing('signatureAlgorithm')),
			sliceElement(ca.certificate.der, signature ?? missing('signatureValue')),
		]);
		expect(toHex(v1Fields[0] ?? missing('version'))).toBe('a003020100');
		const parsed = parseCertificateDer(certificate);
		expect(parsed.ok ? parsed.value.version : parsed.code).toBe(1);
	});

	it('parseOcspRequestDer accepts an explicit [0] version v1', async () => {
		const ca = await crlCa();
		const request = await createOcspRequest({
			requests: [{ certificate: ca.certificate.pem, issuerCertificate: ca.certificate.pem }],
		});
		const tbsRequest = sliceElement(
			request.der,
			readSequenceChildren(request.der)[0] ?? missing('tbsRequest'),
		);
		const withVersion = sequence([
			sequence([
				explicitContext(0, tlv(0x02, Uint8Array.of(0x00))),
				...readSequenceChildren(tbsRequest).map((field) => sliceElement(tbsRequest, field)),
			]),
		]);
		const parsed = parseOcspRequestDer(withVersion);
		expect(parsed.ok ? parsed.value.requests.length : parsed.code).toBe(1);
	});
});
