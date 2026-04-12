import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createCertificateRevocationList,
	createCertificateSigningRequest,
	createOcspRequest,
	createOcspResponse,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificateDer,
	parseCertificateRevocationListDer,
	parseCertificateSigningRequestDer,
	parseOcspRequestDer,
	parseOcspResponseDer,
} from 'micro509';
import {
	bitString,
	explicitContext,
	implicitPrimitiveContext,
	integerFromNumber,
	octetString,
	readSequenceChildren,
	sequence,
	tlv,
} from '#micro509/internal/asn1/der.ts';
import { OIDS } from '#micro509/internal/asn1/oids.ts';
import { childrenOf, decodeObjectIdentifier, hexToBytes } from './helpers.ts';

interface CorpusCase {
	readonly name: string;
	readonly parse: () => unknown;
	readonly messagePattern?: RegExp;
}

function requireValue<T>(value: T | undefined, label: string): T {
	if (value === undefined) {
		throw new Error(`Missing ${label}`);
	}
	return value;
}

function sliceElement(
	source: Uint8Array,
	element: { readonly start: number; readonly end: number; readonly headerLength: number },
): Uint8Array {
	return source.slice(element.start - element.headerLength, element.end);
}

function replaceSequenceChild(
	sequenceDer: Uint8Array,
	childIndex: number,
	replacement: Uint8Array,
): Uint8Array {
	const children = readSequenceChildren(sequenceDer);
	if (childIndex < 0 || childIndex >= children.length) {
		throw new Error(`Sequence child index out of range: ${childIndex}`);
	}
	return sequence(
		children.map((child, index) =>
			index === childIndex ? replacement : sliceElement(sequenceDer, child),
		),
	);
}

function replaceCertificateSubjectPublicKeyInfo(
	certificateDer: Uint8Array,
	replacement: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(certificateDer);
	const tbsCertificate = requireValue(topLevel[0], 'TBSCertificate');
	const signatureAlgorithm = requireValue(topLevel[1], 'signatureAlgorithm');
	const signatureValue = requireValue(topLevel[2], 'signatureValue');
	const tbsDer = sliceElement(certificateDer, tbsCertificate);
	const tbsChildren = readSequenceChildren(tbsDer);
	const versionOffset = tbsChildren[0]?.tag === 0xa0 ? 1 : 0;
	const subjectPublicKeyInfoIndex = versionOffset + 5;
	const rebuiltTbs = replaceSequenceChild(tbsDer, subjectPublicKeyInfoIndex, replacement);
	return sequence([
		rebuiltTbs,
		sliceElement(certificateDer, signatureAlgorithm),
		sliceElement(certificateDer, signatureValue),
	]);
}

function rewriteCertificateVersionTag(certificateDer: Uint8Array, tag: number): Uint8Array {
	const topLevel = readSequenceChildren(certificateDer);
	const tbsCertificate = requireValue(topLevel[0], 'TBSCertificate');
	const signatureAlgorithm = requireValue(topLevel[1], 'signatureAlgorithm');
	const signatureValue = requireValue(topLevel[2], 'signatureValue');
	const tbsDer = sliceElement(certificateDer, tbsCertificate);
	const tbsChildren = readSequenceChildren(tbsDer);
	const versionElement = requireValue(tbsChildren[0], 'version');
	const innerVersion = requireValue(childrenOf(tbsDer, versionElement)[0], 'version INTEGER');
	const rebuiltTbs = replaceSequenceChild(
		tbsDer,
		0,
		explicitContext(0, tlv(tag, innerVersion.value)),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(certificateDer, signatureAlgorithm),
		sliceElement(certificateDer, signatureValue),
	]);
}

function rewriteCsrVersionTag(csrDer: Uint8Array, tag: number): Uint8Array {
	const topLevel = readSequenceChildren(csrDer);
	const certificationRequestInfo = requireValue(topLevel[0], 'CertificationRequestInfo');
	const signatureAlgorithm = requireValue(topLevel[1], 'signatureAlgorithm');
	const signatureValue = requireValue(topLevel[2], 'signatureValue');
	const criDer = sliceElement(csrDer, certificationRequestInfo);
	const versionElement = requireValue(readSequenceChildren(criDer)[0], 'version');
	const rebuiltCri = replaceSequenceChild(criDer, 0, tlv(tag, versionElement.value));
	return sequence([
		rebuiltCri,
		sliceElement(csrDer, signatureAlgorithm),
		sliceElement(csrDer, signatureValue),
	]);
}

function rewriteCrlVersionTag(crlDer: Uint8Array, tag: number): Uint8Array {
	const topLevel = readSequenceChildren(crlDer);
	const tbsCertList = requireValue(topLevel[0], 'TBSCertList');
	const signatureAlgorithm = requireValue(topLevel[1], 'signatureAlgorithm');
	const signatureValue = requireValue(topLevel[2], 'signatureValue');
	const tbsDer = sliceElement(crlDer, tbsCertList);
	const versionElement = requireValue(readSequenceChildren(tbsDer)[0], 'version');
	const rebuiltTbs = replaceSequenceChild(tbsDer, 0, tlv(tag, versionElement.value));
	return sequence([
		rebuiltTbs,
		sliceElement(crlDer, signatureAlgorithm),
		sliceElement(crlDer, signatureValue),
	]);
}

function rewriteOcspResponseStatusTag(ocspResponseDer: Uint8Array, tag: number): Uint8Array {
	const responseStatus = requireValue(readSequenceChildren(ocspResponseDer)[0], 'responseStatus');
	return replaceSequenceChild(ocspResponseDer, 0, tlv(tag, responseStatus.value));
}

function replaceCertificateExtensionValue(
	certificateDer: Uint8Array,
	oid: string,
	extensionValueDer: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(certificateDer);
	const tbsCertificate = requireValue(topLevel[0], 'TBSCertificate');
	const signatureAlgorithm = requireValue(topLevel[1], 'signatureAlgorithm');
	const signatureValue = requireValue(topLevel[2], 'signatureValue');
	const tbsDer = sliceElement(certificateDer, tbsCertificate);
	const tbsChildren = readSequenceChildren(tbsDer);
	const extensionIndex = tbsChildren.findIndex((child) => child.tag === 0xa3);
	if (extensionIndex === -1) {
		throw new Error('Certificate missing extensions');
	}
	const extensionsWrapper = requireValue(tbsChildren[extensionIndex], 'extensions');
	const extensionsWrapperDer = sliceElement(tbsDer, extensionsWrapper);
	const extensionSequenceElement = requireValue(
		readSequenceChildren(extensionsWrapperDer)[0],
		'extensions sequence',
	);
	const extensionSequenceDer = sliceElement(extensionsWrapperDer, extensionSequenceElement);
	const extensionEntries = readSequenceChildren(extensionSequenceDer);
	let replaced = false;
	const rebuiltEntries = extensionEntries.map((entry) => {
		const entryDer = sliceElement(extensionSequenceDer, entry);
		const parts = readSequenceChildren(entryDer);
		const oidElement = requireValue(parts[0], 'extension OID');
		const currentOid = decodeObjectIdentifier(oidElement.value);
		if (currentOid !== oid) {
			return entryDer;
		}
		replaced = true;
		const criticalElement = parts.length === 3 ? parts[1] : undefined;
		return sequence([
			sliceElement(entryDer, oidElement),
			...(criticalElement === undefined ? [] : [sliceElement(entryDer, criticalElement)]),
			octetString(extensionValueDer),
		]);
	});
	if (!replaced) {
		throw new Error(`Certificate missing extension ${oid}`);
	}
	const rebuiltExtensions = explicitContext(3, sequence(rebuiltEntries));
	const rebuiltTbs = replaceSequenceChild(tbsDer, extensionIndex, rebuiltExtensions);
	return sequence([
		rebuiltTbs,
		sliceElement(certificateDer, signatureAlgorithm),
		sliceElement(certificateDer, signatureValue),
	]);
}

function replaceFirstRevokedCertificateEntry(
	crlDer: Uint8Array,
	replacement: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(crlDer);
	const tbsCertList = requireValue(topLevel[0], 'TBSCertList');
	const signatureAlgorithm = requireValue(topLevel[1], 'signatureAlgorithm');
	const signatureValue = requireValue(topLevel[2], 'signatureValue');
	const tbsDer = sliceElement(crlDer, tbsCertList);
	const tbsChildren = readSequenceChildren(tbsDer);
	let revokedIndex = 4;
	if (tbsChildren[0]?.tag !== 0x02) {
		revokedIndex -= 1;
	}
	const maybeNextUpdate = tbsChildren[revokedIndex];
	if (
		maybeNextUpdate !== undefined &&
		(maybeNextUpdate.tag === 0x17 || maybeNextUpdate.tag === 0x18)
	) {
		revokedIndex += 1;
	}
	const revokedCertificates = requireValue(tbsChildren[revokedIndex], 'revokedCertificates');
	const revokedCertificatesDer = sliceElement(tbsDer, revokedCertificates);
	const entries = readSequenceChildren(revokedCertificatesDer);
	if (entries.length === 0) {
		throw new Error('CRL has no revoked certificate entries');
	}
	const rebuiltRevokedCertificates = sequence(
		entries.map((entry, index) =>
			index === 0 ? replacement : sliceElement(revokedCertificatesDer, entry),
		),
	);
	const rebuiltTbs = replaceSequenceChild(tbsDer, revokedIndex, rebuiltRevokedCertificates);
	return sequence([
		rebuiltTbs,
		sliceElement(crlDer, signatureAlgorithm),
		sliceElement(crlDer, signatureValue),
	]);
}

function replaceCrlExtensionValue(
	crlDer: Uint8Array,
	oid: string,
	extensionValueDer: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(crlDer);
	const tbsCertList = requireValue(topLevel[0], 'TBSCertList');
	const signatureAlgorithm = requireValue(topLevel[1], 'signatureAlgorithm');
	const signatureValue = requireValue(topLevel[2], 'signatureValue');
	const tbsDer = sliceElement(crlDer, tbsCertList);
	const tbsChildren = readSequenceChildren(tbsDer);
	const extensionIndex = tbsChildren.findIndex((child) => child.tag === 0xa0);
	if (extensionIndex === -1) {
		throw new Error('CRL missing extensions');
	}
	const extensionsWrapper = requireValue(tbsChildren[extensionIndex], 'extensions');
	const extensionsWrapperDer = sliceElement(tbsDer, extensionsWrapper);
	const extensionSequenceElement = requireValue(
		readSequenceChildren(extensionsWrapperDer)[0],
		'extensions sequence',
	);
	const extensionSequenceDer = sliceElement(extensionsWrapperDer, extensionSequenceElement);
	const extensionEntries = readSequenceChildren(extensionSequenceDer);
	let replaced = false;
	const rebuiltEntries = extensionEntries.map((entry) => {
		const entryDer = sliceElement(extensionSequenceDer, entry);
		const parts = readSequenceChildren(entryDer);
		const oidElement = requireValue(parts[0], 'extension OID');
		if (decodeObjectIdentifier(oidElement.value) !== oid) {
			return entryDer;
		}
		replaced = true;
		const criticalElement = parts.length === 3 ? parts[1] : undefined;
		return sequence([
			sliceElement(entryDer, oidElement),
			...(criticalElement === undefined ? [] : [sliceElement(entryDer, criticalElement)]),
			octetString(extensionValueDer),
		]);
	});
	if (!replaced) {
		throw new Error(`CRL missing extension ${oid}`);
	}
	const rebuiltExtensions = explicitContext(0, sequence(rebuiltEntries));
	const rebuiltTbs = replaceSequenceChild(tbsDer, extensionIndex, rebuiltExtensions);
	return sequence([
		rebuiltTbs,
		sliceElement(crlDer, signatureAlgorithm),
		sliceElement(crlDer, signatureValue),
	]);
}

function rewriteOcspSingleResponseCertStatusTag(responseDer: Uint8Array, tag: number): Uint8Array {
	const topLevel = readSequenceChildren(responseDer);
	const responseBytes = requireValue(topLevel[1], 'responseBytes');
	const responseBytesSequence = requireValue(
		childrenOf(responseDer, responseBytes)[0],
		'responseBytes sequence',
	);
	const responseBytesDer = sliceElement(responseDer, responseBytesSequence);
	const responseBytesChildren = readSequenceChildren(responseBytesDer);
	const responseType = requireValue(responseBytesChildren[0], 'responseType');
	const response = requireValue(responseBytesChildren[1], 'response');
	const basicResponseDer = response.value;
	const basicChildren = readSequenceChildren(basicResponseDer);
	const responseData = requireValue(basicChildren[0], 'responseData');
	const responseDataDer = sliceElement(basicResponseDer, responseData);
	const responseDataChildren = readSequenceChildren(responseDataDer);
	const responses = requireValue(responseDataChildren[2], 'responses');
	const responsesDer = sliceElement(responseDataDer, responses);
	const responseElements = readSequenceChildren(responsesDer);
	const firstResponse = requireValue(responseElements[0], 'SingleResponse');
	const firstResponseDer = sliceElement(responsesDer, firstResponse);
	const rebuiltFirstResponse = replaceSequenceChild(
		firstResponseDer,
		1,
		tlv(tag, Uint8Array.of(0x00)),
	);
	const rebuiltResponses = sequence([
		rebuiltFirstResponse,
		...responseElements.slice(1).map((entry) => sliceElement(responsesDer, entry)),
	]);
	const rebuiltResponseData = replaceSequenceChild(responseDataDer, 2, rebuiltResponses);
	const rebuiltBasicResponse = replaceSequenceChild(basicResponseDer, 0, rebuiltResponseData);
	const rebuiltResponseBytes = sequence([
		sliceElement(responseBytesDer, responseType),
		octetString(rebuiltBasicResponse),
	]);
	return sequence([
		sliceElement(responseDer, requireValue(topLevel[0], 'responseStatus')),
		explicitContext(0, rebuiltResponseBytes),
	]);
}

function nestedSequence(depth: number): Uint8Array {
	let current = sequence([]);
	for (let index = 0; index < depth; index += 1) {
		current = sequence([current]);
	}
	return current;
}

function expectDeterministicParseFailure(testCase: CorpusCase): void {
	let error: unknown;
	try {
		testCase.parse();
	} catch (caught) {
		error = caught;
	}
	if (!(error instanceof Error)) {
		throw new Error(`Expected parse failure for ${testCase.name}`);
	}
	expect(error).not.toBeInstanceOf(TypeError);
	expect(error).not.toBeInstanceOf(RangeError);
	expect(error).not.toBeInstanceOf(ReferenceError);
	expect(error.message.length).toBeGreaterThan(0);
	if (testCase.messagePattern !== undefined) {
		expect(error.message).toMatch(testCase.messagePattern);
	}
}

describe('malformed DER corpus', () => {
	it('rejects malformed certificate corpus deterministically', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Malformed DER CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const certificate = await createCertificate({
			issuer: { commonName: 'Malformed DER CA' },
			subject: { commonName: 'malformed-cert.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});

		const corpus: readonly CorpusCase[] = [
			{
				name: 'truncated certificate',
				parse: () => parseCertificateDer(certificate.der.slice(0, certificate.der.length - 7)),
			},
			{
				name: 'certificate with trailing DER data',
				parse: () => parseCertificateDer(Uint8Array.of(...certificate.der, 0x00)),
				messagePattern: /Trailing data/i,
			},
			{
				name: 'certificate exceeding max DER depth',
				parse: () =>
					parseCertificateDer(
						replaceCertificateSubjectPublicKeyInfo(certificate.der, nestedSequence(70)),
					),
				messagePattern: /max depth/i,
			},
			{
				name: 'certificate missing subjectPublicKeyInfo fields',
				parse: () =>
					parseCertificateDer(
						replaceCertificateSubjectPublicKeyInfo(certificate.der, sequence([])),
					),
				messagePattern: /subjectPublicKeyInfo|algorithm/i,
			},
			{
				name: 'certificate skeletal structure missing serialNumber',
				parse: () =>
					parseCertificateDer(
						sequence([sequence([]), sequence([]), bitString(Uint8Array.of(0x00))]),
					),
				messagePattern: /serialNumber/i,
			},
		];

		for (const testCase of corpus) {
			expectDeterministicParseFailure(testCase);
		}
	});

	it('rejects malformed CRL corpus deterministically', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Malformed CRL CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Malformed CRL CA' },
			subject: { commonName: 'malformed-crl.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const parsedLeaf = parseCertificateDer(leaf.der);
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Malformed CRL CA' },
			issuerPublicKey: issuer.keyPair.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			revokedCertificates: [{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) }],
		});

		const corpus: readonly CorpusCase[] = [
			{
				name: 'truncated CRL',
				parse: () => parseCertificateRevocationListDer(crl.der.slice(0, crl.der.length - 5)),
			},
			{
				name: 'CRL with trailing DER data',
				parse: () => parseCertificateRevocationListDer(Uint8Array.of(...crl.der, 0x00)),
				messagePattern: /Trailing data/i,
			},
			{
				name: 'CRL revoked entry missing revocationDate',
				parse: () =>
					parseCertificateRevocationListDer(
						replaceFirstRevokedCertificateEntry(crl.der, sequence([integerFromNumber(1)])),
					),
				messagePattern: /revocationDate/i,
			},
			{
				name: 'CRL skeletal structure missing issuer',
				parse: () =>
					parseCertificateRevocationListDer(
						sequence([
							sequence([integerFromNumber(1)]),
							sequence([]),
							bitString(Uint8Array.of(0x00)),
						]),
					),
				messagePattern: /issuer|thisUpdate/i,
			},
		];

		for (const testCase of corpus) {
			expectDeterministicParseFailure(testCase);
		}
	});

	it('rejects malformed OCSP corpus deterministically', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Malformed OCSP CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Malformed OCSP CA' },
			subject: { commonName: 'malformed-ocsp.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const request = await createOcspRequest({
			requests: [{ certificate: leaf.der, issuerCertificate: issuer.certificate.der }],
			nonce: Uint8Array.of(0xaa, 0xbb),
		});
		const response = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.der,
			responses: [
				{
					certificate: leaf.der,
					issuerCertificate: issuer.certificate.der,
					certStatus: 'good',
					thisUpdate: new Date('2024-01-01T00:00:00Z'),
				},
			],
			nonce: Uint8Array.of(0xaa, 0xbb),
		});

		const corpus: readonly CorpusCase[] = [
			{
				name: 'truncated OCSP request',
				parse: () => parseOcspRequestDer(request.der.slice(0, request.der.length - 6)),
			},
			{
				name: 'OCSP request with trailing DER data',
				parse: () => parseOcspRequestDer(Uint8Array.of(...request.der, 0x00)),
				messagePattern: /Trailing data/i,
			},
			{
				name: 'OCSP request missing requestList',
				parse: () => parseOcspRequestDer(sequence([sequence([])])),
				messagePattern: /requestList/i,
			},
			{
				name: 'truncated OCSP response',
				parse: () => parseOcspResponseDer(response.der.slice(0, response.der.length - 9)),
			},
			{
				name: 'OCSP response with trailing DER data',
				parse: () => parseOcspResponseDer(Uint8Array.of(...response.der, 0x00)),
				messagePattern: /Trailing data/i,
			},
			{
				name: 'OCSP response missing responseBytes sequence',
				parse: () =>
					parseOcspResponseDer(
						sequence([tlv(0x0a, Uint8Array.of(0x00)), explicitContext(0, sequence([]))]),
					),
				messagePattern: /response(Bytes|Type)/i,
			},
		];

		for (const testCase of corpus) {
			expectDeterministicParseFailure(testCase);
		}
	});

	it('rejects malformed policy-extension corpus deterministically', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Malformed Policy CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
				certificatePolicies: [{ policyIdentifier: '1.2.3.4.1' }],
				policyMappings: [{ issuerDomainPolicy: '1.2.3.4.1', subjectDomainPolicy: '1.2.3.4.2' }],
				policyConstraints: { requireExplicitPolicy: 1 },
				inhibitAnyPolicy: { skipCerts: 2 },
			},
		});

		const corpus: readonly CorpusCase[] = [
			{
				name: 'empty certificatePolicies sequence',
				parse: () =>
					parseCertificateDer(
						replaceCertificateExtensionValue(
							issuer.certificate.der,
							OIDS.certificatePolicies,
							sequence([]),
						),
					),
				messagePattern: /certificatePolicies|SEQUENCE/i,
			},
			{
				name: 'empty policyMappings sequence',
				parse: () =>
					parseCertificateDer(
						replaceCertificateExtensionValue(
							issuer.certificate.der,
							OIDS.policyMappings,
							sequence([]),
						),
					),
				messagePattern: /policyMappings|SEQUENCE/i,
			},
			{
				name: 'empty policyConstraints sequence',
				parse: () =>
					parseCertificateDer(
						replaceCertificateExtensionValue(
							issuer.certificate.der,
							OIDS.policyConstraints,
							sequence([]),
						),
					),
				messagePattern: /policyConstraints|SEQUENCE/i,
			},
			{
				name: 'negative policyConstraints requireExplicitPolicy',
				parse: () =>
					parseCertificateDer(
						replaceCertificateExtensionValue(
							issuer.certificate.der,
							OIDS.policyConstraints,
							sequence([implicitPrimitiveContext(0, Uint8Array.of(0xff))]),
						),
					),
				messagePattern: /policyConstraints requireExplicitPolicy|non-negative|SEQUENCE/i,
			},
			{
				name: 'non-INTEGER inhibitAnyPolicy value',
				parse: () =>
					parseCertificateDer(
						replaceCertificateExtensionValue(
							issuer.certificate.der,
							OIDS.inhibitAnyPolicy,
							sequence([]),
						),
					),
				messagePattern: /inhibitAnyPolicy|INTEGER|SEQUENCE/i,
			},
			{
				name: 'negative inhibitAnyPolicy value',
				parse: () =>
					parseCertificateDer(
						replaceCertificateExtensionValue(
							issuer.certificate.der,
							OIDS.inhibitAnyPolicy,
							tlv(0x02, Uint8Array.of(0xff)),
						),
					),
				messagePattern: /inhibitAnyPolicy skipCerts|non-negative|SEQUENCE/i,
			},
			{
				name: 'distribution point with reasons only',
				parse: () =>
					parseCertificateDer(
						replaceCertificateExtensionValue(
							issuer.certificate.der,
							OIDS.cRLDistributionPoints,
							sequence([sequence([tlv(0x81, Uint8Array.of(0x00))])]),
						),
					),
				messagePattern:
					/DistributionPoint must include distributionPoint or crlIssuer|Expected SEQUENCE/i,
			},
			{
				name: 'authority key identifier fields out of order',
				parse: () =>
					parseCertificateDer(
						replaceCertificateExtensionValue(
							issuer.certificate.der,
							OIDS.authorityKeyIdentifier,
							sequence([tlv(0x82, Uint8Array.of(0x01)), explicitContext(1, sequence([]))]),
						),
					),
				messagePattern: /authorityKeyIdentifier fields must preserve DER order|Expected SEQUENCE/i,
			},
		];

		for (const testCase of corpus) {
			expectDeterministicParseFailure(testCase);
		}
	});

	it('rejects unsupported scalar/tag substitutions with deterministic parse errors', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'Scalar Root' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const csrKeys = await generateKeyPair();
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'Scalar CSR' },
			publicKey: csrKeys.publicKey,
			signerPrivateKey: csrKeys.privateKey,
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Scalar Root' },
			signerPrivateKey: certificate.keyPair.privateKey,
			issuerPublicKey: certificate.keyPair.publicKey,
			crlNumber: 1,
		});
		const ocspResponse = await createOcspResponse({
			signerPrivateKey: certificate.keyPair.privateKey,
			signerCertificate: certificate.certificate.pem,
			responses: [
				{
					certificate: certificate.certificate.pem,
					issuerCertificate: certificate.certificate.pem,
					certStatus: 'good',
				},
			],
		});

		const corpus: readonly CorpusCase[] = [
			{
				name: 'certificate version uses BOOLEAN',
				parse: () =>
					parseCertificateDer(rewriteCertificateVersionTag(certificate.certificate.der, 0x01)),
				messagePattern: /version must use INTEGER/i,
			},
			{
				name: 'csr version uses BOOLEAN',
				parse: () => parseCertificateSigningRequestDer(rewriteCsrVersionTag(csr.der, 0x01)),
				messagePattern: /version must use INTEGER/i,
			},
			{
				name: 'crl version uses BOOLEAN',
				parse: () => parseCertificateRevocationListDer(rewriteCrlVersionTag(crl.der, 0x01)),
				messagePattern: /version must use INTEGER/i,
			},
			{
				name: 'ocsp responseStatus uses INTEGER',
				parse: () => parseOcspResponseDer(rewriteOcspResponseStatusTag(ocspResponse.der, 0x02)),
				messagePattern: /responseStatus must use ENUMERATED/i,
			},
		];

		for (const testCase of corpus) {
			expectDeterministicParseFailure(testCase);
		}
	});

	it('rejects malformed CRL/OCSP nested structures with deterministic parse errors', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Nested Malformed CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Nested Malformed CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			freshestCrlDistributionPoints: [
				{ distributionPoint: { fullName: [{ type: 'uri', value: 'http://example.test/ok.crl' }] } },
			],
		});
		const ocspResponse = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			responses: [
				{
					certificate: ca.certificate.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'good',
				},
			],
		});

		const corpus: readonly CorpusCase[] = [
			{
				name: 'freshestCRL distribution point with reasons only',
				parse: () =>
					parseCertificateRevocationListDer(
						replaceCrlExtensionValue(
							crl.der,
							OIDS.freshestCRL,
							sequence([sequence([tlv(0x81, Uint8Array.of(0x00))])]),
						),
					),
				messagePattern:
					/DistributionPoint must include distributionPoint or crlIssuer|Expected SEQUENCE/i,
			},
			{
				name: 'ocsp SingleResponse unsupported certStatus tag',
				parse: () =>
					parseOcspResponseDer(rewriteOcspSingleResponseCertStatusTag(ocspResponse.der, 0x83)),
				messagePattern: /Unsupported OCSP certStatus tag/i,
			},
		];

		for (const testCase of corpus) {
			expectDeterministicParseFailure(testCase);
		}
	});
});
