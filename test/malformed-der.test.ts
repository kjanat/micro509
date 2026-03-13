import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createCertificateRevocationList,
	createOcspRequest,
	createOcspResponse,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificateDer,
	parseCertificateRevocationListDer,
	parseOcspRequestDer,
	parseOcspResponseDer,
} from '#micro509';
import {
	bitString,
	explicitContext,
	implicitPrimitiveContext,
	integerFromNumber,
	octetString,
	readSequenceChildren,
	sequence,
	tlv,
} from '#micro509/der.ts';
import { OIDS } from '#micro509/oids.ts';
import { decodeObjectIdentifier, hexToBytes } from './helpers.ts';

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
		];

		for (const testCase of corpus) {
			expectDeterministicParseFailure(testCase);
		}
	});
});
