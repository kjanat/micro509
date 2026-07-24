import { createHash } from 'node:crypto';
import path from 'node:path';
import { toArrayBuffer } from '#micro509/internal/asn1/asn1';
import {
	bitString,
	bool,
	concatBytes,
	explicitContext,
	implicitConstructedContext,
	integer,
	integerFromNumber,
	nullValue,
	objectIdentifier,
	octetString,
	readElement,
	readSequenceChildren,
	sequence,
	setOf,
	tlv,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import {
	encodeAlgorithmIdentifier,
	getSignatureAlgorithm,
	signBytes,
} from '#micro509/internal/crypto/signing';
import { exportPkcs8Der, generateKeyPair, importPkcs8Der } from '#micro509/keys';
import { unwrap } from '#micro509/result';
import type {
	BasicConstraints,
	CertificateMaterial,
	CsrMaterial,
	GeneralName,
	ParsedCertificate,
	SelfSignedCertificateResult,
} from '#micro509/x509';
import {
	createCertificate,
	createCertificateSigningRequest,
	createSelfSignedCertificate,
	encodeSubjectAltName,
} from '#micro509/x509';
import { probeOpenSsl } from '#test/oracles/openssl';

/**
 * Encode a CRLDistributionPoints value with an arbitrary cRLIssuer, bypassing the
 * builder's RFC 5280 §4.2.1.13 directoryName validation. Feeds the parser and
 * revocation scanner the non-conformant inputs the conformant builder refuses to emit.
 */
export function encodeUncheckedCrlDistributionPoints(
	points: readonly {
		readonly fullNameUri?: string;
		readonly crlIssuer?: readonly GeneralName[];
	}[],
): Uint8Array {
	return sequence(
		points.map((point) => {
			const fields: Uint8Array[] = [];
			if (point.fullNameUri !== undefined) {
				fields.push(
					implicitConstructedContext(
						0,
						implicitConstructedContext(
							0,
							encodeSubjectAltName({ type: 'uri', value: point.fullNameUri }),
						),
					),
				);
			}
			if (point.crlIssuer !== undefined) {
				fields.push(
					implicitConstructedContext(2, concatBytes(point.crlIssuer.map(encodeSubjectAltName))),
				);
			}
			return sequence(fields);
		}),
	);
}

export function childrenOf(
	source: Uint8Array,
	parent: { readonly start: number; readonly end: number },
): ReturnType<typeof readElement>[] {
	const children: ReturnType<typeof readElement>[] = [];
	let offset = parent.start;
	while (offset < parent.end) {
		const child = readElement(source, offset);
		children.push(child);
		offset = child.end;
	}
	return children;
}

export function decodeObjectIdentifier(bytes: Uint8Array): string {
	const first = bytes[0];
	if (first === undefined) {
		throw new Error('OID is empty');
	}
	const values = [Math.floor(first / 40), first % 40];
	let current = 0;
	for (let index = 1; index < bytes.length; index += 1) {
		const next = bytes[index];
		if (next === undefined) {
			throw new Error('Malformed OID');
		}
		current = (current << 7) | (next & 0x7f);
		if ((next & 0x80) === 0) {
			values.push(current);
			current = 0;
		}
	}
	return values.join('.');
}

export function hexToBytes(value: string): Uint8Array {
	const normalized = value.length % 2 === 0 ? value : `0${value}`;
	const bytes: number[] = [];
	for (let index = 0; index < normalized.length; index += 2) {
		bytes.push(Number.parseInt(normalized.slice(index, index + 2), 16));
	}
	return Uint8Array.from(bytes);
}

export function hasExtensionOid(certificateDer: Uint8Array, oid: string): boolean {
	const top = childrenOf(certificateDer, readElement(certificateDer));
	const tbsCertificate = top[0];
	if (tbsCertificate === undefined) {
		throw new Error('Missing TBSCertificate');
	}
	const tbsChildren = childrenOf(certificateDer, tbsCertificate);
	const extensions = tbsChildren.find((child) => child.tag === 0xa3);
	if (extensions === undefined) {
		return false;
	}
	const extensionSequence = childrenOf(certificateDer, extensions)[0];
	if (extensionSequence === undefined) {
		return false;
	}
	for (const extension of childrenOf(certificateDer, extensionSequence)) {
		const oidElement = childrenOf(certificateDer, extension)[0];
		if (oidElement !== undefined && decodeObjectIdentifier(oidElement.value) === oid) {
			return true;
		}
	}
	return false;
}

export interface RevokedEntryCertificateIssuerOverride {
	readonly entryIndex: number;
	readonly names: readonly GeneralName[];
}

export function sliceElement(
	source: Uint8Array,
	element: { readonly start: number; readonly end: number; readonly headerLength: number },
): Uint8Array {
	return source.slice(element.start - element.headerLength, element.end);
}

export async function importRsaPrivateKeyWithScheme(
	privateKey: CryptoKey,
	hash: 'SHA-256' | 'SHA-384' | 'SHA-512',
	scheme: 'pkcs1-v1_5' | 'pss',
): Promise<CryptoKey> {
	return unwrap(
		await importPkcs8Der(await exportPkcs8Der(privateKey), { kind: 'rsa', hash, scheme }),
	);
}

export async function rewriteCertificateSignatureAsRsaPss(
	certificateDer: Uint8Array,
	signerPrivateKey: CryptoKey,
	parameters: TestRsaPssParameters,
): Promise<Uint8Array> {
	const topLevel = readSequenceChildren(certificateDer);
	const tbsCertificate = topLevel[0];
	if (tbsCertificate === undefined) {
		throw new Error('Missing TBSCertificate');
	}
	const tbsDer = sliceElement(certificateDer, tbsCertificate);
	const tbsChildren = readSequenceChildren(tbsDer);
	const signatureIndex = tbsChildren[0]?.tag === 0xa0 ? 2 : 1;
	const signatureAlgorithm = encodeRsaPssAlgorithmIdentifier(parameters);
	const rebuiltTbs = sequence(
		tbsChildren.map((child, childIndex) =>
			childIndex === signatureIndex ? signatureAlgorithm : sliceElement(tbsDer, child),
		),
	);
	const signature = new Uint8Array(
		await globalThis.crypto.subtle.sign(
			{ name: 'RSA-PSS', saltLength: parameters.saltLength },
			signerPrivateKey,
			toArrayBuffer(rebuiltTbs),
		),
	);
	return sequence([rebuiltTbs, signatureAlgorithm, bitString(signature)]);
}

export async function rewriteCsrSignatureAsRsaPss(
	csrDer: Uint8Array,
	signerPrivateKey: CryptoKey,
	parameters: TestRsaPssParameters,
): Promise<Uint8Array> {
	const topLevel = readSequenceChildren(csrDer);
	const certificationRequestInfo = topLevel[0];
	if (certificationRequestInfo === undefined) {
		throw new Error('Missing CertificationRequestInfo');
	}
	const certificationRequestInfoDer = sliceElement(csrDer, certificationRequestInfo);
	const signatureAlgorithm = encodeRsaPssAlgorithmIdentifier(parameters);
	const signature = new Uint8Array(
		await globalThis.crypto.subtle.sign(
			{ name: 'RSA-PSS', saltLength: parameters.saltLength },
			signerPrivateKey,
			toArrayBuffer(certificationRequestInfoDer),
		),
	);
	return sequence([certificationRequestInfoDer, signatureAlgorithm, bitString(signature)]);
}

export function replaceCertificateSignatureAlgorithm(
	certificateDer: Uint8Array,
	signatureAlgorithmDer: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(certificateDer);
	const tbsCertificate = topLevel[0];
	const signatureValue = topLevel[2];
	if (tbsCertificate === undefined || signatureValue === undefined) {
		throw new Error('Malformed Certificate');
	}
	return sequence([
		sliceElement(certificateDer, tbsCertificate),
		signatureAlgorithmDer,
		sliceElement(certificateDer, signatureValue),
	]);
}

export function replaceCsrSignatureAlgorithm(
	csrDer: Uint8Array,
	signatureAlgorithmDer: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(csrDer);
	const certificationRequestInfo = topLevel[0];
	const signatureValue = topLevel[2];
	if (certificationRequestInfo === undefined || signatureValue === undefined) {
		throw new Error('Malformed CertificationRequest');
	}
	return sequence([
		sliceElement(csrDer, certificationRequestInfo),
		signatureAlgorithmDer,
		sliceElement(csrDer, signatureValue),
	]);
}

export interface TestRsaPssParameters {
	readonly hash: 'SHA-256' | 'SHA-384' | 'SHA-512';
	readonly mgfHash: 'SHA-256' | 'SHA-384' | 'SHA-512';
	readonly saltLength: number;
	readonly trailerField: number;
}

function encodeRsaPssAlgorithmIdentifier(parameters: TestRsaPssParameters): Uint8Array {
	const hashOid = hashNameToOid(parameters.hash);
	const mgfHashOid = hashNameToOid(parameters.mgfHash);
	return sequence([
		objectIdentifier(OIDS.rsassaPss),
		sequence([
			explicitContext(0, sequence([objectIdentifier(hashOid), nullValue()])),
			explicitContext(
				1,
				sequence([
					objectIdentifier(OIDS.mgf1),
					sequence([objectIdentifier(mgfHashOid), nullValue()]),
				]),
			),
			explicitContext(2, integerFromNumber(parameters.saltLength)),
			explicitContext(3, integerFromNumber(parameters.trailerField)),
		]),
	]);
}

function hashNameToOid(hash: TestRsaPssParameters['hash']): string {
	switch (hash) {
		case 'SHA-256':
			return OIDS.sha256;
		case 'SHA-384':
			return OIDS.sha384;
		case 'SHA-512':
			return OIDS.sha512;
	}
}

function encodeExtension(oid: string, value: Uint8Array, critical = false): Uint8Array {
	return sequence([objectIdentifier(oid), ...(critical ? [bool(true)] : []), octetString(value)]);
}

export async function addRevokedEntryCertificateIssuers(
	crlDer: Uint8Array,
	signerPrivateKey: CryptoKey,
	overrides: readonly RevokedEntryCertificateIssuerOverride[],
): Promise<Uint8Array> {
	const top = readSequenceChildren(crlDer);
	const tbsCertList = top[0];
	if (tbsCertList === undefined) {
		throw new Error('CRL missing TBSCertList');
	}
	const tbsDer = sliceElement(crlDer, tbsCertList);
	const tbsChildren = readSequenceChildren(tbsDer);
	let cursor = 3;
	if (tbsChildren[0]?.tag === 0x02) {
		cursor += 1;
	}
	const maybeNextUpdate = tbsChildren[cursor];
	if (
		maybeNextUpdate !== undefined &&
		(maybeNextUpdate.tag === 0x17 || maybeNextUpdate.tag === 0x18)
	) {
		cursor += 1;
	}
	const revokedCertificates = tbsChildren[cursor];
	if (revokedCertificates === undefined || revokedCertificates.tag !== 0x30) {
		throw new Error('CRL missing revokedCertificates sequence');
	}
	const rebuiltEntries = childrenOf(tbsDer, revokedCertificates).map((entry, entryIndex) => {
		const entryDer = sliceElement(tbsDer, entry);
		const entryChildren = readSequenceChildren(entryDer);
		const serialNumber = entryChildren[0];
		const revocationDate = entryChildren[1];
		if (serialNumber === undefined || revocationDate === undefined) {
			throw new Error('Revoked certificate entry is incomplete');
		}
		const override = overrides.find((candidate) => candidate.entryIndex === entryIndex);
		if (override === undefined) {
			return entryDer;
		}
		const existingExtensions = entryChildren[2];
		const encodedExtensions =
			existingExtensions === undefined
				? []
				: childrenOf(tbsDer, existingExtensions).map((extension) =>
						sliceElement(entryDer, extension),
					);
		const certificateIssuerExtension = encodeExtension(
			OIDS.certificateIssuer,
			sequence(override.names.map((name) => encodeSubjectAltName(name))),
			true,
		);
		return sequence([
			sliceElement(entryDer, serialNumber),
			sliceElement(entryDer, revocationDate),
			sequence([...encodedExtensions, certificateIssuerExtension]),
		]);
	});
	const rebuiltTbsChildren = tbsChildren.map((child, childIndex) =>
		childIndex === cursor ? sequence(rebuiltEntries) : sliceElement(tbsDer, child),
	);
	const rebuiltTbsDer = sequence(rebuiltTbsChildren);
	const signatureAlgorithm = getSignatureAlgorithm(signerPrivateKey);
	const signatureValue = await signBytes(signerPrivateKey, signatureAlgorithm, rebuiltTbsDer);
	return sequence([
		rebuiltTbsDer,
		encodeAlgorithmIdentifier(signatureAlgorithm),
		bitString(signatureValue),
	]);
}

/**
 * Drop-in {@link createSelfSignedCertificate} that splices `customExtensions`
 * into the signed TBSCertificate instead of routing them through the builder.
 *
 * The builder refuses to emit a known OID whose value is not that extension's
 * DER, so parser-strictness fixtures need a path that bypasses that check while
 * still producing a properly signed certificate. Takes and returns the same
 * shapes as the real function.
 */
export async function createSelfSignedCertificateWithRawExtensions(
	input: Parameters<typeof createSelfSignedCertificate>[0],
): Promise<SelfSignedCertificateResult> {
	const { customExtensions, ...builderExtensions } = input.extensions ?? {};
	const issued = await createSelfSignedCertificate({
		...input,
		extensions: builderExtensions,
	});
	if (customExtensions === undefined || customExtensions.length === 0) {
		return issued;
	}
	const der = await appendCertificateExtensions(
		issued.certificate.der,
		issued.keyPair.privateKey,
		customExtensions.map((extension) =>
			encodeExtension(extension.oid, new Uint8Array(extension.value), extension.critical ?? false),
		),
	);
	const base64 = Buffer.from(der).toString('base64');
	return {
		certificate: { der, base64, pem: toPemBlock('CERTIFICATE', der) },
		keyPair: issued.keyPair,
	};
}

/** Append encoded extensions to a certificate's TBS extensions and re-sign it. */
export async function appendCertificateExtensions(
	certificateDer: Uint8Array,
	signerPrivateKey: CryptoKey,
	extensionDers: readonly Uint8Array[],
): Promise<Uint8Array> {
	const top = readSequenceChildren(certificateDer);
	const tbsCertificate = top[0];
	if (tbsCertificate === undefined) {
		throw new Error('Missing TBSCertificate');
	}
	const tbsDer = sliceElement(certificateDer, tbsCertificate);
	const tbsChildren = readSequenceChildren(tbsDer);
	const extensionsIndex = tbsChildren.findIndex((child) => child.tag === 0xa3);
	if (extensionsIndex === -1) {
		throw new Error('TBSCertificate has no extensions');
	}
	const extensionsElement = tbsChildren[extensionsIndex];
	if (extensionsElement === undefined) {
		throw new Error('TBSCertificate has no extensions');
	}
	const extensionsSequence = childrenOf(tbsDer, extensionsElement)[0];
	if (extensionsSequence === undefined) {
		throw new Error('Extensions [3] is empty');
	}
	const existing = childrenOf(tbsDer, extensionsSequence).map((extension) =>
		sliceElement(tbsDer, extension),
	);
	const rebuiltTbsDer = sequence(
		tbsChildren.map((child, childIndex) =>
			childIndex === extensionsIndex
				? explicitContext(3, sequence([...existing, ...extensionDers]))
				: sliceElement(tbsDer, child),
		),
	);
	const signatureAlgorithm = getSignatureAlgorithm(signerPrivateKey);
	const signatureValue = await signBytes(signerPrivateKey, signatureAlgorithm, rebuiltTbsDer);
	return sequence([
		rebuiltTbsDer,
		encodeAlgorithmIdentifier(signatureAlgorithm),
		bitString(signatureValue),
	]);
}

/**
 * Drop-in {@link createCertificate} that splices `customExtensions` into the
 * signed TBSCertificate instead of routing them through the builder.
 */
export async function createCertificateWithRawExtensions(
	input: Parameters<typeof createCertificate>[0],
): Promise<CertificateMaterial> {
	const { customExtensions, ...builderExtensions } = input.extensions ?? {};
	const issued = await createCertificate({ ...input, extensions: builderExtensions });
	if (customExtensions === undefined || customExtensions.length === 0) {
		return issued;
	}
	const der = await appendCertificateExtensions(
		issued.der,
		input.signerPrivateKey,
		customExtensions.map((extension) =>
			encodeExtension(extension.oid, new Uint8Array(extension.value), extension.critical ?? false),
		),
	);
	return { der, base64: base64Of(der), pem: toPemBlock('CERTIFICATE', der) };
}

/**
 * Drop-in {@link createCertificateSigningRequest} that splices `customExtensions`
 * into the signed extensionRequest attribute instead of routing them through the
 * builder. The CSR counterpart of
 * {@link createSelfSignedCertificateWithRawExtensions}.
 */
export async function createCsrWithRawExtensions(
	input: Parameters<typeof createCertificateSigningRequest>[0],
): Promise<CsrMaterial> {
	const { customExtensions, ...builderExtensions } = input.extensions ?? {};
	const csr = await createCertificateSigningRequest({ ...input, extensions: builderExtensions });
	if (customExtensions === undefined || customExtensions.length === 0) {
		return csr;
	}
	const encoded = customExtensions.map((extension) =>
		encodeExtension(extension.oid, new Uint8Array(extension.value), extension.critical ?? false),
	);
	const criElement = readSequenceChildren(csr.der)[0];
	if (criElement === undefined) {
		throw new Error('Missing CertificationRequestInfo');
	}
	const criDer = sliceElement(csr.der, criElement);
	const criChildren = readSequenceChildren(criDer);
	const attributesElement = criChildren[3];
	if (attributesElement === undefined || attributesElement.tag !== 0xa0) {
		throw new Error('CertificationRequestInfo has no attributes');
	}
	const rebuiltCriDer = sequence([
		...criChildren.slice(0, 3).map((child) => sliceElement(criDer, child)),
		implicitConstructedContext(
			0,
			concatBytes(withExtensionRequest(criDer, attributesElement, encoded)),
		),
	]);
	const signatureAlgorithm = getSignatureAlgorithm(input.signerPrivateKey);
	const signature = await signBytes(input.signerPrivateKey, signatureAlgorithm, rebuiltCriDer);
	const der = sequence([
		rebuiltCriDer,
		encodeAlgorithmIdentifier(signatureAlgorithm),
		bitString(signature),
	]);
	return { der, pem: toPemBlock('CERTIFICATE REQUEST', der), base64: base64Of(der) };
}

/** Append extensions to the extensionRequest attribute, creating it when absent. */
function withExtensionRequest(
	criDer: Uint8Array,
	attributesElement: { readonly start: number; readonly end: number },
	extensionDers: readonly Uint8Array[],
): Uint8Array[] {
	const attributes = childrenOf(criDer, attributesElement);
	const rebuilt: Uint8Array[] = [];
	let appended = false;
	for (const attribute of attributes) {
		const attributeDer = sliceElement(criDer, attribute);
		const attributeChildren = readSequenceChildren(attributeDer);
		const typeElement = attributeChildren[0];
		const valuesElement = attributeChildren[1];
		if (
			typeElement === undefined ||
			valuesElement === undefined ||
			decodeObjectIdentifier(typeElement.value) !== OIDS.extensionRequest
		) {
			rebuilt.push(attributeDer);
			continue;
		}
		const existingSequence = childrenOf(attributeDer, valuesElement)[0];
		const existing =
			existingSequence === undefined
				? []
				: childrenOf(attributeDer, existingSequence).map((extension) =>
						sliceElement(attributeDer, extension),
					);
		rebuilt.push(
			sequence([
				objectIdentifier(OIDS.extensionRequest),
				setOf([sequence([...existing, ...extensionDers])]),
			]),
		);
		appended = true;
	}
	if (!appended) {
		rebuilt.push(
			sequence([objectIdentifier(OIDS.extensionRequest), setOf([sequence([...extensionDers])])]),
		);
	}
	return rebuilt;
}

/** Standard base64 of DER, matching the `base64` field the builders return. */
function base64Of(der: Uint8Array): string {
	return Buffer.from(der).toString('base64');
}

/** Wrap DER in a PEM block with 64-character base64 lines. */
function toPemBlock(label: string, der: Uint8Array): string {
	const base64 = Buffer.from(der).toString('base64');
	const lines = base64.match(/.{1,64}/g) ?? [];
	return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

export function createSyntheticPkcs7SignedData(signer: ParsedCertificate): Uint8Array {
	const signerInfo = sequence([
		integerFromNumber(1),
		sequence([hexToBytes(signer.issuer.derHex), integer(hexToBytes(signer.serialNumberHex))]),
		sequence([objectIdentifier(OIDS.sha256), nullValue()]),
		sequence([objectIdentifier(OIDS.sha256WithRSAEncryption), nullValue()]),
		octetString(Uint8Array.of(0x01, 0x02, 0x03)),
	]);
	const signedData = sequence([
		integerFromNumber(1),
		setOf([sequence([objectIdentifier(OIDS.sha256), nullValue()])]),
		sequence([objectIdentifier(OIDS.pkcs7Data)]),
		explicitContext(0, signer.der),
		setOf([signerInfo]),
	]);
	return sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
}

export async function createCmsSignedDataWithSignedAttrs(
	signer: ParsedCertificate,
	privateKey: CryptoKey,
	content: Uint8Array,
): Promise<Uint8Array> {
	// Compute message digest of content (SHA-256)
	const contentDigest = createHash('sha256').update(content).digest();
	// Build signedAttrs as SET OF (tag 0x31) for signing
	const signedAttrsContent = concatBytes([
		// contentType attribute
		sequence([objectIdentifier(OIDS.cmsContentType), setOf([objectIdentifier(OIDS.pkcs7Data)])]),
		// messageDigest attribute
		sequence([
			objectIdentifier(OIDS.cmsMessageDigest),
			setOf([octetString(new Uint8Array(contentDigest))]),
		]),
	]);
	// For signing: SET OF (0x31) tag
	const signedAttrsForSigning = tlv(0x31, signedAttrsContent);
	// For encoding in SignerInfo: IMPLICIT [0] (0xa0) tag
	const signedAttrsImplicit = tlv(0xa0, signedAttrsContent);
	// Sign the SET OF-tagged signedAttrs
	const sigAlgorithm = getSignatureAlgorithm(privateKey);
	const signature = await signBytes(privateKey, sigAlgorithm, signedAttrsForSigning);
	// Build SignerInfo
	const signerInfo = sequence([
		integerFromNumber(1),
		// IssuerAndSerialNumber
		sequence([hexToBytes(signer.issuer.derHex), integer(hexToBytes(signer.serialNumberHex))]),
		// digestAlgorithm
		sequence([objectIdentifier(OIDS.sha256), nullValue()]),
		// signedAttrs [0] IMPLICIT
		signedAttrsImplicit,
		// signatureAlgorithm
		sequence([
			objectIdentifier(sigAlgorithm.algorithmOid),
			...(sigAlgorithm.parameters !== undefined ? [sigAlgorithm.parameters] : []),
		]),
		// signature
		octetString(signature),
	]);
	// Build SignedData
	const signedData = sequence([
		integerFromNumber(1),
		setOf([sequence([objectIdentifier(OIDS.sha256), nullValue()])]),
		// EncapsulatedContentInfo with actual content
		sequence([objectIdentifier(OIDS.pkcs7Data), explicitContext(0, octetString(content))]),
		// certificates [0] IMPLICIT
		explicitContext(0, signer.der),
		// signerInfos
		setOf([signerInfo]),
	]);
	return sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
}

export interface IssueChainOptions {
	readonly rootExtensions?: {
		readonly basicConstraints: BasicConstraints;
		readonly keyUsage: readonly ('keyCertSign' | 'cRLSign' | 'digitalSignature')[];
	};
	readonly intermediateExtensions?: {
		readonly basicConstraints: BasicConstraints;
		readonly keyUsage: readonly ('keyCertSign' | 'cRLSign' | 'digitalSignature')[];
	};
	readonly leafValidity?: {
		readonly notBefore: Date;
		readonly notAfter: Date;
	};
	readonly leafSubjectAltNames?: readonly {
		readonly type: 'dns' | 'ip' | 'uri' | 'srv';
		readonly value: string;
	}[];
	readonly leafIssuerPublicKey?: CryptoKey;
	readonly leafSignerPrivateKey?: CryptoKey;
}

export async function issueChain(options: IssueChainOptions = {}) {
	const root = await createSelfSignedCertificate({
		subject: { commonName: 'Verify Root CA' },
		extensions: options.rootExtensions ?? {
			basicConstraints: { ca: true, pathLength: 1 },
			keyUsage: ['keyCertSign', 'cRLSign'],
		},
	});
	const intermediateKeys = await generateKeyPair();
	const intermediate = await createCertificate({
		issuer: { commonName: 'Verify Root CA' },
		subject: { commonName: 'Verify Intermediate CA' },
		publicKey: intermediateKeys.publicKey,
		signerPrivateKey: root.keyPair.privateKey,
		issuerPublicKey: root.keyPair.publicKey,
		extensions: options.intermediateExtensions ?? {
			basicConstraints: { ca: true, pathLength: 0 },
			keyUsage: ['keyCertSign', 'cRLSign'],
		},
	});
	const leafKeys = await generateKeyPair();
	const leafInput = {
		issuer: { commonName: 'Verify Intermediate CA' },
		subject: { commonName: 'verify.example' },
		publicKey: leafKeys.publicKey,
		signerPrivateKey: options.leafSignerPrivateKey ?? intermediateKeys.privateKey,
		issuerPublicKey: options.leafIssuerPublicKey ?? intermediateKeys.publicKey,
		...(options.leafValidity !== undefined ? { validity: options.leafValidity } : {}),
		extensions: {
			keyUsage: ['digitalSignature'],
			extendedKeyUsage: ['serverAuth'],
			subjectAltNames: options.leafSubjectAltNames ?? [{ type: 'dns', value: 'verify.example' }],
		},
	} satisfies Parameters<typeof createCertificate>[0];
	const leaf = await createCertificate(leafInput);
	return { root, intermediate, intermediateKeys, leaf, leafKeys };
}

const projectRoot = path.resolve(import.meta.dir, '..');
const srcRoot = path.join(projectRoot, 'src');
const testRoot = import.meta.dir;
const fixturesDir = path.join(testRoot, 'fixtures');

export { fixturesDir, projectRoot, srcRoot, testRoot };

export const isCi = Bun.env.CI !== undefined;

const openSslAvailable = await probeOpenSsl();
const differentialEnabled = isCi ? Bun.env.DIFFERENTIAL_OPENSSL === '1' : true;

export { differentialEnabled, openSslAvailable };
