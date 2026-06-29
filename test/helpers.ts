import { createHash } from 'node:crypto';
import type { ParsedCertificate } from 'micro509';
import {
	createCertificate,
	createSelfSignedCertificate,
	exportPkcs8Der,
	generateKeyPair,
	importPkcs8Der,
	unwrap,
} from 'micro509';
import type { GeneralName } from 'micro509/x509';
import { encodeSubjectAltName } from 'micro509/x509';
import { toArrayBuffer } from '#micro509/internal/asn1/asn1.ts';
import {
	bitString,
	bool,
	concatBytes,
	explicitContext,
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
} from '#micro509/internal/asn1/der.ts';
import { OIDS } from '#micro509/internal/asn1/oids.ts';
import {
	encodeAlgorithmIdentifier,
	getSignatureAlgorithm,
	signBytes,
} from '#micro509/internal/crypto/signing.ts';

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
		readonly basicConstraints: {
			readonly ca: boolean;
			readonly pathLength?: number;
		};
		readonly keyUsage: readonly ('keyCertSign' | 'cRLSign' | 'digitalSignature')[];
	};
	readonly intermediateExtensions?: {
		readonly basicConstraints: {
			readonly ca: boolean;
			readonly pathLength?: number;
		};
		readonly keyUsage: readonly ('keyCertSign' | 'cRLSign' | 'digitalSignature')[];
	};
	readonly leafValidity?: {
		readonly notBefore: Date;
		readonly notAfter: Date;
	};
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
			subjectAltNames: [{ type: 'dns', value: 'verify.example' }],
		},
	} satisfies Parameters<typeof createCertificate>[0];
	const leaf = await createCertificate(leafInput);
	return { root, intermediate, intermediateKeys, leaf, leafKeys };
}
