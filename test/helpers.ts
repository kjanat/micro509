import { createHash } from 'node:crypto';
import {
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
	type parseCertificatePem,
} from '#micro509';
import {
	concatBytes,
	explicitContext,
	integer,
	integerFromNumber,
	nullValue,
	objectIdentifier,
	octetString,
	readElement,
	sequence,
	setOf,
	tlv,
} from '#micro509/der.ts';
import { OIDS } from '#micro509/oids.ts';
import { getSignatureAlgorithm, signBytes } from '#micro509/signing.ts';

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

export function createSyntheticPkcs7SignedData(
	signer: ReturnType<typeof parseCertificatePem>,
): Uint8Array {
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
	signer: ReturnType<typeof parseCertificatePem>,
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
