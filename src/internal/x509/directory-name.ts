import { childrenOf, decodeObjectIdentifier, requireElement } from '#micro509/internal/asn1/asn1';
import type { DerElement } from '#micro509/internal/asn1/der';
import { DEFAULT_MAX_DER_DEPTH, readRootElement } from '#micro509/internal/asn1/der';

/** Read and validate the explicit X.501 Name carried by directoryName [4]. */
export function readDirectoryNameTlv(element: DerElement): Uint8Array {
	const nameDer = new Uint8Array(element.value);
	const name = requireElement(
		readRootElement(nameDer, { maxDepth: DEFAULT_MAX_DER_DEPTH }),
		'directoryName Name',
	);
	if (name.tag !== 0x30) {
		throw new Error('directoryName must wrap a Name SEQUENCE');
	}
	for (const rdn of childrenOf(nameDer, name)) {
		if (rdn.tag !== 0x31) {
			throw new Error('directoryName RDN must use SET');
		}
		const attributes = childrenOf(nameDer, rdn);
		if (attributes.length === 0) {
			throw new Error('directoryName RDN must not be empty');
		}
		for (const attribute of attributes) {
			if (attribute.tag !== 0x30) {
				throw new Error('directoryName attribute must use SEQUENCE');
			}
			const parts = childrenOf(nameDer, attribute);
			const type = parts[0];
			if (parts.length !== 2 || type === undefined || type.tag !== 0x06) {
				throw new Error('directoryName attribute must contain an OID and value');
			}
			decodeObjectIdentifier(type.value);
		}
	}
	return nameDer;
}
