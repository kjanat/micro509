import type { SignatureVerifierInput, SignatureVerifiers } from '#micro509/crypto';
import {
	bitString,
	explicitContext,
	objectIdentifier,
	octetString,
	readSequenceChildren,
	sequence,
} from '#micro509/internal/asn1/der';
import { sliceElement } from '#test/helpers';

/**
 * A test-only signature algorithm whose value depends on the key parameters the
 * verifier receives, so a wrong `signerPublicKeyParametersDer` fails it. Its
 * value is SHA-256(key || parameters || data); the key is not secret.
 */
export const PARAMETER_SIGNATURE_OID = '2.25.211206380236931305722766446009052392027';

const ALGORITHM = sequence([objectIdentifier(PARAMETER_SIGNATURE_OID)]);

/** A key of the parameter signature algorithm, its domain parameters, and whether its SPKI carries them. */
export interface ParameterKey {
	readonly key: Uint8Array;
	readonly parametersDer: Uint8Array;
	readonly carriesParameters: boolean;
}

export function parameterKey(domain: string, carriesParameters: boolean): ParameterKey {
	return {
		key: crypto.getRandomValues(new Uint8Array(32)),
		parametersDer: octetString(new TextEncoder().encode(domain)),
		carriesParameters,
	};
}

function spki(key: ParameterKey): Uint8Array {
	return sequence([
		sequence([
			objectIdentifier(PARAMETER_SIGNATURE_OID),
			...(key.carriesParameters ? [key.parametersDer] : []),
		]),
		bitString(key.key),
	]);
}

async function sign(
	key: Uint8Array,
	parametersDer: Uint8Array,
	data: Uint8Array,
): Promise<Uint8Array> {
	return new Uint8Array(
		await crypto.subtle.digest('SHA-256', Uint8Array.of(...key, ...parametersDer, ...data)),
	);
}

async function verify(input: SignatureVerifierInput): Promise<boolean> {
	const parametersDer = input.signerPublicKeyParametersDer;
	if (
		input.signatureAlgorithm.parametersDer !== undefined ||
		input.signatureUnusedBits !== 0 ||
		parametersDer === undefined
	) {
		return false;
	}
	const subjectPublicKey = readSequenceChildren(input.signerSpkiDer)[1];
	if (subjectPublicKey?.tag !== 0x03) return false;
	const expected = await sign(subjectPublicKey.value.subarray(1), parametersDer, input.data);
	return (
		input.signature.length === expected.length &&
		input.signature.every((byte, index) => byte === expected[index])
	);
}

export const parameterSignatureVerifiers: SignatureVerifiers = {
	[PARAMETER_SIGNATURE_OID]: verify,
};

/**
 * `certificateDer` with `subject` as its key, signed by `issuer` under the
 * parameter signature algorithm. Names, validity and extensions stay as built.
 */
export async function rekeyedCertificate(
	certificateDer: Uint8Array,
	subject: ParameterKey,
	issuer: ParameterKey,
): Promise<Uint8Array> {
	const [tbs] = readSequenceChildren(certificateDer);
	if (tbs === undefined) throw new Error('expected a TBSCertificate');
	const tbsDer = sliceElement(certificateDer, tbs);
	const fields = readSequenceChildren(tbsDer);
	const algorithmIndex = fields[0]?.tag === 0xa0 ? 2 : 1;
	const spkiIndex = algorithmIndex + 4;
	const rebuilt = sequence(
		fields.map((field, index) =>
			index === algorithmIndex
				? ALGORITHM
				: index === spkiIndex
					? spki(subject)
					: sliceElement(tbsDer, field),
		),
	);
	const signature = await sign(issuer.key, issuer.parametersDer, rebuilt);
	return sequence([rebuilt, ALGORITHM, bitString(signature)]);
}

/**
 * `responseDer` with `signer` as its byKey responder, signed by `signer` under
 * the parameter signature algorithm, embedding `certificates`.
 */
export async function resignedOcspResponse(
	responseDer: Uint8Array,
	signer: ParameterKey,
	certificates: readonly Uint8Array[],
): Promise<Uint8Array> {
	const [status, responseBytes] = readSequenceChildren(responseDer);
	if (status === undefined || responseBytes?.tag !== 0xa0)
		throw new Error('expected responseBytes');
	const [responseType, response] = readSequenceChildren(responseBytes.value);
	if (responseType === undefined || response?.tag !== 0x04) throw new Error('expected a response');
	const [responseData] = readSequenceChildren(response.value);
	if (responseData === undefined) throw new Error('expected ResponseData');
	const responseDataDer = sliceElement(response.value, responseData);
	const keyHash = new Uint8Array(await crypto.subtle.digest('SHA-1', new Uint8Array(signer.key)));
	const tbsDer = sequence(
		readSequenceChildren(responseDataDer).map((field) =>
			field.tag === 0xa1 || field.tag === 0xa2
				? explicitContext(2, octetString(keyHash))
				: sliceElement(responseDataDer, field),
		),
	);
	const basic = sequence([
		tbsDer,
		ALGORITHM,
		bitString(await sign(signer.key, signer.parametersDer, tbsDer)),
		...(certificates.length === 0 ? [] : [explicitContext(0, sequence([...certificates]))]),
	]);
	return sequence([
		sliceElement(responseDer, status),
		explicitContext(
			0,
			sequence([sliceElement(responseBytes.value, responseType), octetString(basic)]),
		),
	]);
}
