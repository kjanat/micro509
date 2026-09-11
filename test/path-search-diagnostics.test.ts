import { describe, expect, it } from 'bun:test';
import { createCertificate, generateKeyPair, verifyCertificateChain } from '#micro509';

const VALIDITY = {
	notBefore: new Date('2020-01-01T00:00:00Z'),
	notAfter: new Date('2099-01-01T00:00:00Z'),
};
const AT = VALIDITY.notBefore;

interface Party {
	readonly publicKey: CryptoKey;
	readonly privateKey: CryptoKey;
}

let serialCounter = 0;
function nextSerial(): Uint8Array {
	serialCounter += 1;
	return Uint8Array.of(0x20, (serialCounter >> 8) & 0xff, serialCounter & 0xff);
}

function party(): Promise<Party> {
	return generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
}

async function caPem(
	subjectCn: string,
	issuerCn: string,
	subject: Party,
	issuer: Party,
): Promise<string> {
	const material = await createCertificate({
		issuer: { commonName: issuerCn },
		subject: { commonName: subjectCn },
		publicKey: subject.publicKey,
		signerPrivateKey: issuer.privateKey,
		issuerPublicKey: issuer.publicKey,
		serialNumber: nextSerial(),
		validity: VALIDITY,
		extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
	});
	return material.pem;
}

async function leafPem(
	subjectCn: string,
	issuerCn: string,
	subject: Party,
	issuer: Party,
): Promise<string> {
	const material = await createCertificate({
		issuer: { commonName: issuerCn },
		subject: { commonName: subjectCn },
		publicKey: subject.publicKey,
		signerPrivateKey: issuer.privateKey,
		issuerPublicKey: issuer.publicKey,
		serialNumber: nextSerial(),
		validity: VALIDITY,
		extensions: { keyUsage: ['digitalSignature'] },
	});
	return material.pem;
}

describe('path search diagnostics', () => {
	it('reports issuer_not_found at the terminal of the chain it returns', async () => {
		const keyM = await party();
		const keyX = await party();
		const keyY = await party();
		const keyL = await party();

		const leaf = await leafPem('Leaf', 'M', keyL, keyM);
		const certM1 = await caPem('M', 'Gone', keyM, keyM);
		const certM2 = await caPem('M', 'X', keyM, keyX);
		const certX = await caPem('X', 'Y', keyX, keyY);
		const certY = await caPem('Y', 'X', keyY, keyX);

		const result = await verifyCertificateChain({
			leaf,
			intermediates: [certM1, certM2, certX, certY],
			roots: [],
			at: AT,
		});

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.code).toBe('issuer_not_found');

		const chainCommonNames = result.details?.chainCommonNames;
		expect(chainCommonNames).toBeDefined();
		if (chainCommonNames === undefined) return;

		const index = result.index;
		expect(index).toBeDefined();
		if (index === undefined) return;

		expect(index).toBeGreaterThanOrEqual(0);
		expect(index).toBeLessThan(chainCommonNames.length);
		expect(index).toBe(chainCommonNames.length - 1);
		expect(result.details?.subjectCommonName).toBe(chainCommonNames[index]);
	});
});
