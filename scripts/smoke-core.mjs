/**
 * Shared smoke assertions, run in every supported runtime (Node, Deno, workerd, browser).
 * @module
 */

/**
 * @param {typeof import('#micro509')} micro509
 * @param {typeof import('#micro509/crypto')} cryptoApi
 */
export async function runSmoke(micro509, cryptoApi) {
	const { signData, verifySignatureWithKey } = cryptoApi;
	const { certificate, keyPair } = await micro509.createSelfSignedCertificate({
		subject: { commonName: 'smoke.example' },
		validity: { days: 1 },
	});

	const parsed = micro509.unwrap(micro509.parseCertificatePem(certificate.pem));
	if (parsed.subject.values.commonName !== 'smoke.example') {
		throw new Error('smoke: parsed commonName mismatch');
	}

	const verified = await micro509.verifyCertificateChain({
		leaf: certificate.pem,
		roots: [certificate.pem],
		allowSelfSignedLeaf: true,
	});
	if (!verified.ok) {
		throw new Error(`smoke: verifyCertificateChain failed: ${verified.error.code}`);
	}

	const data = new TextEncoder().encode('detached smoke payload');
	const signed = await signData(keyPair.privateKey, data);
	const publicKey = await crypto.subtle.importKey(
		'jwk',
		await micro509.exportPublicJwk(keyPair.publicKey),
		{ name: 'ECDSA', namedCurve: 'P-256' },
		false,
		['verify'],
	);
	const input = {
		publicKey,
		signatureAlgorithm: { oid: signed.algorithmOid },
		/** @type {'der'} */
		signatureEncoding: 'der',
		signature: signed.signature,
		data,
	};
	const valid = await verifySignatureWithKey(input);
	const changed = await verifySignatureWithKey({ ...input, data: new Uint8Array([0]) });
	if (publicKey.extractable || !valid.ok || !valid.valid || !changed.ok || changed.valid) {
		throw new Error('smoke: reused non-extractable public key verification failed');
	}

	return 'smoke OK';
}
