/**
 * Shared smoke assertions, run in every supported runtime (Node, Deno, workerd, browser).
 * @module
 */

/** @param {typeof import('#micro509')} micro509 */
export async function runSmoke(micro509) {
	const { certificate } = await micro509.createSelfSignedCertificate({
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

	return 'smoke OK';
}
