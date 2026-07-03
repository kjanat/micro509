// Shared smoke assertions, run in every supported runtime
// (Node, Deno, workerd, browser).

/** @param {typeof import('../src/index.ts')} m */
export async function runSmoke(m) {
	const { certificate } = await m.createSelfSignedCertificate({
		subject: { commonName: 'smoke.example' },
		validity: { days: 1 },
	});

	const parsed = m.unwrap(m.parseCertificatePem(certificate.pem));
	if (parsed.subject.values.commonName !== 'smoke.example') {
		throw new Error('smoke: parsed commonName mismatch');
	}

	const verified = await m.verifyCertificateChain({
		leaf: certificate.pem,
		roots: [certificate.pem],
		allowSelfSignedLeaf: true,
	});
	if (!verified.ok) {
		throw new Error(`smoke: verifyCertificateChain failed: ${verified.error.code}`);
	}

	return 'smoke OK';
}
