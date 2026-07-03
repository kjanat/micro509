// Runtime smoke test against the built dist output.
// Runs under Node (`node scripts/smoke.mjs`) and Deno (`deno run scripts/smoke.mjs`)
// to back the multi-runtime support claim with executable evidence.

const m = await import(new URL('../dist/index.js', import.meta.url).href);

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

// Deno 2 also exposes the `process` global; the CI step name identifies the runtime.
console.log(`smoke OK (${process.version})`);
