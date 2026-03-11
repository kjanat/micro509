import { createCertificate, createPfx, createSelfSignedCertificate, generateKeyPair, parsePfxPem } from "@/index.ts";
import { describe, expect, it } from "bun:test";

describe("pfx", () => {
	it("creates and parses passwordless PFX bundles", async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: "PFX Root" },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "PFX Root" },
			subject: { commonName: "pfx-leaf.example" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const pfx = await createPfx({
			certificates: [
				{
					certificate: leaf.pem,
					attributes: {
						friendlyName: "leaf",
						localKeyId: Uint8Array.of(1, 2, 3),
					},
				},
				{
					certificate: ca.certificate.pem,
					attributes: { friendlyName: "root" },
				},
			],
			privateKeys: [
				{
					privateKey: leafKeys.privateKey,
					attributes: {
						friendlyName: "leaf",
						localKeyId: Uint8Array.of(1, 2, 3),
					},
				},
			],
		});
		const parsed = await parsePfxPem(pfx.pem);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error("unreachable");
		expect(
			parsed.value.certificates.map(
				(certificate) => certificate.subject.values.commonName,
			),
		).toEqual(["pfx-leaf.example", "PFX Root"]);
		expect(parsed.value.privateKeys).toHaveLength(1);
		expect(parsed.value.bags[0]).toMatchObject({
			kind: "certificate",
			attributes: { friendlyName: "leaf", localKeyId: "010203" },
		});
	});

	it("creates and parses encrypted PFX bundles", async () => {
		const keyPair = await generateKeyPair();
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: "encrypted-pfx.example" },
			keyPair,
		});
		const pfx = await createPfx({
			certificates: [
				{
					certificate: certificate.certificate.pem,
					attributes: { friendlyName: "leaf" },
				},
			],
			privateKeys: [
				{
					privateKey: keyPair.privateKey,
					attributes: { friendlyName: "leaf-key" },
				},
			],
			encryption: { password: "secret123" },
		});
		const parsed = await parsePfxPem(pfx.pem, { password: "secret123" });
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error("unreachable");
		expect(
			parsed.value.certificates.map((entry) => entry.subject.values.commonName),
		).toEqual(["encrypted-pfx.example"]);
		expect(parsed.value.privateKeys).toHaveLength(1);
		const wrongPassword = await parsePfxPem(pfx.pem, { password: "wrong" });
		expect(wrongPassword).toMatchObject({
			ok: false,
			code: "invalid_password",
		});
	});

	it("verifies PFX MAC integrity", async () => {
		const keyPair = await generateKeyPair();
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: "mac-pfx.example" },
			keyPair,
		});
		const pfx = await createPfx({
			certificates: [{ certificate: certificate.certificate.pem }],
			privateKeys: [{ privateKey: keyPair.privateKey }],
			mac: { password: "integrity123" },
		});
		const parsed = await parsePfxPem(pfx.pem, { macPassword: "integrity123" });
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error("unreachable");
		expect(parsed.value.macData?.valid).toBe(true);
		const wrongMac = await parsePfxPem(pfx.pem, { macPassword: "wrong" });
		expect(wrongMac).toMatchObject({
			ok: false,
			code: "invalid_password",
		});
	});
});
