import {
	categorizePemBlocks,
	createCertificateSigningRequest,
	createSelfSignedCertificate,
	generateKeyPair,
	pemDecode,
	splitPemBlocks,
} from "#micro509";
import { describe, expect, it } from "bun:test";

describe("pem", () => {
	it("splits mixed PEM bundles by label", async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: "bundle.example" },
		});
		const csr = await createCertificateSigningRequest({
			subject: { commonName: "bundle.example" },
			publicKey: certificate.keyPair.publicKey,
			signerPrivateKey: certificate.keyPair.privateKey,
		});
		const privateKeyPem = await certificate.keyPair.exportPkcs8Pem();
		const bundle = `${certificate.certificate.pem}\n${csr.pem}\n${privateKeyPem}`;

		expect(splitPemBlocks(bundle).map((block) => block.label)).toEqual([
			"CERTIFICATE",
			"CERTIFICATE REQUEST",
			"PRIVATE KEY",
		]);
		expect(categorizePemBlocks(bundle)).toMatchObject({
			certificates: [{ label: "CERTIFICATE" }],
			certificateRequests: [{ label: "CERTIFICATE REQUEST" }],
			privateKeys: [{ label: "PRIVATE KEY" }],
			publicKeys: [],
			others: [],
		});
	});

	it("categorizes public and unknown PEM blocks from text and from blocks", async () => {
		const keyPair = await generateKeyPair({ kind: "ed25519" });
		const publicPem = await keyPair.exportSpkiPem();
		const unknownPem = "-----BEGIN SOMETHING-----\nAQID\n-----END SOMETHING-----";
		const bundle = `${publicPem}\n${unknownPem}`;

		expect(categorizePemBlocks(bundle)).toMatchObject({
			publicKeys: [{ label: "PUBLIC KEY" }],
			others: [{ label: "SOMETHING" }],
		});
		expect(categorizePemBlocks(splitPemBlocks(bundle))).toMatchObject({
			publicKeys: [{ label: "PUBLIC KEY" }],
			others: [{ label: "SOMETHING" }],
		});
		expect(() => pemDecode("CERTIFICATE", publicPem)).toThrow(
			"Invalid PEM for CERTIFICATE",
		);
	});
});
