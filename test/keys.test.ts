import {
	createCertificate,
	exportBinaryBase64,
	exportEncryptedPkcs1Pem,
	exportEncryptedPkcs8Der,
	exportEncryptedPkcs8Pem,
	exportEncryptedSec1Pem,
	exportPkcs1Der,
	exportPkcs1Pem,
	exportPkcs8Der,
	exportPkcs8Pem,
	exportPrivateJwk,
	exportPublicJwk,
	exportSec1Der,
	exportSec1Pem,
	exportSpkiDer,
	exportSpkiPem,
	generateKeyPair,
	importEncryptedPkcs1Pem,
	importEncryptedPkcs8Der,
	importEncryptedPkcs8Pem,
	importEncryptedSec1Pem,
	importPkcs1Der,
	importPkcs1Pem,
	importPkcs8Base64,
	importPkcs8Pem,
	importPrivateJwk,
	importPublicJwk,
	importSec1Der,
	importSec1Pem,
	importSpkiBase64,
	importSpkiPem,
} from "@/index.ts";
import { describe, expect, it } from "bun:test";
import { X509Certificate } from "node:crypto";

describe("keys", () => {
	it("roundtrips RSA PKCS#1 and EC SEC1 private keys", async () => {
		const rsa = await generateKeyPair({ kind: "rsa", modulusLength: 2048 });
		const pkcs1Pem = await exportPkcs1Pem(rsa.privateKey);
		const pkcs1Der = await exportPkcs1Der(rsa.privateKey);
		const rsaFromPem = await importPkcs1Pem(pkcs1Pem, { kind: "rsa" });
		const rsaFromDer = await importPkcs1Der(pkcs1Der, { kind: "rsa" });
		expect(await exportPkcs8Der(rsaFromPem)).toEqual(
			await exportPkcs8Der(rsa.privateKey),
		);
		expect(await exportPkcs8Der(rsaFromDer)).toEqual(
			await exportPkcs8Der(rsa.privateKey),
		);

		const ec = await generateKeyPair({ kind: "ecdsa", namedCurve: "P-256" });
		const sec1Pem = await exportSec1Pem(ec.privateKey);
		const sec1Der = await exportSec1Der(ec.privateKey);
		const ecFromPem = await importSec1Pem(sec1Pem, {
			kind: "ecdsa",
			namedCurve: "P-256",
		});
		const ecFromDer = await importSec1Der(sec1Der, {
			kind: "ecdsa",
			namedCurve: "P-256",
		});
		expect(await exportPkcs8Der(ecFromPem)).toEqual(
			await exportPkcs8Der(ec.privateKey),
		);
		expect(await exportPkcs8Der(ecFromDer)).toEqual(
			await exportPkcs8Der(ec.privateKey),
		);
	});

	it("roundtrips encrypted PKCS#8 helpers", async () => {
		const keyPair = await generateKeyPair({ kind: "rsa", modulusLength: 2048 });
		const pem = await exportEncryptedPkcs8Pem(keyPair.privateKey, {
			password: "secret123",
		});
		const der = await exportEncryptedPkcs8Der(keyPair.privateKey, {
			password: "secret123",
		});
		const importedPem = await importEncryptedPkcs8Pem(pem, "secret123", {
			kind: "rsa",
		});
		const importedDer = await importEncryptedPkcs8Der(der, "secret123", {
			kind: "rsa",
		});
		expect(await exportPkcs8Der(importedPem)).toEqual(
			await exportPkcs8Der(keyPair.privateKey),
		);
		expect(await exportPkcs8Der(importedDer)).toEqual(
			await exportPkcs8Der(keyPair.privateKey),
		);
		await expect(
			importEncryptedPkcs8Pem(pem, "wrong", { kind: "rsa" }),
		).rejects.toThrow("Invalid password or encrypted content");
	});

	it("roundtrips encrypted traditional RSA and EC PEM helpers", async () => {
		const rsa = await generateKeyPair({ kind: "rsa", modulusLength: 2048 });
		const encryptedRsaPem = await exportEncryptedPkcs1Pem(rsa.privateKey, {
			password: "secret123",
		});
		const importedRsa = await importEncryptedPkcs1Pem(
			encryptedRsaPem,
			"secret123",
			{ kind: "rsa" },
		);
		expect(await exportPkcs8Der(importedRsa)).toEqual(
			await exportPkcs8Der(rsa.privateKey),
		);
		await expect(
			importEncryptedPkcs1Pem(encryptedRsaPem, "wrong", { kind: "rsa" }),
		).rejects.toThrow("Invalid password or encrypted PEM content");

		const ec = await generateKeyPair({ kind: "ecdsa", namedCurve: "P-256" });
		const encryptedEcPem = await exportEncryptedSec1Pem(ec.privateKey, {
			password: "secret123",
		});
		const importedEc = await importEncryptedSec1Pem(
			encryptedEcPem,
			"secret123",
			{ kind: "ecdsa", namedCurve: "P-256" },
		);
		expect(await exportPkcs8Der(importedEc)).toEqual(
			await exportPkcs8Der(ec.privateKey),
		);
	});

	it("roundtrips keys through PEM, base64, and JWK imports", async () => {
		const original = await generateKeyPair({
			kind: "rsa",
			modulusLength: 2048,
		});
		const importedPublic = await importSpkiPem(await original.exportSpkiPem(), {
			kind: "rsa",
		});
		const importedPrivate = await importPkcs8Pem(
			await original.exportPkcs8Pem(),
			{ kind: "rsa" },
		);
		const base64Public = await importSpkiBase64(
			await exportBinaryBase64(original.publicKey),
			{ kind: "rsa" },
		);
		const base64Private = await importPkcs8Base64(
			await exportBinaryBase64(original.privateKey),
			{ kind: "rsa" },
		);
		const jwkPublic = await importPublicJwk(await original.exportPublicJwk(), {
			kind: "rsa",
		});
		const jwkPrivate = await importPrivateJwk(
			await original.exportPrivateJwk(),
			{ kind: "rsa" },
		);

		const certificate = await createCertificate({
			issuer: { commonName: "imported-ca" },
			subject: { commonName: "imported-leaf" },
			publicKey: importedPublic,
			signerPrivateKey: importedPrivate,
			issuerPublicKey: importedPublic,
		});
		const certificateFromBase64 = await createCertificate({
			issuer: { commonName: "imported-ca-2" },
			subject: { commonName: "imported-leaf-2" },
			publicKey: base64Public,
			signerPrivateKey: base64Private,
			issuerPublicKey: base64Public,
		});
		const certificateFromJwk = await createCertificate({
			issuer: { commonName: "imported-ca-3" },
			subject: { commonName: "imported-leaf-3" },
			publicKey: jwkPublic,
			signerPrivateKey: jwkPrivate,
			issuerPublicKey: jwkPublic,
		});

		expect(new X509Certificate(certificate.pem).subject).toContain(
			"CN=imported-leaf",
		);
		expect(new X509Certificate(certificateFromBase64.pem).subject).toContain(
			"CN=imported-leaf-2",
		);
		expect(new X509Certificate(certificateFromJwk.pem).subject).toContain(
			"CN=imported-leaf-3",
		);
		expect(await exportSpkiDer(importedPublic)).toEqual(
			await original.exportSpkiDer(),
		);
		expect(await exportPkcs8Der(importedPrivate)).toEqual(
			await original.exportPkcs8Der(),
		);
		expect(await exportSpkiDer(base64Public)).toEqual(
			await original.exportSpkiDer(),
		);
		expect(await exportPkcs8Der(base64Private)).toEqual(
			await original.exportPkcs8Der(),
		);
		expect(await exportSpkiDer(jwkPublic)).toEqual(
			await original.exportSpkiDer(),
		);
		expect(await exportPkcs8Der(jwkPrivate)).toEqual(
			await original.exportPkcs8Der(),
		);
	});

	it("imports and exports keys via ecdsa and ed25519", async () => {
		const ecP384 = await generateKeyPair({
			kind: "ecdsa",
			namedCurve: "P-384",
		});
		const ecPub = await importSpkiBase64(
			await exportBinaryBase64(ecP384.publicKey),
			{ kind: "ecdsa", namedCurve: "P-384" },
		);
		const ecPriv = await importPkcs8Base64(
			await exportBinaryBase64(ecP384.privateKey),
			{ kind: "ecdsa", namedCurve: "P-384" },
		);
		expect(await exportSpkiDer(ecPub)).toEqual(await ecP384.exportSpkiDer());
		expect(await exportPkcs8Der(ecPriv)).toEqual(await ecP384.exportPkcs8Der());

		const ed = await generateKeyPair({ kind: "ed25519" });
		const edPub = await importSpkiPem(await ed.exportSpkiPem(), {
			kind: "ed25519",
		});
		const edPriv = await importPkcs8Pem(await ed.exportPkcs8Pem(), {
			kind: "ed25519",
		});
		expect(await exportSpkiDer(edPub)).toEqual(await ed.exportSpkiDer());
		expect(await exportPkcs8Der(edPriv)).toEqual(await ed.exportPkcs8Der());
	});

	it("exports keys with standalone PEM and JWK helpers", async () => {
		const keyPair = await generateKeyPair({ kind: "ed25519" });
		expect(await exportSpkiPem(keyPair.publicKey)).toContain(
			"BEGIN PUBLIC KEY",
		);
		expect(await exportPkcs8Pem(keyPair.privateKey)).toContain(
			"BEGIN PRIVATE KEY",
		);
		expect(await exportPublicJwk(keyPair.publicKey)).toHaveProperty("kty");
		expect(await exportPrivateJwk(keyPair.privateKey)).toHaveProperty("kty");
	});
});
