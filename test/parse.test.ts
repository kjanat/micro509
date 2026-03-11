import { sequence, tlv } from "@/der.ts";
import {
	createCertificate,
	createSelfSignedCertificate,
	decodeExtension,
	decodeExtensions,
	defineExtensionDecoderMap,
	findExtension,
	generateKeyPair,
	parseCertificateDer,
	parseCertificatePem,
} from "@/index.ts";
import { OIDS } from "@/oids.ts";
import { parseNameConstraints } from "@/parse.ts";
import { describe, expect, it } from "bun:test";

describe("parse", () => {
	it("supports custom extension encode and decode hooks", async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: "custom-ext.example" },
			extensions: {
				customExtensions: [
					{
						oid: "1.2.3.4.200",
						critical: true,
						value: Uint8Array.of(0x04, 0x03, 0x01, 0x02, 0x03),
					},
					{ oid: "1.2.3.4.201", value: Uint8Array.of(0x04, 0x01, 0xff) },
				],
			},
		});

		const parsed = parseCertificatePem(certificate.certificate.pem);
		const extension = findExtension(parsed.extensions, "1.2.3.4.200");
		if (extension === undefined) {
			throw new Error("Missing custom extension");
		}
		expect(extension.critical).toBe(true);
		expect(Array.from(extension.valueDer)).toEqual([
			0x04,
			0x03,
			0x01,
			0x02,
			0x03,
		]);
		expect(
			decodeExtension(parsed.extensions, {
				oid: "1.2.3.4.200",
				decode(input) {
					return Array.from(input.valueDer).join(":");
				},
			}),
		).toBe("4:3:1:2:3");
		expect(
			decodeExtensions(parsed.extensions, [
				{
					oid: "1.2.3.4.200",
					decode(input) {
						return input.valueHex;
					},
				},
				{
					oid: "1.2.3.4.201",
					decode(input) {
						return input.critical ? "critical" : "non-critical";
					},
				},
			]),
		).toEqual([
			{ oid: "1.2.3.4.200", critical: true, value: "0403010203" },
			{ oid: "1.2.3.4.201", critical: false, value: "non-critical" },
		]);

		await expect(
			createSelfSignedCertificate({
				subject: { commonName: "dup-ext.example" },
				extensions: {
					keyUsage: ["digitalSignature"],
					customExtensions: [
						{ oid: OIDS.keyUsage, value: Uint8Array.of(0x05, 0x00) },
					],
				},
			}),
		).rejects.toThrow("Duplicate extension OID");
	});

	it("runs decoder registries directly during parse", async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: "parse-registry.example" },
			extensions: {
				customExtensions: [
					{ oid: "1.2.3.4.210", value: Uint8Array.of(0x04, 0x02, 0xaa, 0xbb) },
				],
			},
		});

		const parsed = parseCertificatePem(certificate.certificate.pem, {
			decoders: [
				{
					oid: "1.2.3.4.210",
					decode(extension) {
						return extension.valueHex;
					},
				},
			],
		});

		expect(parsed.decodedExtensions).toEqual([
			{ oid: "1.2.3.4.210", critical: false, value: "0402aabb" },
		]);
		const typedParsed = parseCertificatePem(certificate.certificate.pem, {
			decoderMap: defineExtensionDecoderMap({
				customText: {
					oid: "1.2.3.4.210",
					decode: (extension: { readonly valueHex: string }) => extension.valueHex,
				},
			}),
		});
		expect(typedParsed.decodedExtensionMap?.customText).toEqual({
			oid: "1.2.3.4.210",
			critical: false,
			value: "0402aabb",
		});
	});

	it("parses all known EKU types", async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: "EKU CA" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign"],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "EKU CA" },
			subject: { commonName: "eku-leaf" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				extendedKeyUsage: [
					"serverAuth",
					"clientAuth",
					"codeSigning",
					"emailProtection",
					"timeStamping",
					"ocspSigning",
				],
			},
		});
		const parsed = parseCertificatePem(leaf.pem);
		expect(parsed.extendedKeyUsage).toEqual([
			"serverAuth",
			"clientAuth",
			"codeSigning",
			"emailProtection",
			"timeStamping",
			"ocspSigning",
		]);
	});

	it("decodeExtension returns undefined for missing OID", async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: "decode-miss" },
		});
		const parsed = parseCertificatePem(certificate.pem);
		expect(
			decodeExtension(parsed.extensions, {
				oid: "1.2.3.4.999.888",
				decode: () => "should not run",
			}),
		).toBeUndefined();
	});

	it("decodeExtensions skips missing decoders", async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: "decode-skip" },
		});
		const parsed = parseCertificatePem(certificate.pem);
		const result = decodeExtensions(parsed.extensions, [
			{ oid: "1.2.3.4.999.777", decode: () => "never" },
			{ oid: "1.2.3.4.999.888", decode: () => "never" },
		]);
		expect(result).toEqual([]);
	});

	it("parses all supported name fields", async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: {
				country: "US",
				state: "CA",
				locality: "San Francisco",
				street: "Market St",
				organization: "Acme",
				organizationalUnit: "PKI",
				commonName: "full-name.example",
				givenName: "Jane",
				surname: "Doe",
				title: "Engineer",
				serialNumber: "12345",
				emailAddress: "jane@example.com",
			},
		});
		const parsed = parseCertificatePem(certificate.pem);
		expect(parsed.subject.values).toMatchObject({
			country: "US",
			state: "CA",
			locality: "San Francisco",
			street: "Market St",
			organization: "Acme",
			organizationalUnit: "PKI",
			commonName: "full-name.example",
			givenName: "Jane",
			surname: "Doe",
			title: "Engineer",
			serialNumber: "12345",
			emailAddress: "jane@example.com",
		});
	});

	it("throws on malformed or truncated DER input", () => {
		expect(() => parseCertificateDer(new Uint8Array([0x30, 0x03, 0x01]))).toThrow();
		expect(() => parseCertificateDer(new Uint8Array([]))).toThrow();
		expect(() => parseCertificatePem("not a pem")).toThrow();
		expect(() => parseCertificateDer(new Uint8Array([0xff, 0xff]))).toThrow();
	});

	it("parses and round-trips nameConstraints extension", async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: "NC Parse Test CA" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
				nameConstraints: {
					permittedSubtrees: [
						{ base: { type: "dns", value: "example.com" } },
						{ base: { type: "email", value: ".example.org" } },
					],
					excludedSubtrees: [
						{ base: { type: "dns", value: "bad.example.com" } },
					],
				},
			},
		});
		const parsed = parseCertificatePem(root.certificate.pem);
		expect(parsed.nameConstraints).toBeDefined();
		expect(parsed.nameConstraints?.permittedSubtrees).toHaveLength(2);
		expect(parsed.nameConstraints?.excludedSubtrees).toHaveLength(1);
		const permitted = parsed.nameConstraints?.permittedSubtrees;
		expect(permitted?.[0]?.base).toEqual({
			type: "dns",
			value: "example.com",
		});
		expect(permitted?.[1]?.base).toEqual({
			type: "email",
			value: ".example.org",
		});
		const excluded = parsed.nameConstraints?.excludedSubtrees;
		expect(excluded?.[0]?.base).toEqual({
			type: "dns",
			value: "bad.example.com",
		});
	});

	it("rejects GeneralSubtree with maximum field during parsing", () => {
		const dnsName = tlv(0x82, new TextEncoder().encode("example.com"));
		const maximum = tlv(0x81, Uint8Array.of(5));
		const subtree = sequence([dnsName, maximum]);
		const permitted = tlv(0xa0, subtree);
		const ncValue = sequence([permitted]);
		expect(() => parseNameConstraints(ncValue)).toThrow(/maximum/i);
	});

	it("rejects GeneralSubtree with non-zero minimum during parsing", () => {
		const dnsName = tlv(0x82, new TextEncoder().encode("example.com"));
		const minimum = tlv(0x80, Uint8Array.of(3));
		const subtree = sequence([dnsName, minimum]);
		const permitted = tlv(0xa0, subtree);
		const ncValue = sequence([permitted]);
		expect(() => parseNameConstraints(ncValue)).toThrow(/minimum/i);
	});
});
