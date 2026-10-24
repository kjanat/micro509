import { c as rethrowIfInvariant, l as successResult, n as failureResult } from "./result-C9WPk47A.js";
import { a as pemDecodeOrThrow, d as base64Encode, l as trimLwsp, o as pemEncode, r as parseTraditionalPemOrThrow, u as base64Decode } from "./pem-C5BecCKu.js";
import { D as explicitContext, F as integerFromNumber, G as sequence, I as nullValue, L as objectIdentifier, P as integer, R as octetString, U as readRootElement, W as readSequenceChildren, Y as tlv, et as decodeFailureResult, m as hexToBytes, nt as i, p as extractBitStringValue, rt as rethrowDecodeRefusal, s as decodeIntegerNumber, u as decodeObjectIdentifier, v as toArrayBuffer, y as toHex } from "./asn1-jyOu_Jva.js";
// ../../dist/internal/asn1/oids.js
var e$1 = {
	$schema: "./oids.schema.json",
	ituT: {
		arc: "0",
		children: { data: {
			arc: "9",
			children: { pss: {
				arc: "2342",
				children: { ucl: {
					arc: "19200300",
					children: { pilot: {
						arc: "100",
						children: { pilotAttributeType: {
							arc: "1",
							oids: {
								userId: "1",
								domainComponent: "25"
							}
						} }
					} }
				} }
			} }
		} }
	},
	iso: {
		arc: "1",
		children: {
			memberBody: {
				arc: "2",
				children: { us: {
					arc: "840",
					children: {
						rsadsi: {
							arc: "113549",
							children: {
								pkcs: {
									arc: "1",
									children: {
										pkcs1: {
											arc: "1",
											oids: {
												rsaEncryption: "1",
												sha1WithRSAEncryption: "5",
												mgf1: "8",
												rsassaPss: "10",
												sha256WithRSAEncryption: "11",
												sha384WithRSAEncryption: "12",
												sha512WithRSAEncryption: "13"
											}
										},
										pkcs5: {
											arc: "5",
											oids: {
												pbkdf2: "12",
												pbes2: "13",
												pbmac1: "14"
											}
										},
										pkcs7: {
											arc: "7",
											oids: {
												pkcs7Data: "1",
												pkcs7SignedData: "2",
												pkcs7EncryptedData: "6"
											}
										},
										pkcs9: {
											arc: "9",
											oids: {
												emailAddress: "1",
												cmsContentType: "3",
												cmsMessageDigest: "4",
												extensionRequest: "14",
												friendlyName: "20",
												localKeyId: "21"
											},
											children: { certTypes: {
												arc: "22",
												oids: { x509CertificateBagType: "1" }
											} }
										},
										pkcs12Bags: {
											arc: "12",
											children: { bagTypes: {
												arc: "10",
												children: { bags: {
													arc: "1",
													oids: {
														pkcs12KeyBag: "1",
														pkcs12CertBag: "3"
													}
												} }
											} }
										}
									}
								},
								digestAlgorithm: {
									arc: "2",
									oids: {
										hmacWithSHA1: "7",
										hmacWithSHA256: "9",
										hmacWithSHA384: "10",
										hmacWithSHA512: "11"
									}
								}
							}
						},
						ansiX962: {
							arc: "10045",
							children: {
								keyType: {
									arc: "2",
									oids: { ecPublicKey: "1" }
								},
								curves: {
									arc: "3",
									children: { prime: {
										arc: "1",
										oids: { prime256v1: "7" }
									} }
								},
								signatures: {
									arc: "4",
									oids: { ecdsaWithSHA1: "1" },
									children: { sha2: {
										arc: "3",
										oids: {
											ecdsaWithSHA224: "1",
											ecdsaWithSHA256: "2",
											ecdsaWithSHA384: "3",
											ecdsaWithSHA512: "4"
										}
									} }
								}
							}
						}
					}
				} }
			},
			identifiedOrganization: {
				arc: "3",
				children: {
					certicom: {
						arc: "132",
						children: { curve: {
							arc: "0",
							oids: {
								secp384r1: "34",
								secp521r1: "35"
							}
						} }
					},
					edwardsCurveAlgs: {
						arc: "101",
						oids: {
							x25519: "110",
							x448: "111",
							ed25519: "112",
							ed448: "113"
						}
					},
					dod: {
						arc: "6",
						children: { internet: {
							arc: "1",
							children: {
								security: {
									arc: "5",
									children: {
										mechanisms: {
											arc: "5",
											children: { pkix: {
												arc: "7",
												children: {
													extensions: {
														arc: "1",
														oids: { authorityInfoAccess: "1" }
													},
													policyQualifiers: {
														arc: "2",
														oids: {
															cpsPolicyQualifier: "1",
															userNoticePolicyQualifier: "2"
														}
													},
													extendedKeyUsage: {
														arc: "3",
														oids: {
															serverAuth: "1",
															clientAuth: "2",
															codeSigning: "3",
															emailProtection: "4",
															timeStamping: "8",
															ocspSigning: "9"
														}
													},
													otherNameForms: {
														arc: "8",
														oids: {
															idOnDnsSrv: "7",
															idOnSmtpUtf8Mailbox: "9"
														}
													},
													accessMethods: {
														arc: "48",
														oids: {
															ocspAccessMethod: "1",
															caIssuersAccessMethod: "2"
														},
														children: { ocsp: {
															arc: "1",
															oids: {
																ocspBasicResponse: "1",
																ocspNonce: "2",
																ocspNoCheck: "5"
															}
														} }
													}
												}
											} }
										},
										kerberosV5: {
											arc: "2",
											oids: { idPkinitSan: "2" }
										}
									}
								},
								private: {
									arc: "4",
									children: { enterprise: {
										arc: "1",
										children: { microsoft: {
											arc: "311",
											children: { msEnrollment: {
												arc: "20",
												children: { msPrincipalNameForms: {
													arc: "2",
													oids: { ntPrincipalName: "3" }
												} }
											} }
										} }
									} }
								}
							}
						} }
					},
					oiw: {
						arc: "14",
						children: { secsig: {
							arc: "3",
							children: { algorithms: {
								arc: "2",
								oids: { sha1: "26" }
							} }
						} }
					}
				}
			}
		}
	},
	jointIsoItuT: {
		arc: "2",
		children: {
			ds: {
				arc: "5",
				children: {
					attributeType: {
						arc: "4",
						oids: {
							commonName: "3",
							surname: "4",
							serialNumber: "5",
							countryName: "6",
							localityName: "7",
							stateOrProvinceName: "8",
							streetAddress: "9",
							organizationName: "10",
							organizationalUnitName: "11",
							title: "12",
							givenName: "42"
						}
					},
					certificateExtension: {
						arc: "29",
						oids: {
							subjectKeyIdentifier: "14",
							keyUsage: "15",
							subjectAltName: "17",
							issuerAltName: "18",
							basicConstraints: "19",
							cRLNumber: "20",
							cRLReason: "21",
							invalidityDate: "24",
							deltaCRLIndicator: "27",
							issuingDistributionPoint: "28",
							certificateIssuer: "29",
							nameConstraints: "30",
							cRLDistributionPoints: "31",
							certificatePolicies: "32",
							policyMappings: "33",
							authorityKeyIdentifier: "35",
							policyConstraints: "36",
							extendedKeyUsage: "37",
							freshestCRL: "46",
							inhibitAnyPolicy: "54",
							noRevAvail: "56"
						},
						children: { certificatePolicies: {
							arc: "32",
							oids: { anyPolicy: "0" }
						} }
					}
				}
			},
			country: {
				arc: "16",
				children: { us: {
					arc: "840",
					children: { organization: {
						arc: "1",
						children: { gov: {
							arc: "101",
							children: { csor: {
								arc: "3",
								children: { nistAlgorithms: {
									arc: "4",
									children: {
										aes: {
											arc: "1",
											oids: {
												aes128Cbc: "2",
												aes192Cbc: "22",
												aes256Cbc: "42"
											}
										},
										hashes: {
											arc: "2",
											oids: {
												sha256: "1",
												sha384: "2",
												sha512: "3"
											}
										}
									}
								} }
							} }
						} }
					} }
				} }
			}
		}
	}
};
// ../../dist/internal/asn1/oids2.js
/**
* Centralized ASN.1 object identifier registry referenced by create, parse,
* verify, and container modules.
*
* All OIDs are dotted-decimal string constants keyed by their common short name.
*
* @module
*/
function joinOidPrefix(e, t) {
	return e === "" ? t : `${e}.${t}`;
}
function isOidNode(e) {
	return typeof e == "object" && !!e && "arc" in e;
}
function hasOidName(e, t) {
	return Object.hasOwn(e, t);
}
function addOidNode(e, t, n) {
	let r = joinOidPrefix(n, t.arc);
	if (t.oids !== void 0) for (let [n, i] of Object.entries(t.oids)) {
		let t = joinOidPrefix(r, i);
		if (hasOidName(e, n)) {
			let r = e[n];
			throw TypeError(`Duplicate OID name "${n}" at ${t}; already assigned to ${r}`);
		}
		e[n] = t;
	}
	t.children !== void 0 && addOidTree(e, t.children, r);
}
function addOidTree(e, t, n) {
	for (let r of Object.values(t)) addOidNode(e, r, n);
}
function addOidDocument(e, t) {
	for (let n of Object.values(t)) isOidNode(n) && addOidNode(e, n, "");
}
function collectOidNamesFromNode(e, t) {
	if (t.oids !== void 0) for (let n of Object.keys(t.oids)) e.add(n);
	if (t.children !== void 0) for (let n of Object.values(t.children)) collectOidNamesFromNode(e, n);
}
function collectOidNamesFromDocument(e) {
	let t = /* @__PURE__ */ new Set();
	for (let n of Object.values(e)) isOidNode(n) && collectOidNamesFromNode(t, n);
	return [...t];
}
function isOidRegistry(e, t) {
	for (let n of t) if (!hasOidName(e, n)) return !1;
	return !0;
}
function flattenOidTree(e) {
	let t = Object.create(null);
	addOidDocument(t, e);
	let n = collectOidNamesFromDocument(e);
	if (!isOidRegistry(t, n)) {
		let e = n.filter((e) => !hasOidName(t, e));
		throw TypeError(`Incomplete OID registry; missing ${e.join(", ")}`);
	}
	return t;
}
/**
* Dotted-decimal OID constants.
*
* Includes:
* - EKU purposes,
* - PKCS algorithms,
* - PKIX access methods,
* - X.500 attributes,
* - X.509v3 extensions, and
* - hash algorithms.
*/
const t$1 = flattenOidTree(e$1);
// ../../dist/internal/crypto/webcrypto.js
/**
* Shared WebCrypto runtime access helper.
*
* @module
*/
/** Return the global `Crypto` object. Throws when WebCrypto is unavailable. */
function getCrypto() {
	let e = globalThis.crypto;
	if (e?.subtle === void 0) throw Error("WebCrypto subtle API is required");
	return e;
}
// ../../dist/internal/crypto/hash.js
/**
* Synchronous digest implementations for MD5 and SHA-1, used where WebCrypto's
* async API is impractical (e.g. `EVP_BytesToKey` key derivation, PKCS#12 MAC).
*
* @module
*/
/** Unsigned 32-bit left-rotate. */
function rotl(e, t) {
	return (e << t | e >>> 32 - t) >>> 0;
}
/**
* Merkle–Damgård padding: append 0x80, zero-pad to 56 mod 64,
* append original bit-length as 64-bit integer.
*/
function mdPad(e, t) {
	let n = BigInt(e.length) * 8n, r = new Uint8Array(Math.ceil((e.length + 1 + 8) / 64) * 64);
	return r.set(e), r[e.length] = 128, new DataView(r.buffer, r.byteOffset, r.byteLength).setBigUint64(r.length - 8, n, t), r;
}
/** Bounds-checked read from a readonly number table. */
function tbl(e, t) {
	let n = e[t];
	if (n === void 0) throw RangeError(`table index ${t}`);
	return n;
}
/** Bounds-checked read from a Uint32Array. */
function w32(e, t) {
	let n = e[t];
	if (n === void 0) throw RangeError(`word index ${t}`);
	return n;
}
/** Per-round left-rotate amounts for MD5 (RFC 1321 §3.4). */
const e = [
	7,
	12,
	17,
	22,
	7,
	12,
	17,
	22,
	7,
	12,
	17,
	22,
	7,
	12,
	17,
	22,
	5,
	9,
	14,
	20,
	5,
	9,
	14,
	20,
	5,
	9,
	14,
	20,
	5,
	9,
	14,
	20,
	4,
	11,
	16,
	23,
	4,
	11,
	16,
	23,
	4,
	11,
	16,
	23,
	4,
	11,
	16,
	23,
	6,
	10,
	15,
	21,
	6,
	10,
	15,
	21,
	6,
	10,
	15,
	21,
	6,
	10,
	15,
	21
];
const t = [
	3614090360,
	3905402710,
	606105819,
	3250441966,
	4118548399,
	1200080426,
	2821735955,
	4249261313,
	1770035416,
	2336552879,
	4294925233,
	2304563134,
	1804603682,
	4254626195,
	2792965006,
	1236535329,
	4129170786,
	3225465664,
	643717713,
	3921069994,
	3593408605,
	38016083,
	3634488961,
	3889429448,
	568446438,
	3275163606,
	4107603335,
	1163531501,
	2850285829,
	4243563512,
	1735328473,
	2368359562,
	4294588738,
	2272392833,
	1839030562,
	4259657740,
	2763975236,
	1272893353,
	4139469664,
	3200236656,
	681279174,
	3936430074,
	3572445317,
	76029189,
	3654602809,
	3873151461,
	530742520,
	3299628645,
	4096336452,
	1126891415,
	2878612391,
	4237533241,
	1700485571,
	2399980690,
	4293915773,
	2240044497,
	1873313359,
	4264355552,
	2734768916,
	1309151649,
	4149444226,
	3174756917,
	718787259,
	3951481745
];
/** Compute a 16-byte MD5 digest (RFC 1321). Used by `EVP_BytesToKey` key derivation. */
function md5(n) {
	let r = mdPad(n, !0), [i, a, o, s] = [
		1732584193,
		4023233417,
		2562383102,
		271733878
	], c = /* @__PURE__ */ new Uint32Array(16);
	for (let n = 0; n < r.length; n += 64) {
		let l = new DataView(r.buffer, r.byteOffset + n, 64);
		for (let e = 0; e < 16; e++) c[e] = l.getUint32(e * 4, !0);
		let [u, d, f, p] = [
			i,
			a,
			o,
			s
		];
		for (let n = 0; n < 64; n++) {
			let r, i;
			n < 16 ? (r = (d & f | ~d & p) >>> 0, i = n) : n < 32 ? (r = (p & d | ~p & f) >>> 0, i = 5 * n + 1 & 15) : n < 48 ? (r = (d ^ f ^ p) >>> 0, i = 3 * n + 5 & 15) : (r = (f ^ (d | ~p)) >>> 0, i = 7 * n & 15), r = r + u + tbl(t, n) + w32(c, i) >>> 0;
			let a = p;
			p = f, f = d, d = d + rotl(r, tbl(e, n)) >>> 0, u = a;
		}
		i = i + u >>> 0, a = a + d >>> 0, o = o + f >>> 0, s = s + p >>> 0;
	}
	let l = /* @__PURE__ */ new Uint8Array(16), u = new DataView(l.buffer, l.byteOffset, l.byteLength);
	return u.setUint32(0, i, !0), u.setUint32(4, a, !0), u.setUint32(8, o, !0), u.setUint32(12, s, !0), l;
}
/** Compute a 20-byte SHA-1 digest (RFC 3174). Used by PKCS#12 MAC verification. */
function sha1(e) {
	let t = mdPad(e, !1), [n, r, i, a, o] = [
		1732584193,
		4023233417,
		2562383102,
		271733878,
		3285377520
	], s = /* @__PURE__ */ new Uint32Array(80), c = new DataView(t.buffer, t.byteOffset, t.byteLength);
	for (let e = 0; e < t.length; e += 64) {
		for (let t = 0; t < 16; t++) s[t] = c.getUint32(e + t * 4, !1);
		for (let e = 16; e < 80; e++) s[e] = rotl(w32(s, e - 3) ^ w32(s, e - 8) ^ w32(s, e - 14) ^ w32(s, e - 16), 1);
		let [t, l, u, d, f] = [
			n,
			r,
			i,
			a,
			o
		];
		for (let e = 0; e < 80; e++) {
			let n, r;
			e <= 19 ? (n = (l & u | ~l & d) >>> 0, r = 1518500249) : e <= 39 ? (n = (l ^ u ^ d) >>> 0, r = 1859775393) : e <= 59 ? (n = (l & u | l & d | u & d) >>> 0, r = 2400959708) : (n = (l ^ u ^ d) >>> 0, r = 3395469782);
			let i = rotl(t, 5) + n + f + r + w32(s, e) >>> 0;
			f = d, d = u, u = rotl(l, 30), l = t, t = i;
		}
		n = n + t >>> 0, r = r + l >>> 0, i = i + u >>> 0, a = a + d >>> 0, o = o + f >>> 0;
	}
	let l = /* @__PURE__ */ new Uint8Array(20), u = new DataView(l.buffer, l.byteOffset, l.byteLength);
	return u.setUint32(0, n, !1), u.setUint32(4, r, !1), u.setUint32(8, i, !1), u.setUint32(12, a, !1), u.setUint32(16, o, !1), l;
}
// ../../dist/internal/crypto/pbes2.js
/**
* PBES2 password-based encryption and decryption (RFC 8018).
*
* Supports AES-CBC-128/192/256 with PBKDF2 using HMAC-SHA-1 or HMAC-SHA-256.
* Used internally by encrypted PKCS#8 and PFX flows.
*
* @module
*/
/** Module-private brand so {@link isWrongPasswordError} cannot be fooled by look-alike errors. */
const d = Symbol("micro509.WrongPasswordError");
/**
* Thrown when PBES2 / AES-CBC decryption fails its integrity check, which in
* practice means the supplied password was wrong (or the ciphertext was
* corrupted). Lets callers distinguish a bad password from malformed input.
*/
function wrongPasswordError(e) {
	return Object.assign(Error(e), {
		name: "WrongPasswordError",
		[d]: !0
	});
}
/** Type guard: was decryption rejected for a wrong password / corrupt content? */
function isWrongPasswordError(e) {
	return e instanceof Error && d in e;
}
/** Upper bound on PBKDF2 iteration counts accepted from untrusted input. */
const f = 2e6;
const p = 1e5;
const m = Symbol("micro509.KdfIterationLimitError");
/** Thrown before key derivation when an encoded iteration count exceeds the caller's limit. */
function kdfIterationLimitError(e, t) {
	return Object.assign(/* @__PURE__ */ Error(`KDF iteration count ${e} exceeds the remaining budget of ${t}`), {
		name: "KdfIterationLimitError",
		[m]: !0
	});
}
/** Type guard: was derivation refused because the iteration count exceeds the limit? */
function isKdfIterationLimitError(e) {
	return e instanceof Error && m in e;
}
/** Opens a budget from the caller's limit. Throws when that limit is not a positive integer. */
function createKdfBudget(e, t = f) {
	let n = e?.maxKdfIterations ?? t;
	if (!Number.isSafeInteger(n) || n < 1) throw RangeError(`Invalid maxKdfIterations: must be an integer >= 1, got ${n}`);
	return { remaining: n };
}
/** Charges iterations against the budget, throwing before any derivation runs. */
function chargeKdfBudget(e, t) {
	if (t > e.remaining) throw kdfIterationLimitError(t, e.remaining);
	e.remaining -= t;
}
const h = 4294967295;
async function derivePbkdf2Bytes(e, t, n, r, i) {
	assertPbkdf2IterationCount(n);
	let a = await getCrypto().subtle.importKey("raw", toArrayBuffer(e), "PBKDF2", !1, ["deriveBits"]);
	return new Uint8Array(await getCrypto().subtle.deriveBits({
		name: "PBKDF2",
		salt: toArrayBuffer(t),
		iterations: n,
		hash: r
	}, a, i * 8));
}
/** Encrypts `data` using PBES2 (PBKDF2 + AES-CBC) and returns ciphertext with algorithm params. */
async function encryptPbes2(e, t) {
	let n = t.iterations ?? 1e5, r = t.salt ?? getCrypto().getRandomValues(/* @__PURE__ */ new Uint8Array(16)), i = t.iv ?? getCrypto().getRandomValues(/* @__PURE__ */ new Uint8Array(16)), a = t.cipher ?? "AES-256-CBC", o = t.prf ?? "HMAC-SHA-256";
	if (assertPbkdf2IterationCount(n), !(r instanceof Uint8Array) || r.length < 8) throw TypeError(`Invalid salt: must be Uint8Array with length >= 8, got length ${r.length}`);
	if (!(i instanceof Uint8Array) || i.length !== 16) throw TypeError(`Invalid IV: must be Uint8Array of exactly 16 bytes, got length ${i.length}`);
	let s = await deriveAesKey(t.password, r, n, a, o, ["encrypt"]), l = new Uint8Array(await getCrypto().subtle.encrypt({
		name: "AES-CBC",
		iv: toArrayBuffer(i)
	}, s, toArrayBuffer(e)));
	return {
		algorithmIdentifierDer: encodePbes2AlgorithmIdentifier({
			iterations: n,
			salt: r,
			iv: i,
			cipher: a,
			prf: o
		}),
		encryptedData: l,
		parameters: {
			iterations: n,
			salt: r,
			iv: i,
			cipher: a,
			prf: o
		}
	};
}
/**
* Decrypts PBES2 ciphertext given the DER AlgorithmIdentifier and password.
* Throws on wrong password, and before derivation when the encoded iteration
* count exceeds what `budget` still allows.
*/
async function decryptPbes2(e, t, n, r = createKdfBudget(void 0)) {
	let i = parsePbes2AlgorithmIdentifier(e);
	chargeKdfBudget(r, i.iterations);
	let a = await deriveAesKey(n, i.salt, i.iterations, i.cipher, i.prf, ["decrypt"]);
	try {
		return new Uint8Array(await getCrypto().subtle.decrypt({
			name: "AES-CBC",
			iv: toArrayBuffer(i.iv)
		}, a, toArrayBuffer(t)));
	} catch {
		throw wrongPasswordError("Invalid password or encrypted content");
	}
}
/**
* DER-encodes a PBES2 AlgorithmIdentifier SEQUENCE from resolved parameters.
*
* @throws {RangeError} if `parameters.iterations` is not an integer from 1 to 4294967295.
*/
function encodePbes2AlgorithmIdentifier(i) {
	assertPbkdf2IterationCount(i.iterations);
	let o = resolveEncryptionProfile(i.cipher), s = resolvePrfProfile(i.prf), c = [
		octetString(i.salt),
		integerFromNumber(i.iterations),
		integerFromNumber(o.keyLengthBytes),
		...i.prf === "HMAC-SHA-1" ? [] : [sequence([objectIdentifier(s.oid), nullValue()])]
	];
	return sequence([objectIdentifier(t$1.pbes2), sequence([sequence([objectIdentifier(t$1.pbkdf2), sequence(c)]), sequence([objectIdentifier(o.oid), octetString(i.iv)])])]);
}
/**
* Decodes a DER-encoded PBES2 AlgorithmIdentifier into structured {@linkcode Pbes2Parameters}.
*
* @throws if the encoding is malformed, names an unsupported KDF, PRF or cipher, or carries an
* iteration count outside 1 to 4294967295.
*/
function parsePbes2AlgorithmIdentifier(e) {
	let { paramsDer: t, kdf: n, scheme: r } = parsePbes2OuterFields(e), { pbkdf2Der: a, pbkdf2Params: c } = parsePbes2KdfFields(t, n), l = c[0], u = c[1];
	if (l === void 0 || u === void 0 || l.tag !== 4 || u.tag !== 2) throw Error("Malformed PBKDF2 params");
	let d = c[2], f = d?.tag === 2, p = f ? c[3] : d, m = t.slice(r.start - r.headerLength, r.end), g = readSequenceChildren(m), _ = g[0], v = g[1];
	if (_ === void 0 || v === void 0 || v.tag !== 4) throw Error("Malformed encryption scheme");
	let y = encryptionSchemeFromOid(decodeObjectIdentifier(_.value));
	if (y === void 0) throw Error("Unsupported content encryption scheme");
	if (d !== void 0 && !f && d.tag !== 48) throw Error("Malformed PBKDF2 params");
	if (f && decodeIntegerNumber(d.value) !== y.keyLengthBytes) throw Error("Unsupported PBKDF2 key length");
	let b = parsePbkdf2Prf(a, p), x = decodeIntegerNumber(u.value), S = new Uint8Array(l.value), C = new Uint8Array(v.value);
	if (x < 1) throw Error(`Invalid PBES2 iterations: must be >= 1, got ${x}`);
	if (x > 4294967295) throw Error(`Invalid PBES2 iterations: must be <= ${h}, got ${x}`);
	if (C.length !== 16) throw Error(`Invalid PBES2 IV: must be exactly 16 bytes, got ${C.length}`);
	return {
		salt: S,
		iterations: x,
		iv: C,
		cipher: y.name,
		prf: b
	};
}
function assertPbkdf2IterationCount(e) {
	if (!Number.isInteger(e) || e < 1 || e > 4294967295) throw RangeError(`Invalid iterations: must be an integer from 1 to ${h}, got ${e}`);
}
/** Extracts the KDF and encryption-scheme fields from a PBES2 AlgorithmIdentifier. */
function parsePbes2OuterFields(e) {
	let t = readSequenceChildren(e), n = t[0], r = t[1];
	if (n === void 0 || r === void 0) throw Error("Malformed PBES2 algorithm identifier");
	if (decodeObjectIdentifier(n.value) !== t$1.pbes2) throw Error("Unsupported encryption algorithm");
	let a = e.slice(r.start - r.headerLength, r.end), o = readSequenceChildren(a), c = o[0], u = o[1];
	if (c === void 0 || u === void 0) throw Error("Malformed PBES2 params");
	return {
		paramsDer: a,
		kdf: c,
		scheme: u
	};
}
function parsePbes2KdfFields(e, t) {
	let n = e.slice(t.start - t.headerLength, t.end), r = readSequenceChildren(n), a = r[0], o = r[1];
	if (a === void 0 || o === void 0) throw Error("Malformed KDF params");
	if (decodeObjectIdentifier(a.value) !== t$1.pbkdf2) throw Error("Unsupported KDF");
	let c = n.slice(o.start - o.headerLength, o.end);
	return {
		pbkdf2Der: c,
		pbkdf2Params: readSequenceChildren(c)
	};
}
/** Derives an AES-CBC `CryptoKey` from a password via PBKDF2. */
async function deriveAesKey(e, t, n, r, i, a) {
	let o = resolveEncryptionProfile(r), s = resolvePrfProfile(i), l = await getCrypto().subtle.importKey("raw", new TextEncoder().encode(e), "PBKDF2", !1, ["deriveKey"]);
	return getCrypto().subtle.deriveKey({
		name: "PBKDF2",
		salt: toArrayBuffer(t),
		iterations: n,
		hash: s.hash
	}, l, {
		name: "AES-CBC",
		length: o.keyLengthBits
	}, !1, a);
}
/** Parses the optional PRF AlgorithmIdentifier from PBKDF2 params. Absent means HMAC-SHA-1. */
function parsePbkdf2Prf(e, t) {
	if (t === void 0) return "HMAC-SHA-1";
	if (t.tag !== 48) throw Error("Malformed PBKDF2 PRF");
	let n = readSequenceChildren(e.slice(t.start - t.headerLength, t.end))[0];
	if (n === void 0) throw Error("Malformed PBKDF2 PRF");
	let r = prfFromOid(decodeObjectIdentifier(n.value));
	if (r === void 0) throw Error("Unsupported PBKDF2 PRF");
	return r;
}
/** Maps an AES-CBC OID to the encryption profile, or `undefined` if unsupported. */
function encryptionSchemeFromOid(e) {
	switch (e) {
		case t$1.aes128Cbc: return {
			name: "AES-128-CBC",
			oid: e,
			keyLengthBits: 128,
			keyLengthBytes: 16
		};
		case t$1.aes192Cbc: return {
			name: "AES-192-CBC",
			oid: e,
			keyLengthBits: 192,
			keyLengthBytes: 24
		};
		case t$1.aes256Cbc: return {
			name: "AES-256-CBC",
			oid: e,
			keyLengthBits: 256,
			keyLengthBytes: 32
		};
	}
}
/** Maps an HMAC OID to the PRF name, or `undefined` if unsupported. */
function prfFromOid(e) {
	switch (e) {
		case t$1.hmacWithSHA1: return "HMAC-SHA-1";
		case t$1.hmacWithSHA256: return "HMAC-SHA-256";
	}
}
/** Looks up the full encryption profile for a scheme name. Throws if unsupported. */
function resolveEncryptionProfile(e) {
	let t = encryptionSchemeFromOid(e === "AES-128-CBC" ? t$1.aes128Cbc : e === "AES-192-CBC" ? t$1.aes192Cbc : t$1.aes256Cbc);
	if (t === void 0) throw Error("Unsupported content encryption scheme");
	return t;
}
/** Looks up OID and WebCrypto hash name for a PRF. */
function resolvePrfProfile(e) {
	switch (e) {
		case "HMAC-SHA-1": return {
			oid: t$1.hmacWithSHA1,
			hash: "SHA-1"
		};
		case "HMAC-SHA-256": return {
			oid: t$1.hmacWithSHA256,
			hash: "SHA-256"
		};
		default: throw Error(`Unhandled Pbes2Prf: ${String(e)}`);
	}
}
// ../../dist/keys/keys.js
/**
* WebCrypto key generation plus import/export for PKCS#1, PKCS#8, SEC1, SPKI, and JWK.
*
* Supports RSA (PKCS#1v1.5, PSS, and OAEP), ECDSA (P-256, P-384, P-521), and Ed25519 keys.
* All functions use the WebCrypto API and return extractable keys.
*
* @example
* ```ts
* import { unwrap } from 'micro509';
* import { generateKeyPair, exportSpkiPem, importSpkiPem } from 'micro509/keys';
*
* // Generate and export
* const keys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
* const publicPem = await exportSpkiPem(keys.publicKey);
*
* // Import — Result-returning; unwrap() throws on failure
* const publicKey = unwrap(await importSpkiPem(publicPem, { kind: 'ecdsa', curve: 'P-256' }));
* ```
*
* @module
*/
/**
* Generate an asymmetric key pair for signing and verification, or — with
* `{ kind: 'rsa', scheme: 'oaep' }` — for RSA-OAEP encryption and decryption.
*
* @example
* ```ts
* const ecKeys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-384' });
* const rsaKeys = await generateKeyPair({ kind: 'rsa', modulusLength: 4096 });
* const edKeys = await generateKeyPair({ kind: 'ed25519' });
* const oaepKeys = await generateKeyPair({ kind: 'rsa', scheme: 'oaep' });
*
* // Default: ECDSA P-256
* const keys = await generateKeyPair();
* const pem = await keys.exportPkcs8Pem();
* ```
*/
async function generateKeyPair(e = {
	kind: "ecdsa",
	curve: "P-256"
}) {
	let t = getCrypto().subtle, n = isRsaOaepInput(e) ? ["encrypt", "decrypt"] : ["sign", "verify"], r = await t.generateKey(toGenerateKeyAlgorithm(e), !0, n);
	if (!("publicKey" in r) || !("privateKey" in r)) throw Error("Expected an asymmetric key pair");
	return wrapKeyPair(r.publicKey, r.privateKey);
}
function wrapKeyPair(e, t) {
	return {
		publicKey: e,
		privateKey: t,
		async exportSpkiDer() {
			return new Uint8Array(await getCrypto().subtle.exportKey("spki", e));
		},
		async exportSpkiPem() {
			return pemEncode("PUBLIC KEY", await this.exportSpkiDer());
		},
		async exportPkcs8Der() {
			return new Uint8Array(await getCrypto().subtle.exportKey("pkcs8", t));
		},
		async exportPkcs8Pem() {
			return pemEncode("PRIVATE KEY", await this.exportPkcs8Der());
		},
		exportPublicJwk() {
			return getCrypto().subtle.exportKey("jwk", e);
		},
		exportPrivateJwk() {
			return getCrypto().subtle.exportKey("jwk", t);
		}
	};
}
/**
* Export a public key as DER-encoded SubjectPublicKeyInfo.
*
* @see {@linkcode importSpkiDer} for the inverse operation
* @see {@linkcode exportSpkiPem} for PEM output
*/
async function exportSpkiDer(e) {
	return new Uint8Array(await getCrypto().subtle.exportKey("spki", e));
}
/**
* Export a private key as DER-encoded PKCS#8 PrivateKeyInfo.
*
* @see {@linkcode importPkcs8Der} for the inverse operation
* @see {@linkcode exportPkcs8Pem} for PEM output
* @see {@linkcode exportEncryptedPkcs8Der} for password-protected export
*/
async function exportPkcs8Der(e) {
	return new Uint8Array(await getCrypto().subtle.exportKey("pkcs8", e));
}
/**
* Export a public key as a JSON Web Key.
*
* @example
* ```ts
* const keys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
* const jwk = await exportPublicJwk(keys.publicKey);
* ```
*/
function exportPublicJwk(e) {
	return getCrypto().subtle.exportKey("jwk", e);
}
/**
* Export a private key as a JSON Web Key.
*
* @see {@linkcode importPrivateJwk} for the inverse operation
* @see {@linkcode exportPublicJwk} for public key export
*/
function exportPrivateJwk(e) {
	return getCrypto().subtle.exportKey("jwk", e);
}
/**
* Export a private key as PEM-encoded PKCS#8 PrivateKeyInfo.
*
* @example
* ```ts
* const keys = await generateKeyPair();
* const pem = await exportPkcs8Pem(keys.privateKey);
* // -----BEGIN PRIVATE KEY-----
* // MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEH...
* // -----END PRIVATE KEY-----
* ```
*
* @see {@linkcode importPkcs8Pem} for the inverse operation
* @see {@linkcode exportEncryptedPkcs8Pem} for password-protected export
*/
async function exportPkcs8Pem(e) {
	return pemEncode("PRIVATE KEY", await exportPkcs8Der(e));
}
/**
* Export a private key as DER-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.
*
* Uses PBES2 (PKCS#5 v2.1) with AES-CBC and PBKDF2. Compatible with OpenSSL.
*
* @param privateKey - The private key to export
* @param options - Encryption options including password and optional algorithm settings
*
* @throws {RangeError} If `options.iterations` is not an integer from 1 to 4294967295
*
* @see {@linkcode importEncryptedPkcs8Der} for the inverse operation
* @see {@linkcode exportEncryptedPkcs8Pem} for PEM output
*/
async function exportEncryptedPkcs8Der(e, t) {
	let r = await encryptPbes2(await exportPkcs8Der(e), t);
	return sequence([r.algorithmIdentifierDer, octetString(r.encryptedData)]);
}
/**
* Export a private key as PEM-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.
*
* @example
* ```ts
* const keys = await generateKeyPair();
* const pem = await exportEncryptedPkcs8Pem(keys.privateKey, { password: 'secret' });
* // -----BEGIN ENCRYPTED PRIVATE KEY-----
* // MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAc...
* // -----END ENCRYPTED PRIVATE KEY-----
* ```
*
* @see {@linkcode importEncryptedPkcs8Pem} for the inverse operation
*/
async function exportEncryptedPkcs8Pem(e, t) {
	return pemEncode("ENCRYPTED PRIVATE KEY", await exportEncryptedPkcs8Der(e, t));
}
/**
* Export an RSA private key as DER-encoded PKCS#1 RSAPrivateKey.
*
* PKCS#1 is the legacy RSA-only format. For algorithm-agnostic export, use
* {@linkcode exportPkcs8Der}.
*
* @throws {Error} If the key is not an RSA key
*
* @see {@linkcode importPkcs1Der} for the inverse operation
* @see {@linkcode exportPkcs1Pem} for PEM output
*/
async function exportPkcs1Der(e) {
	let t = parsePkcs8PrivateKey(await exportPkcs8Der(e));
	if (t.algorithmOid !== t$1.rsaEncryption) throw Error("PKCS#1 export requires an RSA private key");
	return t.privateKeyDer;
}
/**
* Export an RSA private key as PEM-encoded PKCS#1 RSAPrivateKey.
*
* @throws {Error} If the key is not an RSA key
*
* @see {@linkcode importPkcs1Pem} for the inverse operation
* @see {@linkcode exportEncryptedPkcs1Pem} for password-protected export
*/
async function exportPkcs1Pem(e) {
	return pemEncode("RSA PRIVATE KEY", await exportPkcs1Der(e));
}
/**
* Export an RSA private key as legacy `Proc-Type: 4,ENCRYPTED` PEM (PKCS#1).
*
* Uses OpenSSL's traditional PEM encryption with MD5-based key derivation.
* For modern encryption, prefer {@linkcode exportEncryptedPkcs8Pem}.
*
* @throws {Error} If the key is not an RSA key
*
* @see {@linkcode importEncryptedPkcs1Pem} for the inverse operation
*/
async function exportEncryptedPkcs1Pem(e, t) {
	return encryptTraditionalPem("RSA PRIVATE KEY", await exportPkcs1Der(e), t);
}
/**
* Export an EC private key as DER-encoded SEC 1 ECPrivateKey.
*
* SEC 1 is the legacy EC-only format. For algorithm-agnostic export, use
* {@linkcode exportPkcs8Der}.
*
* The output always carries the RFC 5915 `parameters [0]` named curve
* (matching OpenSSL), so it re-imports via {@linkcode importSec1Der} without
* an explicit curve.
*
* @throws {Error} If the key is not an EC key
*
* @see {@linkcode importSec1Der} for the inverse operation
* @see {@linkcode exportSec1Pem} for PEM output
*/
async function exportSec1Der(e) {
	let t = parsePkcs8PrivateKey(await exportPkcs8Der(e));
	if (t.algorithmOid !== t$1.ecPublicKey) throw Error("SEC1 export requires an EC private key");
	return ensureSec1NamedCurveParameters(t.privateKeyDer, t.parametersOid);
}
/**
* Export an EC private key as PEM-encoded SEC 1 ECPrivateKey.
*
* @throws {Error} If the key is not an EC key
*
* @see {@linkcode importSec1Pem} for the inverse operation
* @see {@linkcode exportEncryptedSec1Pem} for password-protected export
*/
async function exportSec1Pem(e) {
	return pemEncode("EC PRIVATE KEY", await exportSec1Der(e));
}
/**
* Export an EC private key as legacy `Proc-Type: 4,ENCRYPTED` PEM (SEC 1).
*
* Uses OpenSSL's traditional PEM encryption with MD5-based key derivation.
* For modern encryption, prefer {@linkcode exportEncryptedPkcs8Pem}.
*
* @throws {Error} If the key is not an EC key
*
* @see {@linkcode importEncryptedSec1Pem} for the inverse operation
*/
async function exportEncryptedSec1Pem(e, t) {
	return encryptTraditionalPem("EC PRIVATE KEY", await exportSec1Der(e), t);
}
/**
* Export a public key as PEM-encoded SubjectPublicKeyInfo.
*
* @example
* ```ts
* const keys = await generateKeyPair();
* const pem = await exportSpkiPem(keys.publicKey);
* ```
*/
async function exportSpkiPem(e) {
	return pemEncode("PUBLIC KEY", await exportSpkiDer(e));
}
/**
* Derive the matching public key from an imported (or generated) private key.
*
* The `import*` functions that read a PKCS#8 / PKCS#1 / SEC 1 / JWK private key
* return a bare `CryptoKey` with only `sign` (or, for RSA-OAEP, `decrypt`)
* usage — there is no accompanying public handle. This bridges that gap: it
* exports the private key's JWK, strips the private components, and re-imports
* the public half with `verify` (RSA-OAEP: `encrypt`) usage, so callers can go
* straight to {@linkcode exportSpkiDer} / {@linkcode exportSpkiPem} (e.g. to
* rebuild a self-signed cert or distribute the public key when only the
* private key is on disk).
*
* Supports RSA (`n`/`e`), ECDSA (`x`/`y`), and Ed25519 (`x`). The derived key
* inherits the private key's algorithm parameters (hash, curve).
*
* @param privateKey - An extractable private `CryptoKey`
* @returns Extractable public `CryptoKey` with `verify` (RSA-OAEP: `encrypt`) usage
*
* @throws {Error} If the key is not a private key, is non-extractable, or uses
* an unsupported key type
*
* @example
* ```ts
* const privateKey = await importPkcs8PemOrThrow(pem, { kind: 'ecdsa', curve: 'P-256' });
* const publicKey = await derivePublicKey(privateKey);
* const spkiPem = await exportSpkiPem(publicKey);
* ```
*
* @see {@linkcode exportSpkiDer} for exporting the derived key
*/
async function derivePublicKey(e) {
	if (e.type !== "private") throw Error("derivePublicKey requires a private CryptoKey");
	if (!e.extractable) throw Error("Cannot derive public key from a non-extractable private key");
	let t = getCrypto().subtle, n = e.algorithm.name === "RSA-OAEP" ? "encrypt" : "verify", r = await t.exportKey("jwk", e);
	return t.importKey("jwk", toPublicJwk(r, n), e.algorithm, !0, [n]);
}
/**
* Export a key as raw base64 (no PEM headers).
*
* Returns SPKI-encoded base64 for public keys, PKCS#8-encoded base64 for private keys.
* Useful for compact storage or transmission where PEM overhead is undesirable.
*
* @throws {Error} If the key is a symmetric/secret key
*
* @see {@linkcode importSpkiBase64} for public key import
* @see {@linkcode importPkcs8Base64} for private key import
*/
async function exportBinaryBase64(e) {
	if (e.type === "public") return base64Encode(await exportSpkiDer(e));
	if (e.type === "private") return base64Encode(await exportPkcs8Der(e));
	throw Error("Cannot export secret/symmetric CryptoKey");
}
/**
* Import a public key from DER-encoded SubjectPublicKeyInfo.
*
* When `algorithm` is omitted, the algorithm (and, for EC keys, the curve) is
* inferred from the SPKI's own AlgorithmIdentifier — useful for keys whose type
* isn't known ahead of time. Pass `algorithm` to additionally assert that the
* DER matches an expected algorithm.
*
* @param der - DER-encoded SubjectPublicKeyInfo bytes
* @param algorithm - Optional expected algorithm; must match key contents when given
* @returns Extractable CryptoKey with `verify` usage
*
* @throws {Error} If DER is malformed, encodes an unsupported algorithm, or doesn't match `algorithm`
*
* @see {@linkcode exportSpkiDer} for the inverse operation
* @see {@linkcode importSpkiPem} for PEM input
*/
async function importSpkiDerOrThrow(e, t) {
	let n = parseSpkiDer(e), r;
	t === void 0 ? r = inferKeyImportInput(n, "Unsupported SubjectPublicKeyInfo algorithm") : (assertSpkiMatchesRequestedAlgorithm(n, t), r = t);
	try {
		return await getCrypto().subtle.importKey("spki", new Uint8Array(e), toImportAlgorithm(r), !0, publicKeyUsages(r));
	} catch {
		throw Error("Malformed SubjectPublicKeyInfo");
	}
}
/** Runs a throwing key import and maps an EXPECTED failure to a `'malformed'` or `'limit_exceeded'` result; invariants rethrow. */
async function importResult(e) {
	try {
		return successResult(await e());
	} catch (e) {
		return rethrowIfInvariant(e), decodeFailureResult(e, i, "Malformed key");
	}
}
/** Like {@link importResult} but distinguishes a typed wrong-password failure (`'invalid_password'`). */
async function encryptedImportResult(a) {
	try {
		return successResult(await a());
	} catch (n) {
		return rethrowIfInvariant(n), isWrongPasswordError(n) ? failureResult("invalid_password", n.message) : isKdfIterationLimitError(n) ? failureResult("kdf_iterations_exceeded", n.message) : decodeFailureResult(n, i, "Malformed encrypted key");
	}
}
/**
* Import a public key from DER-encoded SubjectPublicKeyInfo.
*
* @see `importSpkiDerOrThrow` for the throwing variant
*/
function importSpkiDer(e, t) {
	return importResult(() => importSpkiDerOrThrow(e, t));
}
/**
* Import a public key from PEM-encoded SubjectPublicKeyInfo.
*
* @example
* ```ts
* const pem = `-----BEGIN PUBLIC KEY-----
* MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
* -----END PUBLIC KEY-----`;
* const key = await importSpkiPemOrThrow(pem, { kind: 'ecdsa', curve: 'P-256' });
* ```
*
* @see {@linkcode exportSpkiPem} for the inverse operation
*/
function importSpkiPemOrThrow(e, t) {
	return importSpkiDerOrThrow(pemDecodeOrThrow("PUBLIC KEY", e), t);
}
/**
* Import a public key from PEM-encoded SubjectPublicKeyInfo.
*
* @see `importSpkiPemOrThrow` for the throwing variant
*/
function importSpkiPem(e, t) {
	return importResult(() => importSpkiPemOrThrow(e, t));
}
/**
* Import a public key from base64-encoded SubjectPublicKeyInfo (no PEM headers).
*
* @see {@linkcode exportBinaryBase64} for the inverse operation
* @see {@linkcode importSpkiPem} for PEM input with headers
*/
function importSpkiBase64OrThrow(e, t) {
	let n;
	try {
		n = base64Decode(e);
	} catch {
		throw Error("Invalid base64 SubjectPublicKeyInfo");
	}
	return importSpkiDerOrThrow(n, t);
}
/**
* Import a public key from base64-encoded SubjectPublicKeyInfo (no PEM headers).
*
* @see `importSpkiBase64OrThrow` for the throwing variant
*/
function importSpkiBase64(e, t) {
	return importResult(() => importSpkiBase64OrThrow(e, t));
}
/**
* Import a private key from DER-encoded PKCS#8 PrivateKeyInfo.
*
* When `algorithm` is omitted, the algorithm (and, for EC keys, the curve) is
* inferred from the PrivateKeyInfo's own `privateKeyAlgorithm` — useful for
* keys whose type isn't known ahead of time. Pass `algorithm` to additionally
* assert that the DER matches an expected algorithm.
*
* An RFC 5958 v2 `OneAsymmetricKey` carrying `attributes [0]` or `publicKey [1]`
* is reduced to its v1 fields for the platform import, which Bun 1.3.14 and
* earlier rejects outright
* ([oven-sh/bun#35432](https://github.com/oven-sh/bun/issues/35432)). A
* `publicKey [1]` field is checked against the private key it accompanies.
*
* @param der - DER-encoded PKCS#8 PrivateKeyInfo bytes
* @param algorithm - Optional expected algorithm; must match key contents when given
* @returns Extractable CryptoKey with `sign` usage
*
* @throws {Error} If DER is malformed, encodes an unsupported algorithm, doesn't match `algorithm`, or carries a `publicKey [1]` that is not the private key's own
*
* @see {@linkcode exportPkcs8Der} for the inverse operation
* @see {@linkcode importPkcs8Pem} for PEM input
* @see {@linkcode importEncryptedPkcs8Der} for encrypted PKCS#8
*/
async function importPkcs8DerOrThrow(e, t) {
	let n;
	try {
		n = parsePkcs8PrivateKey(e);
	} catch (e) {
		throw rethrowDecodeRefusal(e, i), Error("Malformed PKCS#8 private key");
	}
	let i$1;
	t === void 0 ? i$1 = inferKeyImportInput(n, "Unsupported PKCS#8 private key algorithm") : (assertPkcs8MatchesRequestedAlgorithm(n, t), i$1 = t);
	let o;
	try {
		o = await getCrypto().subtle.importKey("pkcs8", new Uint8Array(n.v1Der), toImportAlgorithm(i$1), !0, privateKeyUsages(i$1));
	} catch {
		throw Error("Malformed PKCS#8 private key");
	}
	let s = n.declaredPublicKey;
	return s !== void 0 && await assertDeclaredPublicKeyMatches(o, s), o;
}
/**
* Reject a OneAsymmetricKey whose `publicKey [1]` field is not the public key of
* its own `privateKey`.
*
* RFC 8410 Appendix A: "Key mismatch errors: If a public key is provided, it may
* not agree with the private key because either it is wrong or the wrong
* algorithm was used."
*/
async function assertDeclaredPublicKeyMatches(e, t) {
	let n = await exportSpkiDer(await derivePublicKey(e)), r = readSequenceChildren(n)[1];
	if (r === void 0 || r.tag !== 3) throw Error("Malformed PKCS#8 private key");
	let i = r.value.slice(1);
	if (i.length !== t.length || i.some((e, n) => e !== t[n])) throw Error("PKCS#8 publicKey does not match the private key");
}
/**
* Import a private key from DER-encoded PKCS#8 PrivateKeyInfo.
*
* @see `importPkcs8DerOrThrow` for the throwing variant
*/
function importPkcs8Der(e, t) {
	return importResult(() => importPkcs8DerOrThrow(e, t));
}
/**
* Import a private key from PEM-encoded PKCS#8 PrivateKeyInfo.
*
* When `algorithm` is omitted, it is inferred from the key's own
* `privateKeyAlgorithm` (see {@linkcode importPkcs8DerOrThrow}).
*
* @example
* ```ts
* const key = await importPkcs8PemOrThrow(pemString, { kind: 'ecdsa', curve: 'P-256' });
* const inferred = await importPkcs8PemOrThrow(pemString);
* ```
*/
function importPkcs8PemOrThrow(e, t) {
	return importPkcs8DerOrThrow(pemDecodeOrThrow("PRIVATE KEY", e), t);
}
/**
* Import a private key from PEM-encoded PKCS#8 PrivateKeyInfo.
*
* @see `importPkcs8PemOrThrow` for the throwing variant
*/
function importPkcs8Pem(e, t) {
	return importResult(() => importPkcs8PemOrThrow(e, t));
}
/**
* Import a private key from DER-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.
*
* Decrypts the PBES2 envelope using the provided password, then imports the key.
*
* When `algorithm` is omitted, it is inferred from the decrypted key's own
* `privateKeyAlgorithm` (see {@linkcode importPkcs8DerOrThrow}).
*
* @param der - DER-encoded EncryptedPrivateKeyInfo bytes
* @param password - Decryption password
* @param algorithm - Optional expected algorithm; must match decrypted key when given
* @param options - KDF work-factor limit
*
* @throws {Error} If DER is malformed, password is wrong, the PBKDF2 iteration
* count exceeds `options.maxKdfIterations`, or algorithm doesn't match
*
* @see {@linkcode exportEncryptedPkcs8Der} for the inverse operation
*/
async function importEncryptedPkcs8DerOrThrow(e, t, n, r) {
	return await importEncryptedPkcs8WithBudget(e, t, n, createKdfBudget(r));
}
async function importEncryptedPkcs8WithBudget(e, t, n, r) {
	let i = readEncryptedPkcs8Envelope(e), a = await decryptPbes2(i.algorithmIdentifierDer, i.encryptedData, t, r);
	return assertDecryptedPrivateKey(() => parsePkcs8PrivateKey(a), "Invalid password or encrypted content"), importPkcs8DerOrThrow(a, n);
}
/** Splits a DER `EncryptedPrivateKeyInfo` into its AlgorithmIdentifier DER and encryptedData bytes. */
function readEncryptedPkcs8Envelope(e) {
	let t;
	try {
		t = readSequenceChildren(e);
	} catch (e) {
		throw rethrowDecodeRefusal(e, i), Error("Malformed EncryptedPrivateKeyInfo");
	}
	let n = t[0], i$2 = t[1];
	if (t.length !== 2 || n === void 0 || i$2 === void 0 || i$2.tag !== 4) throw Error("Malformed EncryptedPrivateKeyInfo");
	return {
		algorithmIdentifierDer: e.slice(n.start - n.headerLength, n.end),
		encryptedData: i$2.value
	};
}
/**
* Reads the PBES2 encryption parameters of a DER PKCS#8
* `EncryptedPrivateKeyInfo` (RFC 5958 §3) without the password: PBKDF2
* iteration count, salt, and PRF, plus the AES-CBC variant and IV.
* Throws on malformed DER, a non-PBES2 encryption algorithm, or a PBKDF2
* iteration count outside 1 to 4294967295.
*/
function inspectEncryptedPkcs8Der(e) {
	return parsePbes2AlgorithmIdentifier(readEncryptedPkcs8Envelope(e).algorithmIdentifierDer);
}
/**
* Import a private key from DER-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.
*
* @see `importEncryptedPkcs8DerOrThrow` for the throwing variant
*/
function importEncryptedPkcs8Der(e, t, n, r) {
	return encryptedImportResult(() => importEncryptedPkcs8DerOrThrow(e, t, n, r));
}
/**
* Import a private key from PEM-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.
*
* When `algorithm` is omitted, it is inferred from the decrypted key's own
* `privateKeyAlgorithm` (see {@linkcode importPkcs8DerOrThrow}).
*
* @example
* ```ts
* const key = await importEncryptedPkcs8PemOrThrow(pem, 'secret', { kind: 'rsa' });
* const inferred = await importEncryptedPkcs8PemOrThrow(pem, 'secret');
* ```
*/
async function importEncryptedPkcs8PemOrThrow(e, t, n, r) {
	let i = createKdfBudget(r);
	return await importEncryptedPkcs8WithBudget(pemDecodeOrThrow("ENCRYPTED PRIVATE KEY", e), t, n, i);
}
/**
* Import a private key from PEM-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.
*
* @see `importEncryptedPkcs8PemOrThrow` for the throwing variant
*/
function importEncryptedPkcs8Pem(e, t, n, r) {
	return encryptedImportResult(() => importEncryptedPkcs8PemOrThrow(e, t, n, r));
}
/**
* Import an RSA private key from DER-encoded PKCS#1 RSAPrivateKey.
*
* PKCS#1 is the legacy RSA-only format. Internally converts to PKCS#8 for import.
*
* @see {@linkcode exportPkcs1Der} for the inverse operation
* @see {@linkcode importPkcs1Pem} for PEM input
*/
function importPkcs1DerOrThrow(e, t = { kind: "rsa" }) {
	return importPkcs8DerOrThrow(wrapPkcs1InPkcs8(e), t);
}
/**
* Import an RSA private key from DER-encoded PKCS#1 RSAPrivateKey.
*
* @see `importPkcs1DerOrThrow` for the throwing variant
*/
function importPkcs1Der(e, t = { kind: "rsa" }) {
	return importResult(() => importPkcs1DerOrThrow(e, t));
}
/**
* Import an RSA private key from PEM-encoded PKCS#1 RSAPrivateKey.
*
* Expects the `-----BEGIN RSA PRIVATE KEY-----` PEM label.
*
* @see {@linkcode exportPkcs1Pem} for the inverse operation
* @see {@linkcode importEncryptedPkcs1Pem} for encrypted PEM
*/
function importPkcs1PemOrThrow(e, t = { kind: "rsa" }) {
	return importPkcs1DerOrThrow(pemDecodeOrThrow("RSA PRIVATE KEY", e), t);
}
/**
* Import an RSA private key from PEM-encoded PKCS#1 RSAPrivateKey.
*
* @see `importPkcs1PemOrThrow` for the throwing variant
*/
function importPkcs1Pem(e, t = { kind: "rsa" }) {
	return importResult(() => importPkcs1PemOrThrow(e, t));
}
/**
* Import an RSA private key from legacy `Proc-Type: 4,ENCRYPTED` PEM (PKCS#1).
*
* Decrypts OpenSSL's traditional PEM encryption format.
*
* @see {@linkcode exportEncryptedPkcs1Pem} for the inverse operation
* @see {@linkcode importEncryptedPkcs8Pem} for modern PBES2 encryption
*/
async function importEncryptedPkcs1PemOrThrow(e, t, n = { kind: "rsa" }) {
	let r = await decryptTraditionalPem("RSA PRIVATE KEY", e, t);
	return assertDecryptedPrivateKey(() => parsePkcs1PrivateKey(r), "Invalid password or encrypted PEM content"), importPkcs1DerOrThrow(r, n);
}
/**
* Import an RSA private key from legacy `Proc-Type: 4,ENCRYPTED` PEM (PKCS#1).
*
* @see `importEncryptedPkcs1PemOrThrow` for the throwing variant
*/
function importEncryptedPkcs1Pem(e, t, n = { kind: "rsa" }) {
	return encryptedImportResult(() => importEncryptedPkcs1PemOrThrow(e, t, n));
}
/**
* Import a private key from base64-encoded PKCS#8 PrivateKeyInfo (no PEM headers).
*
* @see {@linkcode exportBinaryBase64} for the inverse operation
* @see {@linkcode importPkcs8Pem} for PEM input with headers
*/
function importPkcs8Base64OrThrow(e, t) {
	let n;
	try {
		n = base64Decode(e);
	} catch {
		throw Error("Invalid base64 PKCS#8 private key");
	}
	return importPkcs8DerOrThrow(n, t);
}
/**
* Import a private key from base64-encoded PKCS#8 PrivateKeyInfo (no PEM headers).
*
* @see `importPkcs8Base64OrThrow` for the throwing variant
*/
function importPkcs8Base64(e, t) {
	return importResult(() => importPkcs8Base64OrThrow(e, t));
}
/**
* Import an EC private key from DER-encoded SEC 1 ECPrivateKey.
*
* SEC 1 is the legacy EC-only format. Internally converts to PKCS#8 for import.
* When the ECPrivateKey carries the optional RFC 5915 `parameters [0]` field
* (OpenSSL always writes it), its named-curve OID must match `algorithm.curve`;
* when the field is absent, the caller-supplied curve is trusted.
*
* When `algorithm` is omitted, the curve is inferred from the embedded
* `parameters [0]` field; a key without a supported named curve then fails.
*
* @throws {Error} If DER is not an ECPrivateKey, its embedded curve doesn't
* match `algorithm`, or no curve is available (neither embedded nor supplied)
*
* @see {@linkcode exportSec1Der} for the inverse operation
* @see {@linkcode importSec1Pem} for PEM input
*/
async function importSec1DerOrThrow(e, t) {
	let n;
	try {
		n = parseSec1PrivateKey(e);
	} catch (e) {
		throw rethrowDecodeRefusal(e, i), Error("Malformed SEC 1 private key");
	}
	let i$3;
	return t === void 0 ? i$3 = inferSec1ImportInput(n) : (assertSec1MatchesRequestedAlgorithm(n, t), i$3 = t), await importPkcs8DerOrThrow(wrapSec1InPkcs8(e, i$3.curve), i$3);
}
/**
* Import an EC private key from DER-encoded SEC 1 ECPrivateKey.
*
* @see `importSec1DerOrThrow` for the throwing variant
*/
function importSec1Der(e, t) {
	return importResult(() => importSec1DerOrThrow(e, t));
}
/**
* Import an EC private key from PEM-encoded SEC 1 ECPrivateKey.
*
* Expects the `-----BEGIN EC PRIVATE KEY-----` PEM label. When `algorithm` is
* omitted, the curve is inferred from the embedded `parameters [0]` field
* (see {@linkcode importSec1DerOrThrow}).
*
* @see {@linkcode exportSec1Pem} for the inverse operation
* @see {@linkcode importEncryptedSec1Pem} for encrypted PEM
*/
function importSec1PemOrThrow(e, t) {
	return importSec1DerOrThrow(pemDecodeOrThrow("EC PRIVATE KEY", e), t);
}
/**
* Import an EC private key from PEM-encoded SEC 1 ECPrivateKey.
*
* @see `importSec1PemOrThrow` for the throwing variant
*/
function importSec1Pem(e, t) {
	return importResult(() => importSec1PemOrThrow(e, t));
}
/**
* Import an EC private key from legacy `Proc-Type: 4,ENCRYPTED` PEM (SEC 1).
*
* Decrypts OpenSSL's traditional PEM encryption format.
*
* @see {@linkcode exportEncryptedSec1Pem} for the inverse operation
* @see {@linkcode importEncryptedPkcs8Pem} for modern PBES2 encryption
*/
async function importEncryptedSec1PemOrThrow(e, t, n) {
	let r = await decryptTraditionalPem("EC PRIVATE KEY", e, t);
	return assertDecryptedPrivateKey(() => parseSec1PrivateKey(r), "Invalid password or encrypted PEM content"), importSec1DerOrThrow(r, n);
}
/**
* Import an EC private key from legacy `Proc-Type: 4,ENCRYPTED` PEM (SEC 1).
*
* @see `importEncryptedSec1PemOrThrow` for the throwing variant
*/
function importEncryptedSec1Pem(e, t, n) {
	return encryptedImportResult(() => importEncryptedSec1PemOrThrow(e, t, n));
}
/**
* Import a public verification key from a JSON Web Key.
*
* When `algorithm` is omitted, it is inferred from the JWK's own `kty`, `crv`,
* and `alg` members (e.g. `PS256` → RSA-PSS/SHA-256, `RSA-OAEP-256` →
* RSA-OAEP/SHA-256; an RSA JWK without `alg` defaults to PKCS#1 v1.5 with
* SHA-256). Pass `algorithm` to additionally assert an expected algorithm.
*
* @param jwk - JSON Web Key object with public key components
* @param algorithm - Optional expected algorithm; must match JWK's `kty` and `crv` when given
* @returns Extractable CryptoKey with `verify` usage
*
* @throws {Error} If JWK is malformed, encodes an unsupported algorithm, or doesn't match `algorithm`
*
* @see {@linkcode exportPublicJwk} for the inverse operation
*/
async function importPublicJwkOrThrow(e, t) {
	let n = t ?? inferJwkImportInput(e);
	assertPublicJwkMatchesRequestedAlgorithm(e, n);
	try {
		return await getCrypto().subtle.importKey("jwk", e, toImportAlgorithm(n), !0, publicKeyUsages(n));
	} catch {
		throw Error("Malformed public JWK");
	}
}
/**
* Import a public verification key from a JSON Web Key.
*
* @see `importPublicJwkOrThrow` for the throwing variant
*/
function importPublicJwk(e, t) {
	return importResult(() => importPublicJwkOrThrow(e, t));
}
/**
* Import a private signing key from a JSON Web Key.
*
* When `algorithm` is omitted, it is inferred from the JWK's own `kty`, `crv`,
* and `alg` members (see {@linkcode importPublicJwkOrThrow}).
*
* @param jwk - JSON Web Key object with private key components
* @param algorithm - Optional expected algorithm; must match JWK's `kty` and `crv` when given
* @returns Extractable CryptoKey with `sign` usage
*
* @throws {Error} If JWK is malformed, lacks private key material, encodes an
* unsupported algorithm, or doesn't match `algorithm`
*
* @example
* ```ts
* const jwk = { kty: 'EC', crv: 'P-256', x: '...', y: '...', d: '...' };
* const key = await importPrivateJwkOrThrow(jwk, { kind: 'ecdsa', curve: 'P-256' });
* const inferred = await importPrivateJwkOrThrow(jwk);
* ```
*
* @see {@linkcode exportPrivateJwk} for the inverse operation
*/
async function importPrivateJwkOrThrow(e, t) {
	let n = t ?? inferJwkImportInput(e);
	assertPrivateJwkMatchesRequestedAlgorithm(e, n);
	try {
		return await getCrypto().subtle.importKey("jwk", e, toImportAlgorithm(n), !0, privateKeyUsages(n));
	} catch {
		throw Error("Malformed private JWK");
	}
}
/**
* Import a private signing key from a JSON Web Key.
*
* @see `importPrivateJwkOrThrow` for the throwing variant
*/
function importPrivateJwk(e, t) {
	return importResult(() => importPrivateJwkOrThrow(e, t));
}
/**
* Encrypt a small message with an RSA-OAEP public key.
*
* The key must have been generated or imported with `{ kind: 'rsa', scheme: 'oaep' }`.
* RSA-OAEP encrypts at most modulus bytes − 2 × hash bytes − 2 per call
* (190 bytes for a 2048-bit key with SHA-256) — encrypt a symmetric key, not
* bulk data.
*
* @param publicKey - RSA-OAEP public `CryptoKey` with `encrypt` usage
* @param plaintext - Message bytes, at most the OAEP capacity of the key
* @param options - Optional OAEP label bound to the ciphertext
*
* @throws {Error} If the key is not an RSA-OAEP public encryption key, or the
* plaintext exceeds the key's OAEP capacity
*
* @example
* ```ts
* const keys = await generateKeyPair({ kind: 'rsa', scheme: 'oaep' });
* const ciphertext = await encryptRsaOaepOrThrow(
* 	keys.publicKey,
* 	new TextEncoder().encode('session key'),
* );
* ```
*
* @see {@linkcode decryptRsaOaepOrThrow} for the inverse operation
* @see `encryptRsaOaep` for the Result-returning variant
*/
async function encryptRsaOaepOrThrow(e, n, r = {}) {
	let i = validateRsaOaepKey(e, "public", "encrypt");
	if (i !== void 0) throw Error(i);
	try {
		return new Uint8Array(await getCrypto().subtle.encrypt(toRsaOaepParams(r), e, toArrayBuffer(n)));
	} catch (e) {
		throw rethrowIfInvariant(e), Error("Plaintext exceeds the RSA-OAEP capacity of the key (modulus bytes − 2 × hash bytes − 2)");
	}
}
/**
* Encrypt a small message with an RSA-OAEP public key.
*
* @example
* ```ts
* const keys = await generateKeyPair({ kind: 'rsa', scheme: 'oaep' });
* const encrypted = await encryptRsaOaep(keys.publicKey, plaintext);
* if (!encrypted.ok) {
* 	// encrypted.code: 'invalid_key' | 'message_too_long'
* 	throw new Error(encrypted.message);
* }
* const ciphertext = encrypted.value;
* ```
*
* @see `encryptRsaOaepOrThrow` for the throwing variant
*/
async function encryptRsaOaep(r, i, a = {}) {
	let o = validateRsaOaepKey(r, "public", "encrypt");
	if (o !== void 0) return failureResult("invalid_key", o);
	try {
		return successResult(await encryptRsaOaepOrThrow(r, i, a));
	} catch (n) {
		return rethrowIfInvariant(n), failureResult("message_too_long", n instanceof Error ? n.message : "Plaintext exceeds the RSA-OAEP capacity");
	}
}
/**
* Decrypt an RSA-OAEP ciphertext with the matching private key.
*
* The key must have been generated or imported with `{ kind: 'rsa', scheme: 'oaep' }`,
* and `options.label` must repeat the label used at encryption time (if any).
*
* @param privateKey - RSA-OAEP private `CryptoKey` with `decrypt` usage
* @param ciphertext - Ciphertext produced by {@linkcode encryptRsaOaep} (or any RSA-OAEP encryptor)
* @param options - OAEP label matching the one bound at encryption
*
* @throws {Error} If the key is not an RSA-OAEP private decryption key, or
* decryption fails — wrong key, wrong label, or corrupted ciphertext (OAEP
* deliberately does not reveal which)
*
* @example
* ```ts
* const plaintext = await decryptRsaOaepOrThrow(keys.privateKey, ciphertext);
* ```
*
* @see {@linkcode encryptRsaOaepOrThrow} for the inverse operation
* @see `decryptRsaOaep` for the Result-returning variant
*/
async function decryptRsaOaepOrThrow(e, n, r = {}) {
	let i = validateRsaOaepKey(e, "private", "decrypt");
	if (i !== void 0) throw Error(i);
	try {
		return new Uint8Array(await getCrypto().subtle.decrypt(toRsaOaepParams(r), e, toArrayBuffer(n)));
	} catch (e) {
		throw rethrowIfInvariant(e), Error("RSA-OAEP decryption failed: wrong key, wrong label, or corrupted ciphertext");
	}
}
/**
* Decrypt an RSA-OAEP ciphertext with the matching private key.
*
* @example
* ```ts
* const decrypted = await decryptRsaOaep(keys.privateKey, ciphertext);
* if (!decrypted.ok) {
* 	// decrypted.code: 'invalid_key' | 'decryption_failed'
* 	throw new Error(decrypted.message);
* }
* const plaintext = decrypted.value;
* ```
*
* @see `decryptRsaOaepOrThrow` for the throwing variant
*/
async function decryptRsaOaep(r, i, a = {}) {
	let o = validateRsaOaepKey(r, "private", "decrypt");
	if (o !== void 0) return failureResult("invalid_key", o);
	try {
		return successResult(await decryptRsaOaepOrThrow(r, i, a));
	} catch (n) {
		return rethrowIfInvariant(n), failureResult("decryption_failed", n instanceof Error ? n.message : "RSA-OAEP decryption failed");
	}
}
/** Map a {@linkcode KeyAlgorithmInput} to the WebCrypto `generateKey` algorithm parameter. */
function toGenerateKeyAlgorithm(e) {
	switch (e.kind) {
		case "rsa": return {
			name: rsaSchemeToWebCryptoAlgorithmName(e.scheme),
			modulusLength: e.modulusLength ?? 2048,
			publicExponent: Uint8Array.of(1, 0, 1),
			hash: e.hash ?? "SHA-256"
		};
		case "ecdsa": return {
			name: "ECDSA",
			namedCurve: e.curve ?? "P-256"
		};
		case "ed25519": return { name: "Ed25519" };
		default: throw Error(`Unhandled KeyAlgorithmInput kind: ${String(e)}`);
	}
}
/** Map a {@linkcode PublicKeyImportInput} to the WebCrypto `importKey` algorithm parameter. */
function toImportAlgorithm(e) {
	switch (e.kind) {
		case "rsa": return {
			name: rsaSchemeToWebCryptoAlgorithmName(e.scheme),
			hash: e.hash ?? "SHA-256"
		};
		case "ecdsa": return {
			name: "ECDSA",
			namedCurve: e.curve
		};
		case "ed25519": return { name: "Ed25519" };
		default: throw Error(`Unhandled PublicKeyImportInput kind: ${String(e)}`);
	}
}
/**
* Rejects decrypted plaintext that is not the private-key structure it should be.
*
* PBES2 and traditional PEM both encrypt with unauthenticated AES-CBC, where a
* wrong key clears the padding check roughly once in every 256 attempts and
* yields random plaintext. Structure is the only integrity signal left, so
* plaintext that fails to parse means the password was wrong or the ciphertext
* was corrupted, not that the enclosing input was malformed.
*/
function assertDecryptedPrivateKey(e, t) {
	try {
		e();
	} catch (e) {
		throw rethrowDecodeRefusal(e, i), wrongPasswordError(t);
	}
}
/** Structural check for a PKCS#1 RSAPrivateKey, including optional multiprime fields. */
function parsePkcs1PrivateKey(e) {
	let t = readSequenceChildren(e), n = t[0];
	if (n === void 0 || n.tag !== 2 || n.value.length !== 1 || !t.slice(1, 9).every((e) => e.tag === 2)) throw Error("Malformed PKCS#1 private key");
	let r = n.value[0];
	if (r === 0 && t.length === 9) return;
	let i = t[9];
	if (r !== 1 || t.length !== 10 || i === void 0 || !isOtherPrimeInfosShape(e, i)) throw Error("Malformed PKCS#1 private key");
}
/** RFC 8017 Appendix A.1.2: OtherPrimeInfos is a non-empty SEQUENCE OF three-INTEGER entries. */
function isOtherPrimeInfosShape(e, t) {
	if (t.tag !== 48) return !1;
	let n = e.slice(t.start - t.headerLength, t.end), r = readSequenceChildren(n);
	return r.length !== 0 && r.every((e) => {
		if (e.tag !== 48) return !1;
		let t = readSequenceChildren(n.slice(e.start - e.headerLength, e.end));
		return t.length === 3 && t.every((e) => e.tag === 2);
	});
}
/** Extract algorithm OID and inner key bytes from a PKCS#8 PrivateKeyInfo envelope. */
function parsePkcs8PrivateKey(e) {
	let t = readSequenceChildren(e), n = t[0], r = t[1], i = t[2];
	if (t.length < 3 || n === void 0 || n.tag !== 2 || r === void 0 || r.tag !== 48 || i === void 0 || i.tag !== 4) throw Error("Malformed PKCS#8 private key");
	let a = validateOneAsymmetricKeyTail(t.slice(3));
	if (readPkcs8Version(n.value) !== (a === void 0 ? 0 : 1)) throw Error("Malformed PKCS#8 private key");
	let o = e.slice(r.start - r.headerLength, r.end), c = readSequenceChildren(o), l = c[0];
	if (l === void 0 || l.tag !== 6 || c.length < 1 || c.length > 2) throw Error("Malformed PKCS#8 private key");
	let d = c[1], m = decodeObjectIdentifier(l.value);
	return I.includes(m) && assertCurvePrivateKey(i.value), {
		algorithmOid: m,
		...d === void 0 ? {} : { parametersTag: d.tag },
		...d?.tag === 6 ? { parametersOid: decodeObjectIdentifier(d.value) } : {},
		privateKeyDer: i.value,
		v1Der: t.length === 3 ? e : sequence([
			integer(Uint8Array.of(0)),
			o,
			octetString(i.value)
		]),
		...a === void 0 ? {} : { declaredPublicKey: a }
	};
}
/** Algorithms whose `privateKey` field holds an RFC 8410 §7 `CurvePrivateKey`. */
const I = [
	t$1.x25519,
	t$1.x448,
	t$1.ed25519,
	t$1.ed448
];
/**
* Reject a `privateKey` field that does not hold exactly one DER `CurvePrivateKey`.
*
* RFC 8410 §7: "when encoding a OneAsymmetricKey object, the private key is
* wrapped in a CurvePrivateKey object and wrapped by the OCTET STRING of the
* 'privateKey' field", and `CurvePrivateKey ::= OCTET STRING`.
*/
function assertCurvePrivateKey(e) {
	if (readRootElement(e).tag !== 4) throw Error("Malformed PKCS#8 private key");
}
/**
* Validate the OneAsymmetricKey tail after `privateKey` and return the
* `publicKey [1]` octets when the field is present.
*
* RFC 5958 §2 encodes `attributes [0]` as an IMPLICIT constructed `SET OF`
* (tag `A0`); RFC 8410 §7 adds `publicKey [1]` as an IMPLICIT primitive
* `BIT STRING` (tag `81`) after it. Each appears at most once and in that order.
* The type's two X.680 extensibility markers admit later additions, which take
* the next context-specific numbers, so `[2]` and above are tolerated and every
* other class is malformed.
*/
function validateOneAsymmetricKeyTail(e) {
	let t = !1, n, r = !1;
	for (let i of e) {
		let e = (i.tag & 192) == 128 ? i.tagNumber : -1;
		if (e === 0) {
			if (t || n !== void 0 || r || i.tag !== 160) throw Error("Malformed PKCS#8 private key");
			assertOneAsymmetricKeyAttributes(i.value), t = !0;
		} else if (e === 1) {
			if (n !== void 0 || r || i.tag !== 129) throw Error("Malformed PKCS#8 private key");
			n = readPublicKeyBitString(i.value);
		} else if (e >= 2) r = !0;
		else throw Error("Malformed PKCS#8 private key");
	}
	return n;
}
/**
* Reject an `attributes [0]` field that does not hold a `SET OF Attribute`.
*
* RFC 5958 §2 types the field `Attributes ::= SET OF Attribute`, over the
* `Attribute ::= SEQUENCE { attrType OBJECT IDENTIFIER, attrValues SET OF
* AttributeValue }` of RFC 5652 §5.3. The implicit tag has replaced the SET OF
* tag, so the members are read back under a universal constructed one.
*/
function assertOneAsymmetricKeyAttributes(e) {
	let t = tlv(48, e);
	for (let e of readSequenceChildren(t)) {
		if (e.tag !== 48) throw Error("Malformed PKCS#8 private key");
		let n = readSequenceChildren(t.slice(e.start - e.headerLength, e.end)), r = n[0], i = n[1];
		if (n.length !== 2 || r === void 0 || r.tag !== 6 || i === void 0 || i.tag !== 49) throw Error("Malformed PKCS#8 private key");
	}
}
/** Reject a `publicKey [1]` BIT STRING that is not octet-aligned or carries no key octets. */
function readPublicKeyBitString(e) {
	if (e.length < 2 || e[0] !== 0) throw Error("Malformed PKCS#8 private key");
	return e.slice(1);
}
/** Decode the canonical RFC 5958 version INTEGER content, `v1(0)` or `v2(1)`. */
function readPkcs8Version(e) {
	let t = e[0];
	if (e.length !== 1 || t !== 0 && t !== 1) throw Error("Malformed PKCS#8 private key");
	return t;
}
/**
* Extract the optional `parameters [0]` curve identifier from a SEC 1 ECPrivateKey.
*
* RFC 5915 §3: `ECPrivateKey ::= SEQUENCE { version INTEGER { ecPrivkeyVer1(1) }
* (ecPrivkeyVer1), privateKey OCTET STRING, parameters [0] ECParameters
* {{ NamedCurve }} OPTIONAL, publicKey [1] BIT STRING OPTIONAL }`.
*/
function parseSec1PrivateKey(e) {
	let t = readSequenceChildren(e), n = t[0], r = t[1], i = t[2], a = t[3];
	if (t.length < 2 || t.length > 4 || n === void 0 || n.tag !== 2 || n.value.length !== 1 || n.value[0] !== 1 || r === void 0 || r.tag !== 4 || i !== void 0 && i.tag !== 160 && i.tag !== 161 || a !== void 0 && (i?.tag !== 160 || a.tag !== 161)) throw Error("Malformed SEC 1 private key");
	let o = i?.tag === 160 ? i : void 0;
	if (o === void 0) return {};
	let s = readRootElement(o.value);
	return {
		parametersTag: s.tag,
		...s.tag === 6 ? { parametersOid: decodeObjectIdentifier(s.value) } : {}
	};
}
/**
* Ensure a SEC 1 ECPrivateKey carries the RFC 5915 `parameters [0]` named
* curve. WebCrypto's PKCS#8 export omits it from the inner ECPrivateKey (the
* curve lives in the envelope's privateKeyAlgorithm), but RFC 5915 wants it in
* standalone SEC 1 — and OpenSSL always writes it. Injecting it keeps exports
* self-describing, so they re-import without an explicit curve.
*/
function ensureSec1NamedCurveParameters(e, t) {
	let n = readSequenceChildren(e);
	if (n.some((e) => e.tag === 160)) return new Uint8Array(e);
	if (t === void 0) throw Error("SEC1 export requires a named curve in the PKCS#8 privateKeyAlgorithm");
	let raw = (t) => e.slice(t.start - t.headerLength, t.end);
	return sequence([
		...n.slice(0, 2).map(raw),
		explicitContext(0, objectIdentifier(t)),
		...n.slice(2).map(raw)
	]);
}
/** Wrap a PKCS#1 RSAPrivateKey in a PKCS#8 PrivateKeyInfo envelope for WebCrypto import. */
function wrapPkcs1InPkcs8(e) {
	return sequence([
		Uint8Array.of(2, 1, 0),
		sequence([objectIdentifier(t$1.rsaEncryption), nullValue()]),
		octetString(new Uint8Array(e))
	]);
}
/** Wrap a SEC 1 ECPrivateKey in a PKCS#8 PrivateKeyInfo envelope for WebCrypto import. */
function wrapSec1InPkcs8(e, t) {
	return sequence([
		Uint8Array.of(2, 1, 0),
		sequence([objectIdentifier(t$1.ecPublicKey), objectIdentifier(curveToOid(t))]),
		octetString(new Uint8Array(e))
	]);
}
/** Project a private JWK onto its public-only members, discarding private key material. */
function toPublicJwk(e, t) {
	if (e.kty !== "RSA" && e.kty !== "EC" && e.kty !== "OKP") throw Error(`Cannot derive public key: unsupported JWK key type ${String(e.kty)}`);
	let n = { ...e };
	for (let e of [
		"d",
		"p",
		"q",
		"dp",
		"dq",
		"qi",
		"oth",
		"k"
	]) delete n[e];
	return n.key_ops = [t], n.ext = !0, n;
}
/**
* Single source of truth for the NIST curve ↔ named-curve OID mapping, read in
* both directions by {@linkcode curveToOid} and {@linkcode oidToCurve}.
*/
const L = [
	["P-256", t$1.prime256v1],
	["P-384", t$1.secp384r1],
	["P-521", t$1.secp521r1]
];
/** Map a curve name to its ASN.1 OID string. */
function curveToOid(e) {
	for (let [t, n] of L) if (t === e) return n;
	throw Error(`Unsupported EC curve: ${e}`);
}
/** Map an ASN.1 curve OID string back to its curve name, or `undefined` if unrecognized. */
function oidToCurve(e) {
	for (let [t, n] of L) if (n === e) return t;
}
/** Map an {@linkcode RsaScheme} to the WebCrypto algorithm name string. */
function rsaSchemeToWebCryptoAlgorithmName(e) {
	return e === "pss" ? "RSA-PSS" : e === "oaep" ? "RSA-OAEP" : "RSASSA-PKCS1-v1_5";
}
/** `true` when the algorithm input selects RSA-OAEP, whose keys carry encrypt/decrypt usages. */
function isRsaOaepInput(e) {
	return e.kind === "rsa" && e.scheme === "oaep";
}
/** Key usages for an imported public key: `verify`, or `encrypt` for RSA-OAEP. */
function publicKeyUsages(e) {
	return isRsaOaepInput(e) ? ["encrypt"] : ["verify"];
}
/** Key usages for an imported private key: `sign`, or `decrypt` for RSA-OAEP. */
function privateKeyUsages(e) {
	return isRsaOaepInput(e) ? ["decrypt"] : ["sign"];
}
/**
* Diagnose a key unfit for the given RSA-OAEP operation.
*
* Returns a human-readable problem description, or `undefined` when the key is
* usable — keeping key-level failures (`'invalid_key'`) separable from
* ciphertext-level failures before WebCrypto is ever called.
*/
function validateRsaOaepKey(e, t, n) {
	let r = n === "encrypt" ? "encryption" : "decryption";
	if (e.type !== t) return `RSA-OAEP ${r} requires a ${t} CryptoKey`;
	if (e.algorithm.name !== "RSA-OAEP") return `RSA-OAEP ${r} requires an RSA-OAEP key (got ${e.algorithm.name}); generate or import the key with scheme: 'oaep'`;
	if (!e.usages.includes(n)) return `RSA-OAEP ${r} requires a key with '${n}' usage`;
}
/** Build the WebCrypto RSA-OAEP params, attaching the optional label. */
function toRsaOaepParams(e) {
	return {
		name: "RSA-OAEP",
		...e.label === void 0 ? {} : { label: toArrayBuffer(e.label) }
	};
}
/** Encrypt DER key material as an OpenSSL-style `Proc-Type: 4,ENCRYPTED` PEM block. */
async function encryptTraditionalPem(e, t, n) {
	let r = n.iv ?? getCrypto().getRandomValues(/* @__PURE__ */ new Uint8Array(16));
	if (r.length !== 16) throw Error("Traditional PEM encryption requires a 16-byte IV");
	let i = n.cipher ?? "AES-256-CBC", a = await importTraditionalPemAesKey(n.password, r.slice(0, 8), i, ["encrypt"]), o = new Uint8Array(await getCrypto().subtle.encrypt({
		name: "AES-CBC",
		iv: toArrayBuffer(r)
	}, a, toArrayBuffer(t))), s = base64Encode(o).match(/.{1,64}/g)?.join("\n") ?? "";
	return [
		`-----BEGIN ${e}-----`,
		"Proc-Type: 4,ENCRYPTED",
		`DEK-Info: ${i},${toHex(r).toUpperCase()}`,
		"",
		s,
		`-----END ${e}-----`
	].join("\n");
}
/** Decrypt a `Proc-Type: 4,ENCRYPTED` PEM block, RFC 1421 §4.6 headers, to plaintext DER. */
async function decryptTraditionalPem(e, t, n) {
	let r = parseTraditionalPemOrThrow(t);
	if (r.label !== e) throw Error(`Expected ${e} PEM block`);
	let i = r.headers.get("DEK-Info"), a = r.headers.get("Proc-Type");
	if (a === void 0 || !isEncryptedProcType(a) || i === void 0) throw Error("Traditional PEM encryption headers missing");
	let [o, s] = i.split(",").map(trimLwsp);
	if (!isTraditionalPemCipher(o) || s === void 0) throw Error("Only AES-128-CBC, AES-192-CBC, and AES-256-CBC traditional PEM encryption is supported");
	if (!isTraditionalPemIvHex(s)) throw Error("Traditional PEM encryption requires a 16-byte IV encoded as 32 hex characters");
	let c = hexToBytes(s), l = await importTraditionalPemAesKey(n, c.slice(0, 8), o, ["decrypt"]);
	try {
		return new Uint8Array(await getCrypto().subtle.decrypt({
			name: "AES-CBC",
			iv: toArrayBuffer(c)
		}, l, toArrayBuffer(base64Decode(r.base64Body))));
	} catch {
		throw wrongPasswordError("Invalid password or encrypted PEM content");
	}
}
/** Derive and import an AES-CBC key for legacy PEM encryption using OpenSSL `EVP_BytesToKey`. */
function importTraditionalPemAesKey(e, t, n, r) {
	let i = traditionalPemCipherKeyLength(n), a = opensslBytesToKey(e, t, i / 8);
	return getCrypto().subtle.importKey("raw", toArrayBuffer(a), {
		name: "AES-CBC",
		length: i
	}, !1, r);
}
/**
* RFC 1421 §4.6.1.1 `Proc-Type: 4,ENCRYPTED`.
*
* Fields are trimmed because RFC 822 §3.1.1 unfolding leaves an LWSP-char
* wherever the header was folded.
*/
function isEncryptedProcType(e) {
	let t = e.split(",");
	return t.length === 2 && trimLwsp(t[0] ?? "") === "4" && trimLwsp(t[1] ?? "") === "ENCRYPTED";
}
/** Type guard for the three AES-CBC ciphers supported by legacy PEM encryption. */
function isTraditionalPemCipher(e) {
	return e === "AES-128-CBC" || e === "AES-192-CBC" || e === "AES-256-CBC";
}
function isTraditionalPemIvHex(e) {
	return e.length === 32 && /^[0-9A-Fa-f]+$/.test(e);
}
/** Return the AES key size in bits for a given cipher name. */
function traditionalPemCipherKeyLength(e) {
	switch (e) {
		case "AES-128-CBC": return 128;
		case "AES-192-CBC": return 192;
		case "AES-256-CBC": return 256;
		default: throw Error(`Unhandled traditional PEM cipher: ${String(e)}`);
	}
}
/** OpenSSL `EVP_BytesToKey` with MD5 — derives a fixed-length key from password + salt. */
function opensslBytesToKey(e, t, n) {
	let r = new TextEncoder().encode(e), i = [], a = /* @__PURE__ */ new Uint8Array(), o = 0;
	for (; o < n;) {
		let e = new Uint8Array(a.length + r.length + t.length);
		e.set(a, 0), e.set(r, a.length), e.set(t, a.length + r.length), a = md5(e), i.push(a), o += a.length;
	}
	let s = new Uint8Array(n), c = 0;
	for (let e of i) {
		let t = e.slice(0, Math.min(e.length, n - c));
		if (s.set(t, c), c += t.length, c >= n) break;
	}
	return s;
}
function parseSpkiDer(e) {
	try {
		let t = readSequenceChildren(e);
		if (t.length !== 2) throw Error("Malformed SubjectPublicKeyInfo");
		let n = t[0], r = t[1];
		if (n === void 0 || n.tag !== 48 || r === void 0 || r.tag !== 3) throw Error("Malformed SubjectPublicKeyInfo");
		extractBitStringValue(r);
		let i = readSequenceChildren(e.slice(n.start - n.headerLength, n.end)), a = i[0];
		if (a === void 0 || a.tag !== 6 || i.length < 1 || i.length > 2) throw Error("Malformed SubjectPublicKeyInfo");
		let o = i[1];
		return {
			algorithmOid: decodeObjectIdentifier(a.value),
			...o === void 0 ? {} : { parametersTag: o.tag },
			...o?.tag === 6 ? { parametersOid: decodeObjectIdentifier(o.value) } : {}
		};
	} catch (e) {
		throw rethrowDecodeRefusal(e, i), Error("Malformed SubjectPublicKeyInfo");
	}
}
/**
* Derive the import algorithm from a key envelope's own AlgorithmIdentifier
* (SPKI `algorithm` or PKCS#8 `privateKeyAlgorithm` — both share the shape).
*
* RSA keys default to the `pkcs1-v1_5`/`SHA-256` import parameters (a plain
* `rsaEncryption` AlgorithmIdentifier does not encode padding scheme or hash);
* EC keys carry their curve in the DER; Ed25519 is fully determined by its OID.
*/
function inferKeyImportInput(e, t) {
	switch (e.algorithmOid) {
		case t$1.rsaEncryption:
			if (e.parametersTag === void 0 || e.parametersTag === 5) return { kind: "rsa" };
			break;
		case t$1.ecPublicKey: {
			let t = e.parametersTag === 6 && e.parametersOid !== void 0 ? oidToCurve(e.parametersOid) : void 0;
			if (t !== void 0) return {
				kind: "ecdsa",
				curve: t
			};
			break;
		}
		case t$1.ed25519: if (e.parametersTag === void 0) return { kind: "ed25519" };
	}
	throw Error(t);
}
/**
* Derive the import curve from a SEC 1 ECPrivateKey's own RFC 5915
* `parameters [0]` field. SEC 1 encodes no algorithm family (it is EC by
* definition), so only the named curve needs recovering — and it may be
* absent, in which case the caller must supply it.
*/
function inferSec1ImportInput(e) {
	let t = e.parametersTag === 6 && e.parametersOid !== void 0 ? oidToCurve(e.parametersOid) : void 0;
	if (t === void 0) throw Error("SEC 1 private key does not encode a supported named curve; pass the algorithm explicitly");
	return {
		kind: "ecdsa",
		curve: t
	};
}
/**
* Derive the import algorithm from a JWK's own `kty`, `crv`, and `alg` members.
*
* `alg` disambiguates the RSA scheme and hash (`RS*`, `PS*`, `RSA-OAEP-*`) —
* WebCrypto rejects a JWK whose `alg` disagrees with the import algorithm, so
* it must be honored rather than defaulted over. An RSA JWK without `alg`
* defaults to `pkcs1-v1_5`/`SHA-256`, mirroring SPKI inference.
*/
function inferJwkImportInput(e) {
	if (e.kty === "RSA") return rsaImportInputFromJwkAlg(e.alg);
	if (e.kty === "EC") {
		if (e.crv === "P-256" || e.crv === "P-384" || e.crv === "P-521") return {
			kind: "ecdsa",
			curve: e.crv
		};
		throw Error(`Unsupported EC JWK curve: ${String(e.crv)}`);
	}
	if (e.kty === "OKP" && e.crv === "Ed25519") return { kind: "ed25519" };
	throw Error("Unsupported JWK key type");
}
/** Map a JWA `alg` identifier to the RSA scheme + hash it pins down. */
function rsaImportInputFromJwkAlg(e) {
	switch (e) {
		case void 0:
		case "RS256": return { kind: "rsa" };
		case "RS384": return {
			kind: "rsa",
			hash: "SHA-384"
		};
		case "RS512": return {
			kind: "rsa",
			hash: "SHA-512"
		};
		case "PS256": return {
			kind: "rsa",
			scheme: "pss"
		};
		case "PS384": return {
			kind: "rsa",
			scheme: "pss",
			hash: "SHA-384"
		};
		case "PS512": return {
			kind: "rsa",
			scheme: "pss",
			hash: "SHA-512"
		};
		case "RSA-OAEP-256": return {
			kind: "rsa",
			scheme: "oaep"
		};
		case "RSA-OAEP-384": return {
			kind: "rsa",
			scheme: "oaep",
			hash: "SHA-384"
		};
		case "RSA-OAEP-512": return {
			kind: "rsa",
			scheme: "oaep",
			hash: "SHA-512"
		};
		default: throw Error(`Unsupported RSA JWK alg: ${e}`);
	}
}
function assertSpkiMatchesRequestedAlgorithm(e, t) {
	switch (t.kind) {
		case "rsa":
			if (e.algorithmOid !== t$1.rsaEncryption || e.parametersTag !== void 0 && e.parametersTag !== 5) throw Error("SubjectPublicKeyInfo algorithm does not match requested import algorithm");
			return;
		case "ecdsa":
			if (e.algorithmOid !== t$1.ecPublicKey || e.parametersTag !== 6 || e.parametersOid !== curveToOid(t.curve)) throw Error("SubjectPublicKeyInfo algorithm does not match requested import algorithm");
			return;
		case "ed25519":
			if (e.algorithmOid !== t$1.ed25519 || e.parametersTag !== void 0) throw Error("SubjectPublicKeyInfo algorithm does not match requested import algorithm");
			return;
		default: throw Error(`Unhandled PublicKeyImportInput kind: ${String(t)}`);
	}
}
function assertPkcs8MatchesRequestedAlgorithm(e, t) {
	switch (t.kind) {
		case "rsa":
			if (e.algorithmOid !== t$1.rsaEncryption || e.parametersTag !== void 0 && e.parametersTag !== 5) throw Error("PKCS#8 private key algorithm does not match requested import algorithm");
			return;
		case "ecdsa":
			if (e.algorithmOid !== t$1.ecPublicKey || e.parametersTag !== 6 || e.parametersOid !== curveToOid(t.curve)) throw Error("PKCS#8 private key algorithm does not match requested import algorithm");
			return;
		case "ed25519":
			if (e.algorithmOid !== t$1.ed25519 || e.parametersTag !== void 0) throw Error("PKCS#8 private key algorithm does not match requested import algorithm");
			return;
		default: throw Error(`Unhandled PrivateKeyImportInput kind: ${String(t)}`);
	}
}
function assertSec1MatchesRequestedAlgorithm(e, t) {
	if (e.parametersTag !== void 0 && (e.parametersTag !== 6 || e.parametersOid !== curveToOid(t.curve))) throw Error("SEC 1 private key curve does not match requested import algorithm");
}
function assertPublicJwkMatchesRequestedAlgorithm(e, t) {
	if (e.k !== void 0 || e.d !== void 0 || e.p !== void 0 || e.q !== void 0 || e.dp !== void 0 || e.dq !== void 0 || e.qi !== void 0 || e.oth !== void 0) throw Error("Public JWK must not contain private key material");
	switch (t.kind) {
		case "rsa":
			if (e.kty !== "RSA" || typeof e.n != "string" || typeof e.e != "string") throw Error("Public JWK algorithm does not match requested import algorithm");
			return;
		case "ecdsa":
			if (e.kty !== "EC" || e.crv !== t.curve || typeof e.x != "string" || typeof e.y != "string") throw Error("Public JWK algorithm does not match requested import algorithm");
			return;
		case "ed25519":
			if (e.kty !== "OKP" || e.crv !== "Ed25519" || typeof e.x != "string") throw Error("Public JWK algorithm does not match requested import algorithm");
			return;
		default: throw Error(`Unhandled PublicKeyImportInput kind: ${String(t)}`);
	}
}
function assertPrivateJwkMatchesRequestedAlgorithm(e, t) {
	if (e.k !== void 0 || e.oth !== void 0) throw Error("Private JWK must not contain symmetric or multi-prime key material");
	if (typeof e.d != "string") throw Error("Private JWK must contain private key material");
	switch (t.kind) {
		case "rsa":
			if (e.kty !== "RSA" || typeof e.n != "string" || typeof e.e != "string" || typeof e.p != "string" || typeof e.q != "string" || typeof e.dp != "string" || typeof e.dq != "string" || typeof e.qi != "string") throw Error("Private JWK algorithm does not match requested import algorithm");
			return;
		case "ecdsa":
			if (e.kty !== "EC" || e.crv !== t.curve || typeof e.x != "string" || typeof e.y != "string") throw Error("Private JWK algorithm does not match requested import algorithm");
			return;
		case "ed25519":
			if (e.kty !== "OKP" || e.crv !== "Ed25519" || typeof e.x != "string") throw Error("Private JWK algorithm does not match requested import algorithm");
			return;
		default: throw Error(`Unhandled PrivateKeyImportInput kind: ${String(t)}`);
	}
}
export { importSpkiPemOrThrow as $, importPkcs1Der as A, importPrivateJwk as B, importEncryptedPkcs1PemOrThrow as C, importEncryptedPkcs8PemOrThrow as D, importEncryptedPkcs8Pem as E, importPkcs8Base64OrThrow as F, importSec1DerOrThrow as G, importPublicJwk as H, importPkcs8Der as I, importSpkiBase64 as J, importSec1Pem as K, importPkcs8DerOrThrow as L, importPkcs1Pem as M, importPkcs1PemOrThrow as N, importEncryptedSec1Pem as O, importPkcs8Base64 as P, importSpkiPem as Q, importPkcs8Pem as R, importEncryptedPkcs1Pem as S, importEncryptedPkcs8DerOrThrow as T, importPublicJwkOrThrow as U, importPrivateJwkOrThrow as V, importSec1Der as W, importSpkiDer as X, importSpkiBase64OrThrow as Y, importSpkiDerOrThrow as Z, exportSec1Der as _, encryptRsaOaepOrThrow as a, encryptPbes2 as at, exportSpkiPem as b, exportEncryptedPkcs8Der as c, isKdfIterationLimitError as ct, exportPkcs1Der as d, parsePbes2AlgorithmIdentifier as dt, inspectEncryptedPkcs8Der as et, exportPkcs1Pem as f, sha1 as ft, exportPublicJwk as g, exportPrivateJwk as h, encryptRsaOaep as i, derivePbkdf2Bytes as it, importPkcs1DerOrThrow as j, importEncryptedSec1PemOrThrow as k, exportEncryptedPkcs8Pem as l, isWrongPasswordError as lt, exportPkcs8Pem as m, t$1 as mt, decryptRsaOaepOrThrow as n, createKdfBudget as nt, exportBinaryBase64 as o, f as ot, exportPkcs8Der as p, getCrypto as pt, importSec1PemOrThrow as q, derivePublicKey as r, decryptPbes2 as rt, exportEncryptedPkcs1Pem as s, h as st, decryptRsaOaep as t, chargeKdfBudget as tt, exportEncryptedSec1Pem as u, p as ut, exportSec1Pem as v, importEncryptedPkcs8Der as w, generateKeyPair as x, exportSpkiDer as y, importPkcs8PemOrThrow as z };
