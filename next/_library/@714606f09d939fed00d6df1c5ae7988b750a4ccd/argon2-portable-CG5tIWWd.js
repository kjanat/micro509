// ../../dist/kdf/argon2-arithmetic.js
/**
* Exact high word of an unsigned 32×32 product; `low` is Math.imul(a, b).
*
* Subtracting the exact low word leaves a multiple of 2^32 with at most 2048
* units of floating-point error. Scaling by 2^32 reduces that error below
* 2^-20, so adding 0.5 and truncating recovers the exact integer high word.
* BlaMka already computes the low word and passes it here for reuse.
*/
function multiplyHigh(e, t, n) {
	return (e * t - (n >>> 0)) / 4294967296 + .5 >>> 0;
}
// ../../dist/kdf/argon2-memory.js
/** Reuse wiped matrices without preventing garbage collection of idle storage. */
function createMatrixPool() {
	let e = [];
	return {
		take(t) {
			for (let n = e.length - 1; n >= 0; --n) {
				let r = e[n]?.deref();
				if ((r === void 0 || r.length === t) && (e.splice(n, 1), r !== void 0)) return r;
			}
			return new Uint32Array(t);
		},
		release(t) {
			t.fill(0), t.length !== 0 && (e.length === 4 && e.shift(), e.push(new WeakRef(t)));
		}
	};
}
// ../../dist/kdf/argon2-core.js
const n = createMatrixPool();
const r = 18446744073709551615n;
const i = [
	7640891576956012808n,
	13503953896175478587n,
	4354685564936845355n,
	11912009170470909681n,
	5840696475078001361n,
	11170449401992604703n,
	2270897969802886507n,
	6620516959819538809n
];
const a = [
	[
		0,
		1,
		2,
		3,
		4,
		5,
		6,
		7,
		8,
		9,
		10,
		11,
		12,
		13,
		14,
		15
	],
	[
		14,
		10,
		4,
		8,
		9,
		15,
		13,
		6,
		1,
		12,
		0,
		2,
		11,
		7,
		5,
		3
	],
	[
		11,
		8,
		12,
		0,
		5,
		2,
		15,
		13,
		10,
		14,
		3,
		6,
		7,
		1,
		9,
		4
	],
	[
		7,
		9,
		3,
		1,
		13,
		12,
		11,
		14,
		2,
		6,
		5,
		10,
		4,
		0,
		15,
		8
	],
	[
		9,
		0,
		5,
		7,
		2,
		4,
		10,
		15,
		14,
		1,
		11,
		12,
		6,
		8,
		3,
		13
	],
	[
		2,
		12,
		6,
		10,
		0,
		11,
		8,
		3,
		4,
		13,
		7,
		5,
		15,
		14,
		1,
		9
	],
	[
		12,
		5,
		1,
		15,
		14,
		13,
		4,
		10,
		0,
		7,
		6,
		3,
		9,
		2,
		8,
		11
	],
	[
		13,
		11,
		7,
		14,
		12,
		1,
		3,
		9,
		5,
		0,
		15,
		4,
		8,
		6,
		2,
		10
	],
	[
		6,
		15,
		14,
		9,
		11,
		3,
		0,
		8,
		12,
		2,
		13,
		7,
		1,
		4,
		10,
		5
	],
	[
		10,
		2,
		8,
		4,
		7,
		6,
		1,
		5,
		15,
		11,
		9,
		14,
		3,
		12,
		13,
		0
	],
	[
		0,
		1,
		2,
		3,
		4,
		5,
		6,
		7,
		8,
		9,
		10,
		11,
		12,
		13,
		14,
		15
	],
	[
		14,
		10,
		4,
		8,
		9,
		15,
		13,
		6,
		1,
		12,
		0,
		2,
		11,
		7,
		5,
		3
	]
];
const o = [
	[
		0,
		4,
		8,
		12
	],
	[
		1,
		5,
		9,
		13
	],
	[
		2,
		6,
		10,
		14
	],
	[
		3,
		7,
		11,
		15
	],
	[
		0,
		5,
		10,
		15
	],
	[
		1,
		6,
		11,
		12
	],
	[
		2,
		7,
		8,
		13
	],
	[
		3,
		4,
		9,
		14
	]
];
function read32(e, t) {
	return ((e[t] ?? 0) | (e[t + 1] ?? 0) << 8 | (e[t + 2] ?? 0) << 16 | (e[t + 3] ?? 0) << 24) >>> 0;
}
function write32(e, t, n) {
	e[t] = n & 255, e[t + 1] = n >>> 8 & 255, e[t + 2] = n >>> 16 & 255, e[t + 3] = n >>> 24;
}
function read64(e, t) {
	let n = 0n;
	for (let r = 7; r >= 0; --r) n = n << 8n | BigInt(e[t + r] ?? 0);
	return n;
}
function concat(...e) {
	let t = new Uint8Array(e.reduce((e, t) => e + t.length, 0)), n = 0;
	for (let r of e) t.set(r, n), n += r.length;
	return t;
}
function blakeMix(e, t, n, i, a, o, s) {
	e[t] = (e[t] ?? 0n) + (e[n] ?? 0n) + o & r, e[a] = rotateRight((e[a] ?? 0n) ^ (e[t] ?? 0n), 32), e[i] = (e[i] ?? 0n) + (e[a] ?? 0n) & r, e[n] = rotateRight((e[n] ?? 0n) ^ (e[i] ?? 0n), 24), e[t] = (e[t] ?? 0n) + (e[n] ?? 0n) + s & r, e[a] = rotateRight((e[a] ?? 0n) ^ (e[t] ?? 0n), 16), e[i] = (e[i] ?? 0n) + (e[a] ?? 0n) & r, e[n] = rotateRight((e[n] ?? 0n) ^ (e[i] ?? 0n), 63);
}
function rotateRight(e, t) {
	let n = BigInt(t);
	return (e >> n | e << 64n - n) & r;
}
function blakeRound(e, t, n) {
	for (let [r, [i, a, s, c]] of o.entries()) blakeMix(e, i, a, s, c, t[n[r * 2] ?? 0] ?? 0n, t[n[r * 2 + 1] ?? 0] ?? 0n);
}
function blake2bCompress(e, t, n, o) {
	let s = Array.from({ length: 16 }, (e, n) => read64(t, n * 8)), c = [...e, ...i];
	try {
		c[12] = (c[12] ?? 0n) ^ n & r, c[13] = (c[13] ?? 0n) ^ n >> 64n, o && (c[14] = (c[14] ?? 0n) ^ r);
		for (let e of a) blakeRound(c, s, e);
		for (let t = 0; t < 8; t += 1) e[t] = (e[t] ?? 0n) ^ (c[t] ?? 0n) ^ (c[t + 8] ?? 0n);
	} finally {
		s.fill(0n), c.fill(0n);
	}
}
function blake2b(e, t) {
	let n = [...i], r = /* @__PURE__ */ new Uint8Array(128);
	try {
		n[0] = (n[0] ?? 0n) ^ (16842752n | BigInt(t));
		let i = 0;
		for (; e.length - i > 128;) blake2bCompress(n, e.subarray(i, i + 128), BigInt(i + 128), !1), i += 128;
		r.set(e.subarray(i)), blake2bCompress(n, r, BigInt(e.length), !0);
		let a = new Uint8Array(t);
		for (let e = 0; e < t; e += 1) a[e] = Number((n[Math.floor(e / 8)] ?? 0n) >> BigInt(e % 8 * 8) & 255n);
		return a;
	} finally {
		n.fill(0n), r.fill(0);
	}
}
function blakeLong(e, t) {
	let n = concat(Uint8Array.from([
		t & 255,
		t >>> 8 & 255,
		t >>> 16 & 255,
		t >>> 24
	]), e), r = /* @__PURE__ */ new Uint8Array();
	try {
		if (t <= 64) return blake2b(n, t);
		r = blake2b(n, 64);
		let e = new Uint8Array(t), i = 0;
		for (; t - i > 64;) if (e.set(r.subarray(0, 32), i), i += 32, t - i > 64) {
			let e = blake2b(r, 64);
			r.fill(0), r = e;
		}
		let a = blake2b(r, t - i);
		try {
			return e.set(a, i), e;
		} finally {
			a.fill(0);
		}
	} finally {
		n.fill(0), r.fill(0);
	}
}
function initialHash(e, t) {
	let n = e.password, r = e.salt, i = e.secret ?? /* @__PURE__ */ new Uint8Array(), a = e.associatedData ?? /* @__PURE__ */ new Uint8Array(), o = /* @__PURE__ */ new Uint8Array(28), s = [
		e.parallelism,
		e.outputBytes,
		e.memoryKiB,
		e.passes,
		e.version,
		t,
		n.length
	], c = 0;
	for (let e of s) write32(o, c, e), c += 4;
	let l = /* @__PURE__ */ new Uint8Array(12);
	write32(l, 0, r.length), write32(l, 4, i.length), write32(l, 8, a.length);
	let u = concat(o.subarray(0, 28), n, l.subarray(0, 4), r, l.subarray(4, 8), i, l.subarray(8, 12), a);
	try {
		return blake2b(u, 64);
	} finally {
		u.fill(0);
	}
}
function argonMix(t, n, r, i, a) {
	let o = t[n] ?? 0, s = (t[n + 1] ?? 0) | 0, c = t[r] ?? 0, l = (t[r + 1] ?? 0) | 0, u = t[i] ?? 0, d = (t[i + 1] ?? 0) | 0, f = t[a] ?? 0, p = (t[a + 1] ?? 0) | 0, m, h, g, _;
	m = Math.imul(o, c), h = o + c + (m << 1 >>> 0), s = s + l + (multiplyHigh(o, c, m) << 1 | m >>> 31) + (h / 4294967296 | 0) | 0, o = h >>> 0, g = f ^ o, _ = p ^ s, f = _ >>> 0, p = g | 0, m = Math.imul(u, f), h = u + f + (m << 1 >>> 0), d = d + p + (multiplyHigh(u, f, m) << 1 | m >>> 31) + (h / 4294967296 | 0) | 0, u = h >>> 0, g = c ^ u, _ = l ^ d, c = (g >>> 24 | _ << 8) >>> 0, l = _ >>> 24 | g << 8, m = Math.imul(o, c), h = o + c + (m << 1 >>> 0), s = s + l + (multiplyHigh(o, c, m) << 1 | m >>> 31) + (h / 4294967296 | 0) | 0, o = h >>> 0, g = f ^ o, _ = p ^ s, f = (g >>> 16 | _ << 16) >>> 0, p = _ >>> 16 | g << 16, m = Math.imul(u, f), h = u + f + (m << 1 >>> 0), d = d + p + (multiplyHigh(u, f, m) << 1 | m >>> 31) + (h / 4294967296 | 0) | 0, u = h >>> 0, g = c ^ u, _ = l ^ d, c = (g << 1 | _ >>> 31) >>> 0, l = _ << 1 | g >>> 31, t[n] = o, t[n + 1] = s, t[r] = c, t[r + 1] = l, t[i] = u, t[i + 1] = d, t[a] = f, t[a + 1] = p;
}
function argonRound(e, t, n, r) {
	argonMix(e, t, t + 2 * n, t + 4 * n, t + 6 * n), argonMix(e, t + r, t + 2 * n + r, t + 4 * n + r, t + 6 * n + r), argonMix(e, t + n, t + 3 * n, t + 5 * n, t + 7 * n), argonMix(e, t + n + r, t + 3 * n + r, t + 5 * n + r, t + 7 * n + r), argonMix(e, t, t + 2 * n + r, t + 5 * n, t + 7 * n + r), argonMix(e, t + r, t + 3 * n, t + 5 * n + r, t + 6 * n), argonMix(e, t + n, t + 3 * n + r, t + 4 * n, t + 6 * n + r), argonMix(e, t + n + r, t + 2 * n, t + 4 * n + r, t + 7 * n);
}
function permuteBlock(e) {
	for (let t = 0; t < 256; t += 32) argonRound(e, t, 4, 2);
	for (let t = 0; t < 32; t += 4) argonRound(e, t, 32, 2);
}
function fillBlock(e, t, n, r, i, a, o) {
	for (let r = 0; r < 256; r += 1) {
		let i = (e[t + r] ?? 0) ^ (e[n + r] ?? 0);
		a[r] = i, o[r] = i;
	}
	if (permuteBlock(o), i) for (let t = 0; t < 256; t += 1) e[r + t] = (a[t] ?? 0) ^ (o[t] ?? 0) ^ (e[r + t] ?? 0);
	else for (let t = 0; t < 256; t += 1) e[r + t] = (a[t] ?? 0) ^ (o[t] ?? 0);
}
function indexAlpha(t, n, r, i, a, o, s) {
	let c;
	c = t === 0 ? n === 0 ? r - 1 : n * a + (i ? r - 1 : r === 0 ? -1 : 0) : o - a + (i ? r - 1 : r === 0 ? -1 : 0);
	let l = multiplyHigh(s, s, Math.imul(s, s)), u = c - 1 - multiplyHigh(c, l, Math.imul(c, l));
	return ((t === 0 || n === 3 ? 0 : (n + 1) * a) + u) % o;
}
function dataIndependent(e, t, n) {
	return e === 1 || e === 2 && t === 0 && n < 2;
}
function compressBlocks(e, t, n, r, i) {
	for (let n = 0; n < 256; n += 1) {
		let a = (e[n] ?? 0) ^ (t[n] ?? 0);
		r[n] = a, i[n] = a;
	}
	permuteBlock(i);
	for (let e = 0; e < 256; e += 1) n[e] = (r[e] ?? 0) ^ (i[e] ?? 0);
}
function generateAddressBlock(e, t, n, r, i, a) {
	e[12] = (e[12] ?? 0) + 1 >>> 0, compressBlocks(n, e, a, r, i), compressBlocks(n, a, t, r, i);
}
function toWords(e) {
	let t = /* @__PURE__ */ new Uint32Array(256);
	for (let n = 0; n < 256; n += 1) t[n] = read32(e, n * 4);
	return t;
}
function fillIndexedBlock(e, t, n, r, i) {
	let { pass: a, slice: o, lane: s } = n, { memory: c, laneLength: l, segmentLength: u, original: d, permuted: f } = t, p = s * l + o * u + r, m = (p % l === 0 ? p + l - 1 : p - 1) * 256, h = i === void 0 ? m : r % 128 * 2, g = i ?? c, _ = g[h] ?? 0, v = (g[h + 1] ?? 0) % e.parallelism;
	a === 0 && o === 0 && (v = s);
	let y = indexAlpha(a, o, r, v === s, u, l, _), b = p * 256;
	fillBlock(c, m, (v * l + y) * 256, b, e.version !== 16 && a !== 0, d, f);
}
async function fillSegment(e, t, n, r) {
	let { pass: i, slice: a, lane: o } = r, { memoryBlocks: s, segmentLength: c, original: l, permuted: u, zero: d, addressTemporary: f } = n, p = dataIndependent(t, i, a), m = /* @__PURE__ */ new Uint32Array(256), h = /* @__PURE__ */ new Uint32Array(256);
	try {
		p && (m[0] = i, m[2] = o, m[4] = a, m[6] = s, m[8] = e.passes, m[10] = t);
		let g = i === 0 && a === 0 ? 2 : 0;
		p && g !== 0 && generateAddressBlock(m, h, d, l, u, f);
		for (let t = g; t < c; t += 512) {
			let i = new Promise((e) => setTimeout(e, 0)), a = Math.min(t + 512, c);
			for (let i = t; i < a; i += 1) p && i % 128 == 0 && generateAddressBlock(m, h, d, l, u, f), fillIndexedBlock(e, n, r, i, p ? h : void 0);
			await i;
		}
	} finally {
		m.fill(0), h.fill(0), f.fill(0);
	}
}
async function deriveArgon2TypeScript(e) {
	let t = {
		argon2d: 0,
		argon2i: 1,
		argon2id: 2
	}[e.algorithm], r = Math.floor(e.memoryKiB / (4 * e.parallelism)) * 4 * e.parallelism, i = r / e.parallelism, a = i / 4, o = /* @__PURE__ */ new Uint32Array(), s = /* @__PURE__ */ new Uint8Array(), c = /* @__PURE__ */ new Uint32Array(), l = /* @__PURE__ */ new Uint32Array(), u = /* @__PURE__ */ new Uint32Array(), d = /* @__PURE__ */ new Uint32Array(), f = /* @__PURE__ */ new Uint8Array(), p = /* @__PURE__ */ new Uint32Array();
	try {
		o = n.take(r * 256), s = initialHash(e, t), c = /* @__PURE__ */ new Uint32Array(256), l = /* @__PURE__ */ new Uint32Array(256), u = /* @__PURE__ */ new Uint32Array(256), d = /* @__PURE__ */ new Uint32Array(256);
		for (let t = 0; t < e.parallelism; t += 1) for (let e = 0; e < 2; e += 1) {
			let n = /* @__PURE__ */ new Uint8Array(8);
			write32(n, 0, e), write32(n, 4, t);
			let r = concat(s, n), a = /* @__PURE__ */ new Uint8Array(), c = /* @__PURE__ */ new Uint32Array();
			try {
				a = blakeLong(r, 1024), c = toWords(a), o.set(c, (t * i + e) * 256);
			} finally {
				r.fill(0), a.fill(0), c.fill(0);
			}
		}
		let m = {
			memory: o,
			memoryBlocks: r,
			laneLength: i,
			segmentLength: a,
			original: c,
			permuted: l,
			zero: u,
			addressTemporary: d
		};
		for (let n = 0; n < e.passes; n += 1) for (let r = 0; r < 4; r += 1) for (let i = 0; i < e.parallelism; i += 1) await fillSegment(e, t, m, {
			pass: n,
			slice: r,
			lane: i
		});
		f = /* @__PURE__ */ new Uint8Array(1024), p = toWords(f);
		for (let t = 0; t < e.parallelism; t += 1) {
			let e = (t * i + i - 1) * 256;
			for (let t = 0; t < 256; t += 1) p[t] = (p[t] ?? 0) ^ (o[e + t] ?? 0);
		}
		for (let e = 0; e < 256; e += 1) write32(f, e * 4, p[e] ?? 0);
		return blakeLong(f, e.outputBytes);
	} finally {
		s.fill(0), c.fill(0), l.fill(0), u.fill(0), d.fill(0), f.fill(0), p.fill(0), n.release(o);
	}
}
// ../../dist/kdf/argon2-portable.js
/** Internal TypeScript backend; the public boundary validates inputs and limits. */
async function portableArgon2(t) {
	return t.memoryKiB * 1024 + t.outputBytes + t.password.byteLength + t.salt.byteLength + (t.secret?.byteLength ?? 0) + (t.associatedData?.byteLength ?? 0) >= 2147483648 ? {
		ok: !1,
		error: {
			code: "unsupported",
			message: "Request exceeds portable Argon2 address space"
		}
	} : {
		ok: !0,
		value: await deriveArgon2TypeScript(t)
	};
}
export { portableArgon2 };
