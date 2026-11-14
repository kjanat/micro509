import { y as toHex } from "./asn1-jyOu_Jva.js";
// ../../dist/internal/crypto/prime-ec.js
/** Prime-field curve parameters and membership checks for public affine coordinates. @module */
/** Shared parameters, including those used to decompress SSH public points. */
const t = {
	"P-256": {
		size: 32,
		prime: 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n,
		b: 41058363725152142129326129780047268409114441015993725554835256314039467401291n
	},
	"P-384": {
		size: 48,
		prime: 2n ** 384n - 2n ** 128n - 2n ** 96n + 2n ** 32n - 1n,
		b: 27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575n
	},
	"P-521": {
		size: 66,
		prime: 2n ** 521n - 1n,
		b: 1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984n
	}
};
/**
* Checks fixed-width public coordinates before synchronous key selection. These curves have
* cofactor one; finite field coordinates satisfying the equation represent a valid public point.
* Signature operations and key import still run through WebCrypto.
*/
function isPrimeEcPoint(n, r, i) {
	let { size: a, prime: o, b: s } = t[n];
	if (r.length !== a || i.length !== a) return !1;
	let c = BigInt(`0x${toHex(r)}`), l = BigInt(`0x${toHex(i)}`);
	if (c >= o || l >= o) return !1;
	let u = (((c * c - 3n) * c + s) % o + o) % o;
	return l * l % o === u;
}
export { t as n, isPrimeEcPoint as t };
