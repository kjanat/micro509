/**
 * Canonical PEM boundary surface.
 * Owns the stable `micro509/pem` entrypoint.
 * @module
 */

export type { CategorizedPemBlocks, PemBlock } from './pem.ts';
export { categorizePemBlocks, pemDecode, pemEncode, splitPemBlocks } from './pem.ts';
