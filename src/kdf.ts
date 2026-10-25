/**
 * Optional byte-oriented Argon2 key derivation with explicit resource limits.
 * Import this entrypoint directly. Certificate APIs do not load it.
 *
 * @module micro509/kdf
 */

export type {
	Argon2Algorithm,
	Argon2Backend,
	Argon2ErrorCode,
	Argon2Input,
	Argon2Limits,
	Argon2Options,
	Argon2Result,
	Argon2Version,
} from '#micro509/kdf/argon2';
export { deriveArgon2 } from '#micro509/kdf/argon2';
