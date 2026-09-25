import { describe, expect, it } from 'bun:test';
import type { NameConstraints, SubjectAltName } from '#micro509';
import {
	createCertificate,
	generateKeyPair,
	isResultError,
	parseCertificateDerOrThrow,
	verifyCertificateChain,
} from '#micro509';
import {
	concatBytes,
	explicitContext,
	implicitConstructedContext,
	objectIdentifier,
	sequence,
	utf8String,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { encodeExtension } from '#micro509/x509';
import {
	appendCertificateExtensions,
	createSelfSignedCertificateWithRawExtensions,
	flattenedText,
	legacyMailboxNameConstraints,
	rfcDir,
} from '#test/helpers';

const rfc9598 = await flattenedText(`${rfcDir}/rfc9598.txt`);

const ROOT_NAME = 'RFC 9598 Root';

async function constrainedRoot(nameConstraints: NameConstraints | Uint8Array) {
	return createSelfSignedCertificateWithRawExtensions({
		subject: { commonName: ROOT_NAME },
		extensions: {
			basicConstraints: { ca: true },
			keyUsage: ['keyCertSign', 'cRLSign'],
			...(nameConstraints instanceof Uint8Array
				? {
						customExtensions: [
							{ oid: OIDS.nameConstraints, value: nameConstraints, critical: true },
						],
					}
				: { nameConstraints }),
		},
	});
}

type Root = Awaited<ReturnType<typeof constrainedRoot>>;

async function leafWith(root: Root, subjectAltNames?: readonly SubjectAltName[]) {
	const keys = await generateKeyPair();
	const leaf = await createCertificate({
		issuer: { commonName: ROOT_NAME },
		subject: { commonName: 'rfc9598-leaf' },
		publicKey: keys.publicKey,
		signerPrivateKey: root.keyPair.privateKey,
		issuerPublicKey: root.keyPair.publicKey,
		...(subjectAltNames === undefined ? {} : { extensions: { subjectAltNames } }),
	});
	return leaf.der;
}

function mailbox(value: string): SubjectAltName {
	return { type: 'smtpUtf8Mailbox', value };
}

function builderErrorCode(run: () => Promise<unknown>): Promise<string | undefined> {
	return run().then(
		() => undefined,
		(error: unknown) => (isResultError(error) ? error.code : undefined),
	);
}

async function verdict(root: Root, leaf: Uint8Array): Promise<string> {
	const result = await verifyCertificateChain({ leaf, roots: [root.certificate.der] });
	return result.ok ? 'ok' : result.code;
}

describe('RFC 9598 §3: the SmtpUTF8Mailbox otherName', () => {
	it('prints the sentences this suite relies on', () => {
		expect(rfc9598).toContain('id-on-SmtpUTF8Mailbox OBJECT IDENTIFIER ::= { id-on 9 }');
		expect(rfc9598).toContain(
			'The UTF8String encoding MUST NOT contain a Byte Order Mark (BOM) [RFC3629] to aid consistency across implementations, particularly for comparison.',
		);
	});

	it('encodes and parses an internationalized mailbox', async () => {
		const root = await constrainedRoot({
			excludedSubtrees: [{ base: { type: 'dns', value: 'x' } }],
		});
		const leaf = parseCertificateDerOrThrow(await leafWith(root, [mailbox('用户@example.com')]));
		expect(leaf.subjectAltNames).toEqual([mailbox('用户@example.com')]);
	});

	it('refuses a mailbox that breaks the §3 value rules', async () => {
		const root = await constrainedRoot({
			excludedSubtrees: [{ base: { type: 'dns', value: 'x' } }],
		});
		for (const value of ['user@example.com', `${String.fromCharCode(0x01)}@example.com`]) {
			expect(await builderErrorCode(() => leafWith(root, [mailbox(value)]))).toBe(
				'smtp_utf8_mailbox_ascii_local_part',
			);
		}
		for (const value of [
			'用户@EXAMPLE.com',
			`${String.fromCharCode(0xfeff)}用户@example.com`,
			'用户',
			'用户@',
			'用户@-bad.com',
			'用户@bad-.com',
			'用户@a..com',
			'用户@.',
			'用户@ab--c.com',
			`用户@${'a'.repeat(64)}.com`,
		]) {
			expect(await builderErrorCode(() => leafWith(root, [mailbox(value)]))).toBe(
				'invalid_smtp_utf8_mailbox',
			);
		}
	});
});

describe('RFC 9598 §3 and §4: the mailbox domain is IDNA2008 in A-labels', () => {
	it('prints the sentences this suite relies on', () => {
		expect(rfc9598).toContain(
			'labels that include non-ASCII characters MUST be stored in A-label (rather than U-label) form',
		);
		expect(rfc9598).toContain(
			'all email address domains in X.509 certificates MUST conform to IDNA2008',
		);
	});

	it('stores a U-label domain as its A-labels', async () => {
		const root = await constrainedRoot({
			excludedSubtrees: [{ base: { type: 'dns', value: 'x' } }],
		});
		const leaf = parseCertificateDerOrThrow(await leafWith(root, [mailbox('用户@bücher.example')]));
		expect(leaf.subjectAltNames).toEqual([mailbox('用户@xn--bcher-kva.example')]);
	});

	it('refuses a domain that is not valid IDNA2008', async () => {
		const root = await constrainedRoot({
			excludedSubtrees: [{ base: { type: 'dns', value: 'x' } }],
		});
		for (const value of ['用户@\u265a.example', '用户@xn--45h.example', '用户@xn--abc.example']) {
			expect(await builderErrorCode(() => leafWith(root, [mailbox(value)]))).toBe('invalid_idn');
		}
	});
});

describe('RFC 9598 §6: rfc822Name name constraints apply to SmtpUTF8Mailbox by domain', () => {
	it('prints the sentences this suite relies on', () => {
		expect(rfc9598).toContain(
			'This section updates Section 4.2.1.10 of [RFC5280] to extend rfc822Name name constraints to SmtpUTF8Mailbox subjectAltNames.',
		);
		expect(rfc9598).toContain(
			'Strip the Local-part and "@" separator from each rfc822Name and SmtpUTF8Mailbox, which leaves just the domain part.',
		);
	});

	it('enforces a permitted rfc822Name subtree', async () => {
		const root = await constrainedRoot({
			permittedSubtrees: [{ base: { type: 'email', value: 'example.com' } }],
		});
		expect(await verdict(root, await leafWith(root, [mailbox('用户@example.com')]))).toBe('ok');
		expect(await verdict(root, await leafWith(root, [mailbox('用户@evil.example')]))).toBe(
			'name_constraints_violated',
		);
	});

	it('enforces an excluded rfc822Name subtree, with a leading "." as a domain suffix', async () => {
		const root = await constrainedRoot({
			excludedSubtrees: [{ base: { type: 'email', value: '.evil.example' } }],
		});
		expect(await verdict(root, await leafWith(root, [mailbox('用户@mail.evil.example')]))).toBe(
			'name_constraints_violated',
		);
		expect(await verdict(root, await leafWith(root, [mailbox('用户@evil.example')]))).toBe('ok');
	});

	it('compares only the domain of a pre-RFC 9549 constraint that names a mailbox', async () => {
		const root = await constrainedRoot(
			legacyMailboxNameConstraints('permitted', 'root@example.com'),
		);
		expect(await verdict(root, await leafWith(root, [mailbox('用户@example.com')]))).toBe('ok');
	});

	it('rejects a received mailbox whose domain is not in A-labels while rfc822Name constraints apply', async () => {
		const root = await constrainedRoot({
			permittedSubtrees: [{ base: { type: 'email', value: 'xn--bcher-kva.example' } }],
		});
		const otherName = implicitConstructedContext(
			0,
			concatBytes([
				objectIdentifier(OIDS.idOnSmtpUtf8Mailbox),
				explicitContext(0, utf8String('用户@bücher.example')),
			]),
		);
		const leaf = await appendCertificateExtensions(await leafWith(root), root.keyPair.privateKey, [
			encodeExtension(OIDS.subjectAltName, sequence([otherName]), false),
		]);
		expect(parseCertificateDerOrThrow(leaf).subjectAltNames).toEqual([
			mailbox('用户@bücher.example'),
		]);
		expect(await verdict(root, leaf)).toBe('name_constraints_violated');
	});

	it('rejects a received domain that only lowercases to ASCII', async () => {
		const kelvin = String.fromCharCode(0x212a);
		const root = await constrainedRoot({
			permittedSubtrees: [{ base: { type: 'email', value: 'kexample.com' } }],
		});
		const otherName = implicitConstructedContext(
			0,
			concatBytes([
				objectIdentifier(OIDS.idOnSmtpUtf8Mailbox),
				explicitContext(0, utf8String(`用户@${kelvin}example.com`)),
			]),
		);
		const leaf = await appendCertificateExtensions(await leafWith(root), root.keyPair.privateKey, [
			encodeExtension(OIDS.subjectAltName, sequence([otherName]), false),
		]);
		expect(`${kelvin}example.com`.toLowerCase()).toBe('kexample.com');
		expect(await verdict(root, leaf)).toBe('name_constraints_violated');
	});

	it('rejects a received domain that is not NR-LDH labels and A-labels', async () => {
		const cases = [
			{ constraint: 'excludedSubtrees', value: '用户@host.example.com.' },
			{ constraint: 'permittedSubtrees', value: '用户@host..example.com' },
			{ constraint: 'permittedSubtrees', value: '用户@_host.example.com' },
			{ constraint: 'permittedSubtrees', value: '用户@xn--45h.example.com' },
		] as const;
		for (const { constraint, value } of cases) {
			const root = await constrainedRoot({
				[constraint]: [{ base: { type: 'email', value: '.example.com' } }],
			});
			const otherName = implicitConstructedContext(
				0,
				concatBytes([
					objectIdentifier(OIDS.idOnSmtpUtf8Mailbox),
					explicitContext(0, utf8String(value)),
				]),
			);
			const leaf = await appendCertificateExtensions(
				await leafWith(root),
				root.keyPair.privateKey,
				[encodeExtension(OIDS.subjectAltName, sequence([otherName]), false)],
			);
			expect(await verdict(root, leaf)).toBe('name_constraints_violated');
		}
	});

	it('compares a received uppercase domain after lowercasing it', async () => {
		const root = await constrainedRoot({
			permittedSubtrees: [{ base: { type: 'email', value: '.example.com' } }],
		});
		const otherName = implicitConstructedContext(
			0,
			concatBytes([
				objectIdentifier(OIDS.idOnSmtpUtf8Mailbox),
				explicitContext(0, utf8String('用户@HOST.XN--BCHER-KVA.example.com')),
			]),
		);
		const leaf = await appendCertificateExtensions(await leafWith(root), root.keyPair.privateKey, [
			encodeExtension(OIDS.subjectAltName, sequence([otherName]), false),
		]);
		expect(await verdict(root, leaf)).toBe('ok');
	});

	it('keeps a leading Byte Order Mark visible to the customExtensions profile check', async () => {
		const root = await constrainedRoot({
			excludedSubtrees: [{ base: { type: 'dns', value: 'x' } }],
		});
		const otherName = implicitConstructedContext(
			0,
			concatBytes([
				objectIdentifier(OIDS.idOnSmtpUtf8Mailbox),
				explicitContext(0, utf8String(`${String.fromCharCode(0xfeff)}用户@example.com`)),
			]),
		);
		expect(
			await builderErrorCode(async () => {
				const keys = await generateKeyPair();
				return createCertificate({
					issuer: { commonName: ROOT_NAME },
					subject: { commonName: 'rfc9598-leaf' },
					publicKey: keys.publicKey,
					signerPrivateKey: root.keyPair.privateKey,
					issuerPublicKey: root.keyPair.publicKey,
					extensions: {
						customExtensions: [{ oid: OIDS.subjectAltName, value: sequence([otherName]) }],
					},
				});
			}),
		).toBe('invalid_smtp_utf8_mailbox');
	});
});
