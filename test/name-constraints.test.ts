import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
	verifyCertificateChain,
} from '#micro509';
import {
	objectIdentifier,
	printableString,
	sequence,
	setOf,
	utf8String,
} from '#micro509/internal/asn1/der.ts';
import { OIDS } from '#micro509/internal/asn1/oids.ts';

type TestDnStringEncoding = 'printable' | 'utf8';
type DirectoryNameAttribute = {
	readonly oid: string;
	readonly value: string;
	readonly encoding: TestDnStringEncoding;
};
type CreateCertificateInput = Parameters<typeof createCertificate>[0];
type CreateSelfSignedCertificateInput = Parameters<typeof createSelfSignedCertificate>[0];
type NameConstraintsInput = NonNullable<
	NonNullable<CreateSelfSignedCertificateInput['extensions']>['nameConstraints']
>;
type LeafSubject = CreateCertificateInput['subject'];
type LeafSubjectAltNames = NonNullable<
	NonNullable<CreateCertificateInput['extensions']>['subjectAltNames']
>;

function encodeDirectoryNameString(value: string, encoding: TestDnStringEncoding): Uint8Array {
	return encoding === 'printable' ? printableString(value) : utf8String(value);
}

function buildDirectoryNameDerHex(rdns: readonly (readonly DirectoryNameAttribute[])[]): string {
	const encoded = sequence(
		rdns.map((rdn) =>
			setOf(
				rdn.map((attribute) =>
					sequence([
						objectIdentifier(attribute.oid),
						encodeDirectoryNameString(attribute.value, attribute.encoding),
					]),
				),
			),
		),
	);
	return Buffer.from(encoded).toString('hex');
}

async function verifyNameConstraintFixture(options: {
	readonly rootNameConstraints: NameConstraintsInput;
	readonly leafSubject?: LeafSubject;
	readonly leafSubjectAltNames?: LeafSubjectAltNames;
}) {
	const rootCommonName = 'Name Constraint Fixture Root';
	const root = await createSelfSignedCertificate({
		subject: { commonName: rootCommonName },
		extensions: {
			basicConstraints: { ca: true },
			keyUsage: ['keyCertSign', 'cRLSign'],
			nameConstraints: options.rootNameConstraints,
		},
	});
	const leafKeys = await generateKeyPair();
	const leafExtensions =
		options.leafSubjectAltNames === undefined
			? ({
					keyUsage: ['digitalSignature'],
				} satisfies NonNullable<CreateCertificateInput['extensions']>)
			: ({
					keyUsage: ['digitalSignature'],
					subjectAltNames: options.leafSubjectAltNames,
				} satisfies NonNullable<CreateCertificateInput['extensions']>);
	const leaf = await createCertificate({
		issuer: { commonName: rootCommonName },
		subject: options.leafSubject ?? { commonName: 'fixture-leaf' },
		publicKey: leafKeys.publicKey,
		signerPrivateKey: root.keyPair.privateKey,
		issuerPublicKey: root.keyPair.publicKey,
		extensions: leafExtensions,
	});
	return await verifyCertificateChain({
		leaf: leaf.pem,
		roots: [root.certificate.pem],
	});
}

describe('name constraint fixtures', () => {
	it('covers DNS permitted and excluded subtrees', async () => {
		const permitted = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [{ base: { type: 'dns', value: '.example.com' } }],
			},
			leafSubjectAltNames: [{ type: 'dns', value: 'api.example.com' }],
		});
		expect(permitted).toMatchObject({ ok: true });

		const excluded = await verifyNameConstraintFixture({
			rootNameConstraints: {
				excludedSubtrees: [{ base: { type: 'dns', value: '.example.com' } }],
			},
			leafSubjectAltNames: [{ type: 'dns', value: 'api.example.com' }],
		});
		expect(excluded).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});

	it('covers exact rfc822Name mailbox matching', async () => {
		const permitted = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [{ base: { type: 'email', value: 'user@example.com' } }],
			},
			leafSubjectAltNames: [{ type: 'email', value: 'user@example.com' }],
		});
		expect(permitted).toMatchObject({ ok: true });

		const rejected = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [{ base: { type: 'email', value: 'user@example.com' } }],
			},
			leafSubjectAltNames: [{ type: 'email', value: 'admin@example.com' }],
		});
		expect(rejected).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});

	it('covers URI host-subtree matching', async () => {
		const permitted = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [{ base: { type: 'uri', value: '.example.com' } }],
			},
			leafSubjectAltNames: [{ type: 'uri', value: 'https://www.example.com/app' }],
		});
		expect(permitted).toMatchObject({ ok: true });

		const rejected = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [{ base: { type: 'uri', value: '.example.com' } }],
			},
			leafSubjectAltNames: [{ type: 'uri', value: 'https://www.example.net/app' }],
		});
		expect(rejected).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});

	it('covers IPv4 subnet matching', async () => {
		const permitted = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [
					{
						base: {
							type: 'ip',
							addressBytes: Uint8Array.of(10, 0, 0, 0),
							maskBytes: Uint8Array.of(255, 0, 0, 0),
						},
					},
				],
			},
			leafSubjectAltNames: [{ type: 'ip', value: '10.1.2.3' }],
		});
		expect(permitted).toMatchObject({ ok: true });

		const rejected = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [
					{
						base: {
							type: 'ip',
							addressBytes: Uint8Array.of(10, 0, 0, 0),
							maskBytes: Uint8Array.of(255, 0, 0, 0),
						},
					},
				],
			},
			leafSubjectAltNames: [{ type: 'ip', value: '192.0.2.10' }],
		});
		expect(rejected).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});

	it('covers directoryName subject and SAN matching semantics', async () => {
		const constraintDerHex = buildDirectoryNameDerHex([
			[{ oid: OIDS.organizationName, value: 'allowed org', encoding: 'printable' }],
		]);
		const matchingSubject = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [{ base: { type: 'directoryName', derHex: constraintDerHex } }],
			},
			leafSubject: { organization: '  ALLOWED   ORG  ', commonName: 'fixture-leaf' },
			leafSubjectAltNames: [{ type: 'dns', value: 'fixture.example.com' }],
		});
		expect(matchingSubject).toMatchObject({ ok: true });

		const rejectedSan = await verifyNameConstraintFixture({
			rootNameConstraints: {
				excludedSubtrees: [{ base: { type: 'directoryName', derHex: constraintDerHex } }],
			},
			leafSubjectAltNames: [
				{
					type: 'directoryName',
					derHex: buildDirectoryNameDerHex([
						[{ oid: OIDS.organizationName, value: 'Allowed Org', encoding: 'utf8' }],
					]),
				},
			],
		});
		expect(rejectedSan).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});
});
