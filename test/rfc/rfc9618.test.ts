import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificatePem,
	unwrap,
	validateCandidatePath,
} from '#micro509';
import { flattenedText, rfcDir } from '#test/helpers';

const rfc5280 = await flattenedText(`${rfcDir}/rfc5280.txt`);
const rfc9618 = await flattenedText(`${rfcDir}/rfc9618.txt`);

const P1 = '1.2.3.4';
const P2 = '1.2.3.5';
const ANY_POLICY = '2.5.29.32.0';

describe('RFC 5280 §6.1.3 as kept by RFC 9618 §5.3: policy mapping (§6.1.4(b)) never runs on certificate n', () => {
	it('prints the sentences this suite relies on', () => {
		expect(rfc5280).toContain(
			'If i is not equal to n, continue by performing the preparatory steps listed in Section 6.1.4. If i is equal to n, perform the wrap-up steps listed in Section 6.1.5.',
		);
		expect(rfc9618).toContain(
			'The text following step (f) in Section 6.1.3 of [RFC5280], beginning with',
		);
		expect(rfc9618).toContain('If any of steps (a), (b), (c), or (f) fails');
	});

	it("ignores the leaf's policyMappings when inhibitPolicyMapping is already zero", async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'RFC 9618 Root' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const caKeys = await generateKeyPair();
		const ca = await createCertificate({
			issuer: { commonName: 'RFC 9618 Root' },
			subject: { commonName: 'RFC 9618 CA' },
			publicKey: caKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				certificatePolicies: [{ policyIdentifier: P1 }],
				policyConstraints: { inhibitPolicyMapping: 0 },
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'RFC 9618 CA' },
			subject: { commonName: 'rfc9618-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: caKeys.privateKey,
			issuerPublicKey: caKeys.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				certificatePolicies: [{ policyIdentifier: P1 }],
				policyMappings: [{ issuerDomainPolicy: P1, subjectDomainPolicy: P2 }],
			},
		});

		const result = await validateCandidatePath({
			chain: [
				unwrap(parseCertificatePem(leaf.pem)),
				unwrap(parseCertificatePem(ca.pem)),
				unwrap(parseCertificatePem(root.certificate.pem)),
			],
			requireExplicitPolicy: true,
		});
		expect(result).toMatchObject({
			ok: true,
			value: { policyValidation: { userConstrainedPolicies: [{ policyIdentifier: P1 }] } },
		});
	});
});

describe('RFC 5280 §6.1.1(c): the special value any-policy in user-initial-policy-set', () => {
	it('prints the sentences this suite relies on', () => {
		expect(rfc5280).toContain(
			'The user-initial-policy-set contains the special value any-policy if the user is not concerned about certificate policy.',
		);
	});

	async function policyChain() {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'RFC 5280 Policy Root' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'RFC 5280 Policy Root' },
			subject: { commonName: 'rfc5280-policy-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				certificatePolicies: [{ policyIdentifier: P1 }],
			},
		});
		return [
			unwrap(parseCertificatePem(leaf.pem)),
			unwrap(parseCertificatePem(root.certificate.pem)),
		];
	}

	it('reads the anyPolicy OID in initialPolicySet as any-policy', async () => {
		const chain = await policyChain();
		expect(await validateCandidatePath({ chain, initialPolicySet: [ANY_POLICY] })).toMatchObject({
			ok: true,
			value: { policyValidation: { userConstrainedPolicies: [{ policyIdentifier: P1 }] } },
		});
		expect(
			await validateCandidatePath({ chain, initialPolicySet: [P2, ANY_POLICY] }),
		).toMatchObject({ ok: true });
	});

	it('fails an initialPolicySet holding a malformed OID, even beside anyPolicy', async () => {
		const chain = await policyChain();
		for (const initialPolicySet of [['not-an-oid'], [ANY_POLICY, 'not-an-oid']]) {
			expect(await validateCandidatePath({ chain, initialPolicySet })).toMatchObject({
				ok: false,
				code: 'initial_policy_set_not_satisfied',
			});
		}
	});
});
