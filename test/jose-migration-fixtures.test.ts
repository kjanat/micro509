import { expect, it } from 'bun:test';
import { importJWK, jwtVerify } from 'jose-v5';
import { verifyJwt } from '#micro509/jose';
import { importPublicJwk } from '#micro509/keys';
import { unwrap } from '#micro509/result';
import fixtures from '../site/assets/fixtures/jose-migration.json' with { type: 'json' };

const primary = unwrap(
	await importPublicJwk(fixtures.keys.primary, { kind: 'rsa', hash: 'SHA-256' }),
);
const independentPrimary = await importJWK(fixtures.keys.primary, 'RS256');
const policy = {
	algorithms: ['RS256'],
	key: primary,
	tokenType: 'JWT',
	claims: {
		issuer: fixtures.issuer,
		audience: fixtures.audience,
		now: () => new Date(fixtures.now * 1000),
	},
} as const;
const independentPolicy = {
	algorithms: ['RS256'],
	typ: 'JWT',
	issuer: fixtures.issuer,
	audience: fixtures.audience,
	currentDate: new Date(fixtures.now * 1000),
};

for (const fixture of fixtures.cases) {
	it(`consumer corpus: ${fixture.id}`, async () => {
		const result = await verifyJwt(fixture.token, policy);
		expect(result.ok ? 'ok' : result.code).toBe(fixture.micro);
		let accepted = false;
		try {
			await jwtVerify(fixture.token, independentPrimary, independentPolicy);
			accepted = true;
		} catch {
			/* independent verdict */
		}
		expect(accepted).toBe(fixture.joseAccepts);
		if (result.ok && fixture.id === 'valid-unicode')
			expect(result.value.claims).toEqual(fixtures.claims);
	});
}
it('proves the unsupported-algorithm token has a real independent signature', async () => {
	const token = fixtures.cases.find((entry) => entry.id === 'signed-unsupported-PS256')?.token;
	if (token === undefined) throw new Error('missing independent signed fixture');
	const key = await importJWK(fixtures.keys.unsupported, 'PS256');
	const result = await jwtVerify(token, key, { ...independentPolicy, algorithms: ['PS256'] });
	expect(result.payload).toEqual(fixtures.claims);
});
it('verifies the micro509-produced reverse token using jose', async () => {
	expect(
		(await jwtVerify(fixtures.reverse.token, independentPrimary, independentPolicy)).payload,
	).toEqual(fixtures.claims);
});
it('aligns optional policies explicitly without losing default-difference fixtures', async () => {
	for (const id of ['missing-exp', 'future-iat']) {
		const token = fixtures.cases.find((entry) => entry.id === id)?.token;
		if (token === undefined) throw new Error('missing default difference fixture');
		const result = await verifyJwt(token, {
			...policy,
			claims: {
				...policy.claims,
				...(id === 'missing-exp' ? { requiredClaims: [] } : { futureIssuedAt: 'allow' as const }),
			},
		});
		expect(result.ok).toBe(true);
		let accepted = true;
		try {
			await jwtVerify(token, independentPrimary, {
				...independentPolicy,
				requiredClaims: ['exp'],
				maxTokenAge: 600,
			});
		} catch {
			accepted = false;
		}
		expect(accepted).toBe(false);
	}
});
