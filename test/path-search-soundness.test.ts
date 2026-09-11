import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificatePem,
	type TrustAnchor,
	trustAnchorFromCertificate,
	unwrap,
	verifyCertificateChain,
} from '#micro509';
import { canonicalDnKey, compareDistinguishedNames } from '#micro509/internal/shared/dn';
import type { ParsedCertificate } from '#micro509/x509/parse';

const VALIDITY = {
	notBefore: new Date('2020-01-01T00:00:00Z'),
	notAfter: new Date('2099-01-01T00:00:00Z'),
};
const AT = VALIDITY.notBefore;

interface Party {
	readonly publicKey: CryptoKey;
	readonly privateKey: CryptoKey;
}

interface Cert {
	readonly name: string;
	readonly subject: string;
	readonly issuer: string;
	readonly pem: string;
	readonly parsed: ParsedCertificate;
}

let serialCounter = 0;
function nextSerial(): Uint8Array {
	serialCounter += 1;
	return Uint8Array.of(0x10, (serialCounter >> 8) & 0xff, serialCounter & 0xff);
}

async function party(): Promise<Party> {
	return generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
}

async function issueCa(
	name: string,
	subjectCn: string,
	issuerCn: string,
	subject: Party,
	issuer: Party,
	pathLength?: number,
): Promise<Cert> {
	const basicConstraints =
		pathLength === undefined ? ({ ca: true } as const) : ({ ca: true, pathLength } as const);
	const material = await createCertificate({
		issuer: { commonName: issuerCn },
		subject: { commonName: subjectCn },
		publicKey: subject.publicKey,
		signerPrivateKey: issuer.privateKey,
		issuerPublicKey: issuer.publicKey,
		serialNumber: nextSerial(),
		validity: VALIDITY,
		extensions: { basicConstraints, keyUsage: ['keyCertSign', 'cRLSign'] },
	});
	return {
		name,
		subject: subjectCn,
		issuer: issuerCn,
		pem: material.pem,
		parsed: unwrap(parseCertificatePem(material.pem)),
	};
}

async function issueLeaf(
	name: string,
	subjectCn: string,
	issuerCn: string,
	subject: Party,
	issuer: Party,
): Promise<Cert> {
	const material = await createCertificate({
		issuer: { commonName: issuerCn },
		subject: { commonName: subjectCn },
		publicKey: subject.publicKey,
		signerPrivateKey: issuer.privateKey,
		issuerPublicKey: issuer.publicKey,
		serialNumber: nextSerial(),
		validity: VALIDITY,
		extensions: { keyUsage: ['digitalSignature'] },
	});
	return {
		name,
		subject: subjectCn,
		issuer: issuerCn,
		pem: material.pem,
		parsed: unwrap(parseCertificatePem(material.pem)),
	};
}

async function selfSignedRoot(
	name: string,
	subjectCn: string,
): Promise<{ cert: Cert; keys: Party }> {
	const result = await createSelfSignedCertificate({
		subject: { commonName: subjectCn },
		algorithm: { kind: 'ecdsa', curve: 'P-256' },
		validity: VALIDITY,
		extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
	});
	const parsed = unwrap(parseCertificatePem(result.certificate.pem));
	return {
		cert: {
			name,
			subject: subjectCn,
			issuer: subjectCn,
			pem: result.certificate.pem,
			parsed,
		},
		keys: { publicKey: result.keyPair.publicKey, privateKey: result.keyPair.privateKey },
	};
}

function dnEquals(childIssuer: ParsedCertificate, issuerSubject: ParsedCertificate): boolean {
	return compareDistinguishedNames(childIssuer.issuer, issuerSubject.subject);
}

function enumerateTerminatingPaths(
	leaf: Cert,
	roots: readonly Cert[],
	inters: readonly Cert[],
	anchorSubjectKeys: ReadonlySet<string>,
): readonly (readonly Cert[])[] {
	const rootNames = new Set(roots.map((cert) => cert.name));
	const pool = [...inters, ...roots];
	const paths: (readonly Cert[])[] = [];
	const limit = pool.length + 1;
	const maxPaths = 400;
	const walk = (current: Cert, acc: readonly Cert[], usedNames: ReadonlySet<string>): void => {
		if (paths.length >= maxPaths) return;
		if (acc.length > limit) return;
		if (rootNames.has(current.name) && acc.length > 1) {
			paths.push(acc);
			return;
		}
		if (acc.length > 1 && anchorSubjectKeys.has(canonicalDnKey(current.parsed.issuer))) {
			paths.push(acc);
		}
		for (const candidate of pool) {
			if (usedNames.has(candidate.name)) continue;
			if (!dnEquals(current.parsed, candidate.parsed)) continue;
			const nextUsed = new Set(usedNames);
			nextUsed.add(candidate.name);
			walk(candidate, [...acc, candidate], nextUsed);
		}
	};
	walk(leaf, [leaf], new Set([leaf.name]));
	return paths;
}

async function verifyResult(
	leaf: Cert,
	roots: readonly Cert[],
	inters: readonly Cert[],
	anchors: readonly TrustAnchor[],
): Promise<{ ok: boolean; code?: string; chainLength?: number }> {
	const result = await verifyCertificateChain({
		leaf: leaf.pem,
		intermediates: inters.map((cert) => cert.pem),
		roots: roots.map((cert) => cert.pem),
		trustAnchors: anchors,
		at: AT,
	});
	return result.ok
		? { ok: true, chainLength: result.value.chain.length }
		: { ok: false, code: result.code };
}

async function findValidTerminatingPaths(
	leaf: Cert,
	roots: readonly Cert[],
	anchors: readonly TrustAnchor[],
	inters: readonly Cert[],
): Promise<readonly (readonly Cert[])[]> {
	const rootNames = new Set(roots.map((cert) => cert.name));
	const anchorSubjectKeys = new Set(anchors.map((anchor) => canonicalDnKey(anchor.subject)));
	const candidates = enumerateTerminatingPaths(leaf, roots, inters, anchorSubjectKeys);
	const valid: (readonly Cert[])[] = [];
	for (const path of candidates) {
		const middle = path.slice(1).filter((cert) => !rootNames.has(cert.name));
		const outcome = await verifyResult(leaf, roots, middle, anchors);
		if (outcome.ok) valid.push(path);
	}
	return valid;
}

function names(path: readonly Cert[]): string {
	return path.map((cert) => cert.name).join(' -> ');
}

function makeRng(seed: number): () => number {
	let state = seed >>> 0;
	return () => {
		state = (state * 1664525 + 1013904223) >>> 0;
		return state / 0x100000000;
	};
}

function shuffle<T>(items: readonly T[], rng: () => number): readonly T[] {
	const copy = [...items];
	for (let index = copy.length - 1; index > 0; index -= 1) {
		const swap = Math.floor(rng() * (index + 1));
		const here = copy[index];
		const there = copy[swap];
		if (here === undefined || there === undefined) continue;
		copy[index] = there;
		copy[swap] = here;
	}
	return copy;
}

interface OrderingOutcome {
	readonly ordering: readonly Cert[];
	readonly ok: boolean;
	readonly code?: string;
	readonly chainLength?: number;
}

interface MeshFixture {
	readonly rootCert: Cert;
	readonly leaves: readonly Cert[];
	readonly anchorsToRoot: readonly Cert[];
	readonly nonAnchors: readonly Cert[];
}

interface ConfigOutcome {
	readonly anyOk: boolean;
	readonly anyFail: boolean;
	readonly maxLength: number;
	readonly hasLong: boolean;
}

async function buildMeshFixture(): Promise<MeshFixture> {
	const root = await selfSignedRoot('R', 'R');
	const root2 = await selfSignedRoot('R2', 'R2');
	const subjectKeys: Record<string, Party> = {
		A: await party(),
		B: await party(),
		C: await party(),
		D: await party(),
	};
	const leafKeys = await party();
	const parties: Record<string, Party> = { R: root.keys, R2: root2.keys, ...subjectKeys };
	const partyOf = (cn: string): Party => {
		const found = parties[cn];
		if (found === undefined) throw new Error(`no party ${cn}`);
		return found;
	};
	const ca = (subject: string, issuer: string, pathLength?: number) => {
		const suffix = pathLength === undefined ? '' : `:pl${pathLength}`;
		return issueCa(
			`${subject}/${issuer}${suffix}`,
			subject,
			issuer,
			partyOf(subject),
			partyOf(issuer),
			pathLength,
		);
	};
	const subjects = ['A', 'B', 'C', 'D'] as const;
	const issuers = ['R', 'R2', 'A', 'B', 'C', 'D'] as const;
	const pool: Cert[] = [root2.cert];
	for (const subject of subjects) {
		for (const issuer of issuers) {
			pool.push(await ca(subject, issuer));
			pool.push(await ca(subject, issuer, 0));
			pool.push(await ca(subject, issuer, 1));
		}
	}
	const leaves: Cert[] = [];
	for (const subject of subjects) {
		leaves.push(await issueLeaf(`L/${subject}`, 'Leaf', subject, leafKeys, partyOf(subject)));
	}
	return {
		rootCert: root.cert,
		leaves,
		anchorsToRoot: pool.filter((cert) => cert.issuer === 'R'),
		nonAnchors: pool.filter((cert) => cert.issuer !== 'R'),
	};
}

interface Scenario {
	readonly leaf: Cert;
	readonly roots: readonly Cert[];
	readonly anchors: readonly TrustAnchor[];
	readonly picked: readonly Cert[];
}

function bareAnchor(subjectCert: Cert, keyCert: Cert): TrustAnchor {
	if (subjectCert === keyCert) return trustAnchorFromCertificate(subjectCert.parsed);
	const keyParsed = keyCert.parsed;
	return {
		subject: subjectCert.parsed.subject,
		subjectPublicKeyInfoDer: keyParsed.subjectPublicKeyInfoDer,
		publicKeyAlgorithmOid: keyParsed.publicKeyAlgorithmOid,
		...(keyParsed.publicKeyParametersOid === undefined
			? {}
			: { publicKeyParametersOid: keyParsed.publicKeyParametersOid }),
	};
}

async function runOrderings(
	scenario: Scenario,
	count: number,
	rng: () => number,
): Promise<readonly OrderingOutcome[]> {
	const results: OrderingOutcome[] = [];
	for (let attempt = 0; attempt < count; attempt += 1) {
		const ordering = shuffle(scenario.picked, rng);
		const anchorOrder = shuffle(scenario.anchors, rng);
		const outcome = await verifyResult(scenario.leaf, scenario.roots, ordering, anchorOrder);
		results.push({
			ordering,
			ok: outcome.ok,
			...(outcome.code === undefined ? {} : { code: outcome.code }),
			...(outcome.chainLength === undefined ? {} : { chainLength: outcome.chainLength }),
		});
	}
	return results;
}

function summarizeOrderings(results: readonly OrderingOutcome[]): ConfigOutcome {
	let maxLength = 0;
	let hasLong = false;
	for (const entry of results) {
		const length = entry.chainLength ?? 0;
		if (length > maxLength) maxLength = length;
		if (length >= 4) hasLong = true;
	}
	return {
		anyOk: results.some((entry) => entry.ok),
		anyFail: results.some((entry) => !entry.ok),
		maxLength,
		hasLong,
	};
}

function describeOrderDependence(leaf: Cert, results: readonly OrderingOutcome[]): string {
	const okEntry = results.find((entry) => entry.ok);
	const failEntry = results.find((entry) => !entry.ok);
	return `ORDER-DEP leaf=${leaf.name} ok=[${names(okEntry?.ordering ?? [])}] fail(${
		failEntry?.code ?? '?'
	})=[${names(failEntry?.ordering ?? [])}]`;
}

interface ConfigResult {
	readonly built: boolean;
	readonly long: boolean;
	readonly maxLength: number;
	readonly orderDependent?: string;
	readonly droppedValid?: string;
}

async function evaluateScenario(
	scenario: Scenario,
	rng: () => number,
	orderingsPerConfig: number,
): Promise<ConfigResult> {
	const results = await runOrderings(scenario, orderingsPerConfig, rng);
	const summary = summarizeOrderings(results);
	const base = { built: summary.anyOk, long: summary.hasLong, maxLength: summary.maxLength };
	if (summary.anyOk && summary.anyFail) {
		return { ...base, orderDependent: describeOrderDependence(scenario.leaf, results) };
	}
	if (summary.anyOk) return base;
	const validPaths = await findValidTerminatingPaths(
		scenario.leaf,
		scenario.roots,
		scenario.anchors,
		scenario.picked,
	);
	if (validPaths.length === 0) return base;
	return {
		...base,
		droppedValid: `DROPPED-VALID leaf=${scenario.leaf.name} valid=[${names(validPaths[0] ?? [])}]`,
	};
}

function rootScenario(mesh: MeshFixture, rng: () => number): Scenario | undefined {
	const leaf = mesh.leaves[Math.floor(rng() * mesh.leaves.length)];
	const anchor = mesh.anchorsToRoot[Math.floor(rng() * mesh.anchorsToRoot.length)];
	if (leaf === undefined || anchor === undefined) return undefined;
	const size = 3 + Math.floor(rng() * 6);
	const picked = [anchor, ...shuffle(mesh.nonAnchors, rng).slice(0, size)];
	return { leaf, roots: [mesh.rootCert], anchors: [], picked };
}

interface AnchorContext {
	readonly repBySubject: ReadonlyMap<string, Cert>;
	readonly certsByIssuer: ReadonlyMap<string, readonly Cert[]>;
	readonly subjects: readonly string[];
	readonly pool: readonly Cert[];
}

function anchorContext(mesh: MeshFixture): AnchorContext {
	const pool = [...mesh.anchorsToRoot, ...mesh.nonAnchors];
	const repBySubject = new Map<string, Cert>();
	for (const cert of [mesh.rootCert, ...pool]) {
		if (!repBySubject.has(cert.subject)) repBySubject.set(cert.subject, cert);
	}
	const certsByIssuer = new Map<string, Cert[]>();
	for (const cert of pool) {
		const list = certsByIssuer.get(cert.issuer) ?? [];
		list.push(cert);
		certsByIssuer.set(cert.issuer, list);
	}
	return { repBySubject, certsByIssuer, subjects: [...repBySubject.keys()], pool };
}

function pickDecoyAnchor(
	ctx: AnchorContext,
	rep: Cert,
	rng: () => number,
): TrustAnchor | undefined {
	const otherSubject = ctx.subjects[Math.floor(rng() * ctx.subjects.length)];
	if (otherSubject === undefined) return undefined;
	const otherRep = ctx.repBySubject.get(otherSubject);
	if (otherRep === undefined || otherRep === rep) return undefined;
	return bareAnchor(rep, otherRep);
}

function anchorScenario(
	mesh: MeshFixture,
	ctx: AnchorContext,
	rng: () => number,
): Scenario | undefined {
	const leaf = mesh.leaves[Math.floor(rng() * mesh.leaves.length)];
	const terminal = ctx.subjects[Math.floor(rng() * ctx.subjects.length)];
	if (leaf === undefined || terminal === undefined) return undefined;
	const rep = ctx.repBySubject.get(terminal);
	const issuerTerminals = ctx.certsByIssuer.get(terminal) ?? [];
	const forced = issuerTerminals[Math.floor(rng() * issuerTerminals.length)];
	if (rep === undefined || forced === undefined) return undefined;
	const anchors: TrustAnchor[] = [bareAnchor(rep, rep)];
	if (rng() < 0.5) {
		const decoy = pickDecoyAnchor(ctx, rep, rng);
		if (decoy !== undefined) anchors.push(decoy);
	}
	const roots = rng() < 0.5 ? [mesh.rootCert] : [];
	const size = 2 + Math.floor(rng() * 5);
	const extras = shuffle(ctx.pool, rng)
		.filter((cert) => cert !== forced)
		.slice(0, size);
	return { leaf, roots, anchors, picked: [forced, ...extras] };
}

interface CampaignReport {
	readonly built: number;
	readonly orderDependent: readonly string[];
	readonly droppedValid: readonly string[];
}

function reportCampaign(label: string, results: readonly ConfigResult[]): CampaignReport {
	const built = results.filter((entry) => entry.built).length;
	const long = results.filter((entry) => entry.long).length;
	const maxLength = results.reduce((best, entry) => Math.max(best, entry.maxLength), 0);
	const orderDependent = results
		.map((entry) => entry.orderDependent)
		.filter((line): line is string => line !== undefined);
	const droppedValid = results
		.map((entry) => entry.droppedValid)
		.filter((line): line is string => line !== undefined);
	console.log(
		`[${label}] configs=${results.length} builtChains=${built} longChains(>=4)=${long} maxChainLength=${maxLength} orderDependentHits=${orderDependent.length} droppedValidHits=${droppedValid.length}`,
	);
	for (const line of [...orderDependent, ...droppedValid].slice(0, 10)) {
		console.log(`  ${line}`);
	}
	return { built, orderDependent, droppedValid };
}

describe('path search soundness exploration', () => {
	it('root-terminated cross/self/pathlen meshes: the yes/no verdict is order-independent', async () => {
		const mesh = await buildMeshFixture();
		const rng = makeRng(0x5eed1234);
		const orderingsPerConfig = 6;

		const results: ConfigResult[] = [];
		for (let config = 0; config < 120; config += 1) {
			const scenario = rootScenario(mesh, rng);
			if (scenario !== undefined)
				results.push(await evaluateScenario(scenario, rng, orderingsPerConfig));
		}

		const report = reportCampaign('root', results);
		expect(report.built).toBeGreaterThan(0);
		expect(report.orderDependent.length).toBe(0);
		expect(report.droppedValid.length).toBe(0);
	}, 120_000);

	it('bare-trust-anchor termination: the yes/no verdict is order-independent', async () => {
		const mesh = await buildMeshFixture();
		const ctx = anchorContext(mesh);
		const rng = makeRng(0x1234abcd);
		const orderingsPerConfig = 6;

		let anchorOnlyBuilt = 0;
		const results: ConfigResult[] = [];
		for (let config = 0; config < 100; config += 1) {
			const scenario = anchorScenario(mesh, ctx, rng);
			if (scenario === undefined) continue;
			const result = await evaluateScenario(scenario, rng, orderingsPerConfig);
			results.push(result);
			if (scenario.roots.length === 0 && result.built) anchorOnlyBuilt += 1;
		}

		const report = reportCampaign('anchor', results);
		console.log(`  anchorOnlyBuilt=${anchorOnlyBuilt}`);
		expect(report.built).toBeGreaterThan(0);
		expect(anchorOnlyBuilt).toBeGreaterThan(0);
		expect(report.orderDependent.length).toBe(0);
		expect(report.droppedValid.length).toBe(0);
	}, 120_000);
});
