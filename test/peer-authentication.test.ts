import { afterAll, describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import type { DetailedPeerCertificate, TLSSocket } from 'node:tls';
import { connect, createServer } from 'node:tls';
import {
	createCertificate,
	createSelfSignedCertificate,
	exportPkcs8Pem,
	generateKeyPair,
	subjectPublicKeyInfoFingerprint,
	verifyCertificateChain,
} from '#micro509';
import { projectRoot } from '#test/helpers';

type AuthenticateClient = (
	handshakeChain: readonly Uint8Array[],
	trustedRootPems: readonly string[],
	accountsBySpkiSha256: ReadonlyMap<string, string>,
) => Promise<unknown>;

function exportsAuthenticateClient(
	value: unknown,
): value is { readonly authenticateClient: AuthenticateClient } {
	return (
		typeof value === 'object' &&
		value !== null &&
		'authenticateClient' in value &&
		typeof value.authenticateClient === 'function'
	);
}

const recipe = readFileSync(path.join(projectRoot, 'site/guide/recipes.md'), 'utf8');
const start = recipe.indexOf('async function authenticateClient(');
const end = recipe.indexOf('\n}\n', start);
if (start === -1 || end === -1) throw new Error('recipes.md has no authenticateClient function');
const scratch = path.join(projectRoot, 'node_modules/.cache/peer-authentication');
const recipeModule = path.join(scratch, 'authenticate-client.ts');
await fsp.mkdir(scratch, { recursive: true });
await fsp.writeFile(
	recipeModule,
	`import { subjectPublicKeyInfoFingerprint, verifyCertificateChain } from '#micro509';\nexport ${recipe.slice(start, end + 2)}`,
);
const loaded: unknown = await import(recipeModule);
if (!exportsAuthenticateClient(loaded)) throw new Error('recipe module exports no function');
const { authenticateClient } = loaded;

const ca = await createSelfSignedCertificate({
	subject: { commonName: 'Peer Authentication CA' },
	extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] },
});
const roots = [ca.certificate.pem];

async function issue(commonName: string, purpose: 'serverAuth' | 'clientAuth') {
	const keys = await generateKeyPair();
	const certificate = await createCertificate({
		issuer: { commonName: 'Peer Authentication CA' },
		subject: { commonName },
		publicKey: keys.publicKey,
		signerPrivateKey: ca.keyPair.privateKey,
		issuerCertificate: ca.certificate.pem,
		extensions: {
			extendedKeyUsage: [purpose],
			subjectAltNames: [{ type: 'dns', value: commonName }],
		},
	});
	return { certificate, keyPem: await exportPkcs8Pem(keys.privateKey) };
}

const server = await issue('localhost', 'serverAuth');
const alice = await issue('alice.example', 'clientAuth');
const mallory = await issue('mallory.example', 'clientAuth');
const accounts = new Map([
	[(await subjectPublicKeyInfoFingerprint(alice.certificate.der)).hex, 'alice'],
]);

function presentedChain(socket: TLSSocket): Uint8Array[] {
	const chain: Uint8Array[] = [];
	let current: DetailedPeerCertificate | undefined = socket.getPeerCertificate(true);
	while (current?.raw !== undefined) {
		chain.push(new Uint8Array(current.raw));
		const next: DetailedPeerCertificate | undefined = current.issuerCertificate;
		if (next === undefined || next === current) break;
		current = next;
	}
	return chain;
}

const tlsServer = createServer(
	{
		cert: server.certificate.pem,
		key: server.keyPem,
		ca: ca.certificate.pem,
		requestCert: true,
		rejectUnauthorized: true,
	},
	(socket) => {
		socket.end();
	},
);
const chains: ((chain: readonly Uint8Array[]) => void)[] = [];
tlsServer.on('secureConnection', (socket) => {
	chains.shift()?.(presentedChain(socket));
});
await new Promise<void>((resolve) => tlsServer.listen(0, '127.0.0.1', resolve));
afterAll(() => {
	tlsServer.close();
});

async function handshake(certificatePems: readonly string[], keyPem: string) {
	const address = tlsServer.address();
	if (address === null || typeof address === 'string') throw new Error('TLS server has no port');
	const received = new Promise<readonly Uint8Array[]>((resolve) => chains.push(resolve));
	await new Promise<void>((resolve, reject) => {
		const socket = connect(
			{
				host: '127.0.0.1',
				port: address.port,
				servername: 'localhost',
				ca: ca.certificate.pem,
				cert: certificatePems.join(''),
				key: keyPem,
			},
			() => {
				socket.end();
				resolve();
			},
		);
		socket.on('error', reject);
	});
	return received;
}

describe('TLS client authentication recipe (site/guide/recipes.md)', () => {
	it('authenticates the client whose key the handshake proved', async () => {
		const chain = await handshake([alice.certificate.pem], alice.keyPem);
		expect(chain[0]).toEqual(alice.certificate.der);
		expect(await authenticateClient(chain, roots, accounts)).toMatchObject({
			ok: true,
			account: 'alice',
		});
	});

	it('denies a client whose certificate validates but maps to no account', async () => {
		const chain = await handshake([mallory.certificate.pem], mallory.keyPem);
		expect(
			await verifyCertificateChain({
				leaf: chain[0] ?? new Uint8Array(),
				roots,
				purpose: 'clientAuth',
			}),
		).toMatchObject({ ok: true });
		expect(await authenticateClient(chain, roots, accounts)).toEqual({
			ok: false,
			reason: 'not_authorized',
			spkiSha256: (await subjectPublicKeyInfoFingerprint(mallory.certificate.der)).hex,
		});
	});

	it('denies a client that appends an authorized certificate to its own chain (GHSA-99jp-jwmc-65p4)', async () => {
		const chain = await handshake([mallory.certificate.pem, alice.certificate.pem], mallory.keyPem);
		expect(chain[0]).toEqual(mallory.certificate.der);
		expect(chain).toContainEqual(alice.certificate.der);
		const presentedMatches = await Promise.all(
			chain.map(async (der) => accounts.has((await subjectPublicKeyInfoFingerprint(der)).hex)),
		);
		expect(presentedMatches[0]).toBe(false);
		expect(presentedMatches).toContain(true);
		expect(await authenticateClient(chain, roots, accounts)).toMatchObject({
			ok: false,
			reason: 'not_authorized',
		});
	});
});
