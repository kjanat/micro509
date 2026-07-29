import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { SubjectAltName } from 'micro509';
import { createSelfSignedCertificate, parseCertificatePem } from 'micro509';
import { normalizeIpAddress } from 'micro509/x509';

const VALIDITY_DAYS = 30;
const RENEW_MARGIN_MS = 24 * 60 * 60 * 1000;

interface DevCertificate {
	readonly cert: string;
	readonly key: string;
}

function machineNames(): { readonly ips: readonly string[]; readonly hosts: readonly string[] } {
	const ips = new Set(['127.0.0.1', '::1']);
	for (const entries of Object.values(os.networkInterfaces())) {
		for (const entry of entries ?? []) {
			ips.add(entry.address.replace(/%.*$/, ''));
		}
	}
	return { ips: [...ips], hosts: ['localhost', os.hostname().toLowerCase()] };
}

function covers(certPem: string, ips: readonly string[], hosts: readonly string[]): boolean {
	const parsed = parseCertificatePem(certPem);
	if (!parsed.ok) return false;
	if (parsed.value.notAfter.getTime() < Date.now() + RENEW_MARGIN_MS) return false;
	const sans = parsed.value.subjectAltNames ?? [];
	const ipSans = new Set(
		sans.flatMap((san) => (san.type === 'ip' ? [normalizeIpAddress(san.value)] : [])),
	);
	const dnsSans = new Set(sans.flatMap((san) => (san.type === 'dns' ? [san.value] : [])));
	return (
		ips.every((ip) => ipSans.has(normalizeIpAddress(ip))) &&
		hosts.every((host) => dnsSans.has(host))
	);
}

/**
 * A self-signed TLS certificate for the local dev server, minted with micro509
 * itself. Cached under `cacheDir` and reissued when it nears expiry or the
 * machine's addresses outgrow its subject alternative names.
 */
export async function devServerCertificate(cacheDir: string): Promise<DevCertificate> {
	const certPath = path.join(cacheDir, 'dev-cert.pem');
	const keyPath = path.join(cacheDir, 'dev-key.pem');
	const { ips, hosts } = machineNames();
	if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
		const cert = fs.readFileSync(certPath, 'utf8');
		if (covers(cert, ips, hosts)) {
			return { cert, key: fs.readFileSync(keyPath, 'utf8') };
		}
	}
	const subjectAltNames: readonly SubjectAltName[] = [
		...hosts.map((value): SubjectAltName => ({ type: 'dns', value })),
		...ips.map((value): SubjectAltName => ({ type: 'ip', value })),
	];
	const { certificate, keyPair } = await createSelfSignedCertificate({
		subject: { commonName: 'micro509 dev server' },
		validity: { days: VALIDITY_DAYS },
		extensions: {
			keyUsage: ['digitalSignature'],
			extendedKeyUsage: ['serverAuth'],
			subjectAltNames,
		},
	});
	const key = await keyPair.exportPkcs8Pem();
	fs.mkdirSync(cacheDir, { recursive: true });
	fs.writeFileSync(certPath, certificate.pem);
	fs.writeFileSync(keyPath, key, { mode: 0o600 });
	console.log(`[dev-cert] issued for ${hosts.join(', ')}, ${ips.join(', ')}`);
	return { cert: certificate.pem, key };
}
