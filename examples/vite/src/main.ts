import type { KeyAlgorithmInput, ParsedCertificate, SubjectAltName } from 'micro509';
import { certificateFingerprint, createSelfSignedCertificate } from 'micro509';
import { parseCertificatePem } from 'micro509/x509';

const form = document.querySelector<HTMLFormElement>('#form');
const pemPane = document.querySelector<HTMLPreElement>('#pem');
const parsedPane = document.querySelector<HTMLDListElement>('#parsed');
const button = document.querySelector<HTMLButtonElement>('button[type="submit"]');

if (form === null || pemPane === null || parsedPane === null || button === null) {
	throw new Error('the page is missing an element the demo needs');
}

function field(data: FormData, name: string): string {
	const value = data.get(name);
	return typeof value === 'string' ? value.trim() : '';
}

function keyAlgorithm(choice: string): KeyAlgorithmInput {
	if (choice === 'RSA') return { kind: 'rsa', modulusLength: 2048 };
	if (choice === 'P-384') return { kind: 'ecdsa', curve: 'P-384' };
	return { kind: 'ecdsa', curve: 'P-256' };
}

function nameOf(name: SubjectAltName): string {
	if (!('value' in name)) return name.derHex;
	if (typeof name.value === 'string') return name.value;
	return [...name.value].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function describe(certificate: ParsedCertificate, fingerprint: string): Array<[string, string]> {
	const names = (certificate.subjectAltNames ?? []).map(nameOf).join(', ');
	return [
		['subject', certificate.subject.values.commonName ?? '—'],
		['organization', certificate.subject.values.organization ?? '—'],
		['serial', certificate.serialNumberHex],
		['not before', certificate.notBefore.toISOString()],
		['not after', certificate.notAfter.toISOString()],
		['signature', certificate.signatureAlgorithmName ?? '—'],
		['public key', certificate.publicKeyAlgorithmName ?? '—'],
		['key usage', certificate.keyUsage?.flags.join(', ') || '—'],
		['alt names', names || '—'],
		['sha-256', fingerprint],
	];
}

form.addEventListener('submit', async (event) => {
	event.preventDefault();
	button.disabled = true;
	pemPane.textContent = 'Generating a key and signing…';
	parsedPane.replaceChildren();

	try {
		const data = new FormData(form);
		const commonName = field(data, 'commonName');
		const organization = field(data, 'organization');
		const san = field(data, 'san');
		const days = Number(field(data, 'days')) || 30;

		const subjectAltNames: SubjectAltName[] = [{ type: 'dns', value: commonName }];
		if (san !== '') subjectAltNames.push({ type: 'dns', value: san });

		const { certificate } = await createSelfSignedCertificate({
			subject: {
				commonName,
				...(organization === '' ? {} : { organization }),
			},
			algorithm: keyAlgorithm(field(data, 'algorithm')),
			validity: { days },
			extensions: {
				keyUsage: ['digitalSignature', 'keyEncipherment'],
				subjectAltNames,
			},
		});

		pemPane.textContent = certificate.pem;

		const parsed = parseCertificatePem(certificate.pem);
		if (!parsed.ok) {
			parsedPane.append(row('parse failed', parsed.error.code));
			return;
		}

		const { colonHex } = await certificateFingerprint(certificate.pem);
		parsedPane.append(...describe(parsed.value, colonHex).map(([term, value]) => row(term, value)));
	} catch (error) {
		pemPane.textContent = error instanceof Error ? error.message : String(error);
	} finally {
		button.disabled = false;
	}
});

const COLON_HEX = /^[0-9A-F]{2}(:[0-9A-F]{2})+$/;

function row(term: string, value: string): DocumentFragment {
	const fragment = document.createDocumentFragment();
	const dt = document.createElement('dt');
	dt.textContent = term;

	const dd = document.createElement('dd');
	if (COLON_HEX.test(value)) {
		for (const [index, byte] of value.split(':').entries()) {
			if (index > 0) {
				dd.append(':');
				dd.append(document.createElement('wbr'));
			}
			dd.append(byte);
		}
	} else {
		dd.textContent = value;
	}

	fragment.append(dt, dd);
	return fragment;
}
