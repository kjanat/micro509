import { describe, expect, it } from 'bun:test';
import { toHex } from '#micro509/internal/asn1/asn1';
import { objectIdentifier, sequence, setOf, utf8String } from '#micro509/internal/asn1/der';
import type { SubjectAltName } from '#micro509/x509';
import {
	createSelfSignedCertificate,
	distinguishedNameToString,
	encodeName,
	parseCertificatePemOrThrow,
	relativeDistinguishedNameToString,
	subjectAltNameLabel,
	subjectAltNameToString,
} from '#micro509/x509';

function directoryName(name: Parameters<typeof encodeName>[0]): SubjectAltName {
	return { type: 'directoryName', derHex: toHex(encodeName(name)) };
}

describe('subjectAltNameToString', () => {
	it('renders every string-valued variant as its value', () => {
		const names: readonly SubjectAltName[] = [
			{ type: 'dns', value: 'example.com' },
			{ type: 'ip', value: '192.0.2.1' },
			{ type: 'email', value: 'admin@example.com' },
			{ type: 'uri', value: 'https://example.com/ca' },
			{ type: 'srv', value: '_imaps.example.com' },
		];
		expect(names.map((name) => subjectAltNameToString(name))).toEqual([
			'example.com',
			'192.0.2.1',
			'admin@example.com',
			'https://example.com/ca',
			'_imaps.example.com',
		]);
	});

	it('renders an unknown variant as hex rather than comma-separated bytes', () => {
		const name: SubjectAltName = {
			type: 'unknown',
			tag: 9,
			value: Uint8Array.from([0xc0, 0x00, 0x02, 0x01]),
		};
		expect(subjectAltNameToString(name)).toBe('c0000201');
	});

	it('renders a directoryName as an RFC 4514 string with RDNs reversed', () => {
		const name = directoryName({
			country: 'US',
			organization: 'Acme',
			commonName: 'Example CA',
		});
		expect(subjectAltNameToString(name)).toBe('CN=Example CA,O=Acme,C=US');
	});

	it('falls back to the hex when a directoryName does not decode', () => {
		const name: SubjectAltName = { type: 'directoryName', derHex: '3021deadbeef' };
		expect(subjectAltNameToString(name)).toBe('3021deadbeef');
	});

	it('falls back to the hex when a directoryName is not a SEQUENCE', () => {
		const name: SubjectAltName = { type: 'directoryName', derHex: '0403010203' };
		expect(subjectAltNameToString(name)).toBe('0403010203');
	});

	it('prefixes with the OpenSSL label on request', () => {
		expect(subjectAltNameToString({ type: 'dns', value: 'example.com' }, { prefix: true })).toBe(
			'DNS:example.com',
		);
		expect(subjectAltNameToString({ type: 'ip', value: '192.0.2.1' }, { prefix: true })).toBe(
			'IP Address:192.0.2.1',
		);
		expect(subjectAltNameToString(directoryName({ commonName: 'CA' }), { prefix: true })).toBe(
			'DirName:CN=CA',
		);
		expect(
			subjectAltNameToString(
				{ type: 'unknown', tag: 9, value: Uint8Array.from([0xff]) },
				{ prefix: true },
			),
		).toBe('[tag 9]:ff');
	});

	it('omits the prefix by default', () => {
		expect(subjectAltNameToString({ type: 'dns', value: 'example.com' }, {})).toBe('example.com');
	});
});

describe('subjectAltNameLabel', () => {
	it('labels every variant', () => {
		const labels = (
			[
				{ type: 'dns', value: 'a' },
				{ type: 'ip', value: 'a' },
				{ type: 'email', value: 'a' },
				{ type: 'uri', value: 'a' },
				{ type: 'srv', value: 'a' },
				{ type: 'directoryName', derHex: '3000' },
				{ type: 'unknown', tag: 8, value: new Uint8Array() },
			] satisfies readonly SubjectAltName[]
		).map((name) => subjectAltNameLabel(name));
		expect(labels).toEqual(['DNS', 'IP Address', 'email', 'URI', 'SRV', 'DirName', '[tag 8]']);
	});
});

describe('distinguishedNameToString', () => {
	it('renders a parsed subject in reverse RDN order', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { country: 'US', organization: 'Acme', commonName: 'leaf.example' },
		});
		const parsed = parseCertificatePemOrThrow(certificate.pem);
		expect(distinguishedNameToString(parsed.subject)).toBe('CN=leaf.example,O=Acme,C=US');
	});

	it('escapes the RFC 4514 special characters', () => {
		const name = directoryName({ organization: 'Acme, Inc. + "Co"; <x>\\y' });
		expect(subjectAltNameToString(name)).toBe('O=Acme\\, Inc. \\+ \\"Co\\"\\; \\<x\\>\\\\y');
	});

	it('escapes a leading hash, and a leading or trailing space', () => {
		expect(subjectAltNameToString(directoryName({ commonName: '#hash' }))).toBe('CN=\\#hash');
		expect(subjectAltNameToString(directoryName({ commonName: ' pad ' }))).toBe('CN=\\ pad\\ ');
		expect(subjectAltNameToString(directoryName({ commonName: ' ' }))).toBe('CN=\\ ');
	});

	it('hex-escapes control characters', () => {
		expect(subjectAltNameToString(directoryName({ commonName: 'a\u0000b\u001fc' }))).toBe(
			'CN=a\\00b\\1fc',
		);
	});

	it('joins a multi-valued RDN with plus and falls back to the OID for unknown types', () => {
		const derHex = toHex(
			sequence([
				setOf([
					sequence([objectIdentifier('2.5.4.3'), utf8String('device-7')]),
					sequence([objectIdentifier('1.3.6.1.4.1.99999.1'), utf8String('custom')]),
				]),
			]),
		);
		expect(subjectAltNameToString({ type: 'directoryName', derHex })).toBe(
			'CN=device-7+1.3.6.1.4.1.99999.1=custom',
		);
	});

	it('renders an empty name as the empty string', () => {
		expect(subjectAltNameToString({ type: 'directoryName', derHex: '3000' })).toBe('');
	});
});

describe('relativeDistinguishedNameToString', () => {
	it('renders a single RDN of a parsed name', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { country: 'US', commonName: 'leaf.example' },
		});
		const parsed = parseCertificatePemOrThrow(certificate.pem);
		const rdns = parsed.subject.rdns.map((rdn) => relativeDistinguishedNameToString(rdn));
		expect(rdns).toEqual(['C=US', 'CN=leaf.example']);
	});
});

describe('parsed certificate SANs', () => {
	it('renders the SAN list of a real certificate without hand-narrowing', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: 'san.example' },
			extensions: {
				subjectAltNames: [
					{ type: 'dns', value: 'san.example' },
					{ type: 'ip', value: '192.0.2.1' },
					directoryName({ organization: 'Acme', commonName: 'Example CA' }),
				],
			},
		});
		const parsed = parseCertificatePemOrThrow(certificate.pem);
		const rendered = (parsed.subjectAltNames ?? []).map((name) => subjectAltNameToString(name));
		expect(rendered).toEqual(['san.example', '192.0.2.1', 'CN=Example CA,O=Acme']);
	});
});
