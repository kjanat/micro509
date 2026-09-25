import { describe, expect, it } from 'bun:test';
import {
	createSelfSignedCertificate,
	matchServiceIdentity,
	parseCertificateDerOrThrow,
	type SubjectAltName,
} from '#micro509';
import { ia5Bytes, implicitPrimitiveContext, sequence } from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { createSelfSignedCertificateWithRawExtensions, flattenedText, rfcDir } from '#test/helpers';

const rfc9525 = await flattenedText(`${rfcDir}/rfc9525.txt`);

async function presenting(san: SubjectAltName) {
	const issued = await createSelfSignedCertificate({
		subject: { commonName: 'rfc9525' },
		extensions: { subjectAltNames: [san] },
	});
	return parseCertificateDerOrThrow(issued.certificate.der);
}

async function presentingRawDnsName(dnsName: string) {
	const issued = await createSelfSignedCertificateWithRawExtensions({
		subject: { commonName: 'rfc9525' },
		extensions: {
			keyUsage: ['digitalSignature'],
			customExtensions: [
				{
					oid: OIDS.subjectAltName,
					value: sequence([implicitPrimitiveContext(2, ia5Bytes(dnsName))]),
				},
			],
		},
	});
	return parseCertificateDerOrThrow(issued.certificate.der);
}

async function matchesDns(presented: string, reference: string): Promise<boolean> {
	return matchServiceIdentity({
		certificate: await presentingRawDnsName(presented),
		serviceIdentity: { type: 'dns', value: reference },
	}).ok;
}

describe('RFC 9525 §6.3: reference U-labels are converted to A-labels under IDNA2008', () => {
	it('prints the sentences this suite relies on', () => {
		expect(rfc9525).toContain(
			'the client MUST convert any U-labels [IDNA-DEFS] in the domain name to A-labels before checking the domain name or comparing it with others.',
		);
	});

	it('matches a reference U-label against the presented A-label', async () => {
		expect(await matchesDns('xn--bcher-kva.example', 'bücher.example')).toBe(true);
		expect(await matchesDns('xn--bcher-kva.example', 'BÜCHER.example')).toBe(true);
	});

	it('matches a reference written with fullwidth forms and an ideographic full stop', async () => {
		expect(await matchesDns('xn--bcher-kva.example', 'ｂüｃｈｅｒ。example')).toBe(true);
	});

	it('matches nothing for a reference that IDNA2008 disallows, where UTS #46 would map it', async () => {
		expect(await matchesDns('xn--45h.example', '♚.example')).toBe(false);
	});

	it('matches nothing for a reference xn-- label that is not an A-label', async () => {
		expect(await matchesDns('xn--45h.example', 'xn--45h.example')).toBe(false);
	});

	it('matches nothing for a reference with a malformed ASCII label', async () => {
		expect(await matchesDns('foo bar.example', 'foo bar.example')).toBe(false);
	});

	it('returns a mismatch, without throwing, for a reference label too long to encode', async () => {
		expect(await matchesDns('example.com', `${'a'.repeat(20000)}\u{20000}.example`)).toBe(false);
	});

	it('stores a SRVName U-label domain as its A-labels (RFC 4985 §3)', async () => {
		const certificate = await presenting({ type: 'srv', value: '_imap.bücher.example' });
		expect(certificate.subjectAltNames).toEqual([
			{ type: 'srv', value: '_imap.xn--bcher-kva.example' },
		]);
	});

	it('decodes a percent-encoded UTF-8 URI host once before converting it', async () => {
		const uriMatches = async (presented: string, reference: string) =>
			matchServiceIdentity({
				certificate: await presenting({ type: 'uri', value: presented }),
				serviceIdentity: { type: 'uri', value: reference },
			}).ok;
		expect(await uriMatches('https://b%C3%BCcher.example/', 'https://xn--bcher-kva.example/')).toBe(
			true,
		);
		expect(await uriMatches('https://xn--bcher-kva.example/', 'https://b%C3%BCcher.example/')).toBe(
			true,
		);
		expect(await uriMatches('https://b%C3cher.example/', 'https://b%C3cher.example/')).toBe(false);
		expect(await uriMatches('https://b%zzcher.example/', 'https://b%zzcher.example/')).toBe(false);
	});

	it('matches a URI-ID and an SRV-ID host after the same conversion', async () => {
		expect(
			matchServiceIdentity({
				certificate: await presenting({ type: 'uri', value: 'https://xn--bcher-kva.example/' }),
				serviceIdentity: { type: 'uri', value: 'https://bücher.example/' },
			}).ok,
		).toBe(true);
		expect(
			matchServiceIdentity({
				certificate: await presenting({ type: 'srv', value: '_imap.xn--bcher-kva.example' }),
				serviceIdentity: { type: 'srv', value: '_imap.bücher.example' },
			}).ok,
		).toBe(true);
	});
});
