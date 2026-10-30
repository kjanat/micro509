import{At as e,St as t,at as n,it as r,n as i,ot as a,st as o,tt as s,vt as c}from"./chunks/framework.aIoRY1TZ.js";var l=JSON.parse(`{"title":"Revocation","description":"","frontmatter":{"outline":[2,3],"packageVersion":"0.17.1"},"headers":[],"relativePath":"guide/revocation.md","filePath":"site/guide/revocation.md","lastUpdated":1792971609000}`),u={name:`guide/revocation.md`};function d(i,l,u,d,f,p){let m=t(`LiveCode`);return c(),r(`div`,null,[l[7]||=n("",6),o(m,null,{default:e(()=>[...l[0]||=[s(`div`,{"data-js":`import { createSelfSignedCertificate, createCertificateRevocationList, } from 'micro509';
const ca = await createSelfSignedCertificate({
    subject: { commonName: 'My CA' },
    extensions: {
        basicConstraints: { ca: true },
        keyUsage: ['keyCertSign', 'cRLSign'],
    },
});
const crl = await createCertificateRevocationList({
    issuer: { commonName: 'My CA' },
    signerPrivateKey: ca.keyPair.privateKey,
    issuerCertificate: ca.certificate.pem,
    crlNumber: 1,
    thisUpdate: new Date(),
    nextUpdate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    revokedCertificates: [
        {
            serialNumber: Uint8Array.of(0x01),
            revocationDate: new Date(),
            reasonCode: 'keyCompromise',
        },
    ],
});
console.log(crl.pem);
`},[s(`div`,{class:`language-ts`,dir:`ltr`},[s(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),s(`span`,{class:`lang`},`ts`),s(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[s(`code`,null,[s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificateRevocationList,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'My CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    basicConstraints: { ca: `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    keyUsage: [`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCertSign'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'cRLSign'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` crl`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificateRevocationList`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuer: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'My CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  crlNumber: `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`1`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  thisUpdate: `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`new`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Date`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(),`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  nextUpdate: `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`new`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Date`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(Date.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`now`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`() `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`+`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 7`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` *`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 24`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` *`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 60`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` *`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 60`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` *`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 1000`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`),`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  revokedCertificates: [`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      serialNumber: Uint8Array.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`of`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`0x01`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`),`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      revocationDate: `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`new`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Date`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(),`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      reasonCode: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCompromise'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(crl.pem);`)])])])])],-1)]]),_:1}),l[8]||=s(`h3`,{id:`crl-location-and-issuer-identity`,tabindex:`-1`},[a(`CRL location and issuer identity `),s(`a`,{class:`header-anchor`,href:`#crl-location-and-issuer-identity`,"aria-label":`Permalink to “CRL location and issuer identity”`},`​`)],-1),l[9]||=s(`p`,null,[a(`A URI in `),s(`code`,null,`distributionPoint.fullName`),a(` identifies where a CRL can be retrieved. The separate `),s(`code`,null,`cRLIssuer`),a(` field identifies its signer. Under RFC 5280 §4.2.1.13, that field may contain only the CRL issuer's `),s(`code`,null,`directoryName`),a(`, encoded exactly as the CRL's issuer Name. A semantically equivalent name with different DER encoding, or a list mixing a directory name with a URI, cannot authorize the CRL.`)],-1),l[10]||=s(`h3`,{id:`parse-and-validate-a-crl`,tabindex:`-1`},[a(`Parse and validate a CRL `),s(`a`,{class:`header-anchor`,href:`#parse-and-validate-a-crl`,"aria-label":`Permalink to “Parse and validate a CRL”`},`​`)],-1),o(m,null,{default:e(()=>[...l[1]||=[s(`div`,{"data-js":`import { createSelfSignedCertificate } from 'micro509';
import { createCertificateRevocationList, isCertificateRevoked, validateCertificateRevocationList, } from 'micro509/revocation';
const ca = await createSelfSignedCertificate({
    subject: { commonName: 'My CA' },
    extensions: {
        basicConstraints: { ca: true },
        keyUsage: ['keyCertSign', 'cRLSign'],
    },
});
const crl = await createCertificateRevocationList({
    issuer: { commonName: 'My CA' },
    signerPrivateKey: ca.keyPair.privateKey,
    issuerCertificate: ca.certificate.pem,
    crlNumber: 1,
    nextUpdate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    revokedCertificates: [
        {
            serialNumber: Uint8Array.of(0x01),
            reasonCode: 'keyCompromise',
        },
    ],
});
const validationResult = await validateCertificateRevocationList({
    crl: crl.pem,
    issuerCertificate: ca.certificate.pem,
});
if (!validationResult.ok) {
    console.log(\`validation failed: \${validationResult.code}\`);
}
else {
    const parsed = validationResult.value;
    const entry = parsed.revokedCertificates[0];
    const body = crl.pem.trimEnd().split('\\n').slice(1, -1).join('');
    console.log(\`\\
validated:  true
sig algo:   \${parsed.signatureAlgorithmName}
signature:  …\${body.slice(-44)}
thisUpdate: \${parsed.thisUpdate.toISOString()}
entry 01:   revoked \${entry?.revocationDate.toISOString().slice(0, 10)}, reason \${entry?.reasonCode}
revoked 01: \${isCertificateRevoked('01', parsed)}
revoked 02: \${isCertificateRevoked('02', parsed)}\`);
}
`},[s(`div`,{class:`language-ts`,dir:`ltr`},[s(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),s(`span`,{class:`lang`},`ts`),s(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[s(`code`,null,[s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { createSelfSignedCertificate } `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificateRevocationList,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  isCertificateRevoked,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  validateCertificateRevocationList,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509/revocation'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'My CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    basicConstraints: { ca: `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    keyUsage: [`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCertSign'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'cRLSign'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` crl`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificateRevocationList`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuer: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'My CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  crlNumber: `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`1`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  nextUpdate: `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`new`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Date`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(Date.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`now`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`() `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`+`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 7`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` *`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 24`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` *`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 60`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` *`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 60`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` *`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 1000`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`),`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  revokedCertificates: [`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      serialNumber: Uint8Array.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`of`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`0x01`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`),`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      reasonCode: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCompromise'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` validationResult`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` validateCertificateRevocationList`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  crl: crl.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`if`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`!`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`validationResult.ok) {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`validation failed: ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`validationResult`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`code`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`else`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` parsed`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` validationResult.value;`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` entry`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` parsed.revokedCertificates[`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`0`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`];`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` body`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` crl.pem.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`trimEnd`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`().`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`split`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\n`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`).`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`slice`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`1`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`-`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`1`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`).`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`join`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`''`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`validated:  true`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"sig algo:   ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`signatureAlgorithmName`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"signature:  …${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`body`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`slice`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`(`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`-`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`44`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`)`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"thisUpdate: ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`thisUpdate`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`toISOString`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`()`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"entry 01:   revoked ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`entry`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`revocationDate`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`toISOString`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`().`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`slice`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`(`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`0`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`, `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`10`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`)`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}, reason ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`entry`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`reasonCode`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"revoked 01: ${"),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`isCertificateRevoked`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'01'`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`, `),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`)`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"revoked 02: ${"),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`isCertificateRevoked`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'02'`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`, `),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`)`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`}`)])])])])],-1)]]),_:1}),l[11]||=n("",13),o(m,null,{default:e(()=>[...l[2]||=[s(`div`,{"data-js":`import { createCertificate, createSelfSignedCertificate, generateKeyPair, } from 'micro509';
import { createOcspRequest, parseOcspRequestDerOrThrow, } from 'micro509/revocation';
const ca = await createSelfSignedCertificate({
    subject: { commonName: 'Demo CA' },
    extensions: {
        basicConstraints: { ca: true },
        keyUsage: ['keyCertSign', 'cRLSign'],
    },
});
const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
    issuer: { commonName: 'Demo CA' },
    subject: { commonName: 'app.example.com' },
    publicKey: leafKeys.publicKey,
    signerPrivateKey: ca.keyPair.privateKey,
    issuerCertificate: ca.certificate.pem,
});
const request = await createOcspRequest({
    requests: [
        {
            certificate: leaf.pem,
            issuerCertificate: ca.certificate.pem,
        },
    ],
});
// Parse it back to see the CertID the responder will look up
const certId = parseOcspRequestDerOrThrow(request.der).requests[0];
console.log(\`\\
serial:   \${certId?.serialNumberHex}
hashed:   with \${certId?.hashAlgorithmName} (RFC 9919 default)
key hash: \${certId?.issuerKeyHashHex}\`);
console.log(request.pem);
`},[s(`div`,{class:`language-ts`,dir:`ltr`},[s(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),s(`span`,{class:`lang`},`ts`),s(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[s(`code`,null,[s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificate,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  generateKeyPair,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createOcspRequest,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  parseOcspRequestDerOrThrow,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509/revocation'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    basicConstraints: { ca: `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    keyUsage: [`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCertSign'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'cRLSign'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leafKeys`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` generateKeyPair`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`();`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leaf`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificate`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuer: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'app.example.com'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  publicKey: leafKeys.publicKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` request`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createOcspRequest`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  requests: [`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      certificate: leaf.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      issuerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Parse it back to see the CertID the responder will look up`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` certId`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` parseOcspRequestDerOrThrow`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(request.der).requests[`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`0`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`];`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"serial:   ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`certId`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`serialNumberHex`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"hashed:   with ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`certId`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`hashAlgorithmName`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`} (RFC 9919 default)`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"key hash: ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`certId`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`issuerKeyHashHex`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(request.pem);`)])])])])],-1)]]),_:1}),l[12]||=s(`h3`,{id:`parse-and-validate-a-response`,tabindex:`-1`},[a(`Parse and validate a response `),s(`a`,{class:`header-anchor`,href:`#parse-and-validate-a-response`,"aria-label":`Permalink to “Parse and validate a response”`},`​`)],-1),o(m,null,{default:e(()=>[...l[3]||=[s(`div`,{"data-js":`import { createCertificate, createSelfSignedCertificate, generateKeyPair, } from 'micro509';
import { createOcspRequest, createOcspResponse, parseOcspResponseDerOrThrow, validateOcspResponse, } from 'micro509/revocation';
const ca = await createSelfSignedCertificate({
    subject: { commonName: 'Demo CA' },
    extensions: {
        basicConstraints: { ca: true },
        keyUsage: ['keyCertSign', 'cRLSign'],
    },
});
const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
    issuer: { commonName: 'Demo CA' },
    subject: { commonName: 'app.example.com' },
    publicKey: leafKeys.publicKey,
    signerPrivateKey: ca.keyPair.privateKey,
    issuerCertificate: ca.certificate.pem,
});
const nonce = crypto.getRandomValues(new Uint8Array(16));
const nonceHex = Array.from(nonce, (byte) => byte.toString(16).padStart(2, '0')).join('');
const request = await createOcspRequest({
    nonce,
    requests: [
        {
            certificate: leaf.pem,
            issuerCertificate: ca.certificate.pem,
        },
    ],
});
// Responder signs an OCSP response for the leaf
const ocsp = await createOcspResponse({
    signerPrivateKey: ca.keyPair.privateKey,
    signerCertificate: ca.certificate.pem,
    nonce,
    responses: [
        {
            certificate: leaf.pem,
            issuerCertificate: ca.certificate.pem,
            certStatus: 'good',
        },
    ],
});
const response = parseOcspResponseDerOrThrow(ocsp.der);
// Verifies the signature, binds and authorizes the
// responder against the issuer, matches the nonce and
// every requested CertID, and checks freshness
const result = await validateOcspResponse({
    response,
    request: request.der,
    issuerCertificate: ca.certificate.pem,
});
if (result.ok) {
    const entry = result.value.responses?.[0];
    const responder = response.responderId;
    console.log(\`\\
status:     \${response.responseStatus}, \${entry?.certStatus}
serial:     \${entry?.certId.serialNumberHex}
certId:     hashed with \${entry?.certId.hashAlgorithmName} (RFC 9919 default)
responder:  \${responder?.type === 'byKeyHash' ? \`key hash \${responder.keyHashHex}\` : 'by name'}
signature:  \${response.signatureAlgorithmName}, verified
nonce:      \${response.nonce === nonceHex ? 'echoed' : response.nonce}
window:     \${entry?.thisUpdate.toISOString()} → \${entry?.nextUpdate?.toISOString() ?? 'no nextUpdate'}
producedAt: \${response.producedAt?.toISOString()}\`);
}
else {
    console.log(\`invalid: \${result.error.code}\`);
}
`},[s(`div`,{class:`language-ts`,dir:`ltr`},[s(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),s(`span`,{class:`lang`},`ts`),s(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[s(`code`,null,[s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificate,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  generateKeyPair,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createOcspRequest,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createOcspResponse,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  parseOcspResponseDerOrThrow,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  validateOcspResponse,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509/revocation'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    basicConstraints: { ca: `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    keyUsage: [`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCertSign'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'cRLSign'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leafKeys`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` generateKeyPair`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`();`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leaf`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificate`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuer: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'app.example.com'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  publicKey: leafKeys.publicKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` nonce`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` crypto.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`getRandomValues`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`new`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Uint8Array`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`16`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`));`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` nonceHex`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` Array.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`from`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(nonce, (`),s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`byte`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`) `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`=>`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  byte.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`toString`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`16`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`).`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`padStart`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`2`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'0'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`),`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`).`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`join`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`''`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` request`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createOcspRequest`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  nonce,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  requests: [`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      certificate: leaf.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      issuerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Responder signs an OCSP response for the leaf`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ocsp`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createOcspResponse`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  nonce,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  responses: [`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      certificate: leaf.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      issuerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      certStatus: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'good'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` response`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` parseOcspResponseDerOrThrow`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(ocsp.der);`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Verifies the signature, binds and authorizes the`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// responder against the issuer, matches the nonce and`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// every requested CertID, and checks freshness`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` result`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` validateOcspResponse`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  response,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  request: request.der,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`if`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (result.ok) {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` entry`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` result.value.responses?.[`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`0`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`];`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` responder`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` response.responderId;`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"status:     ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`response`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`responseStatus`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}, ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`entry`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`certStatus`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"serial:     ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`entry`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`certId`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`serialNumberHex`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"certId:     hashed with ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`entry`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`certId`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`hashAlgorithmName`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`} (RFC 9919 default)`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"responder:  ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`responder`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`type`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` ===`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'byKeyHash'`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` ?`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}}," `key hash ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`responder`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`keyHashHex`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` :`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'by name'}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"signature:  ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`response`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`signatureAlgorithmName`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}, verified`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"nonce:      ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`response`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`nonce`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` ===`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` nonceHex`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` ?`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'echoed'`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` :`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` response`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`nonce`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"window:     ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`entry`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`thisUpdate`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`toISOString`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`()`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"} → ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`entry`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`nextUpdate`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`toISOString`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`() `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`??`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'no nextUpdate'}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"producedAt: ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`response`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`producedAt`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`toISOString`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`()`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`else`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`invalid: ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`result`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`error`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`code`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`}`)])])])])],-1)]]),_:1}),l[13]||=n("",7),s(`details`,null,[l[5]||=s(`summary`,null,`Generate a certificate and evaluate CRL and OCSP evidence`,-1),o(m,null,{default:e(()=>[...l[4]||=[s(`div`,{"data-js":`import { createCertificate, createSelfSignedCertificate, generateKeyPair, parseCertificatePem, unwrap, } from 'micro509';
import { checkCertificateRevocation, createCertificateRevocationList, createOcspResponse, revocationReasonFromCode, } from 'micro509/revocation';
const ca = await createSelfSignedCertificate({
    subject: { commonName: 'Demo CA' },
    extensions: {
        basicConstraints: { ca: true },
        keyUsage: ['keyCertSign', 'cRLSign'],
    },
});
const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
    issuer: { commonName: 'Demo CA' },
    subject: { commonName: 'app.example.com' },
    publicKey: leafKeys.publicKey,
    signerPrivateKey: ca.keyPair.privateKey,
    issuerCertificate: ca.certificate.pem,
});
// Leaf serial as bytes for the CRL entry
const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
const serialHex = parsedLeaf.serialNumberHex;
const leafSerial = Uint8Array.from(serialHex.match(/.{2}/g) ?? [], (byte) => parseInt(byte, 16));
// CRL evidence that revokes the leaf
const crl = await createCertificateRevocationList({
    issuer: { commonName: 'Demo CA' },
    signerPrivateKey: ca.keyPair.privateKey,
    issuerCertificate: ca.certificate.pem,
    crlNumber: 1,
    nextUpdate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    revokedCertificates: [
        {
            serialNumber: leafSerial,
            revocationDate: new Date(),
            reasonCode: 'keyCompromise',
        },
    ],
});
// OCSP evidence that also reports revoked
const ocsp = await createOcspResponse({
    signerPrivateKey: ca.keyPair.privateKey,
    signerCertificate: ca.certificate.pem,
    responses: [
        {
            certificate: leaf.pem,
            issuerCertificate: ca.certificate.pem,
            certStatus: 'revoked',
            revokedAt: new Date(),
            revocationReasonCode: 1,
        },
    ],
});
const result = await checkCertificateRevocation({
    certificate: leaf.pem,
    issuerCertificate: ca.certificate.pem,
    evidence: [
        { kind: 'crl', crl: crl.pem },
        { kind: 'ocsp', response: ocsp.der },
    ],
});
// Evidence failures are represented by an indeterminate status.
const status = unwrap(result);
if (status.status === 'revoked') {
    // CRL evidence reports a RevocationReason name,
    // OCSP a raw CRLReason integer;
    // revocationReasonFromCode() maps the integer to
    // the same name so either path yields one answer
    const reason = status.revocationReason ??
        revocationReasonFromCode(status.revocationReasonCode);
    console.log(\`\\
status:     revoked
serial:     \${serialHex}
revoked at: \${status.revokedAt?.toISOString()}
reason:     \${reason}\`);
}
else {
    console.log('status:', status.status);
}
`},[s(`div`,{class:`language-ts`,dir:`ltr`},[s(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),s(`span`,{class:`lang`},`ts`),s(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[s(`code`,null,[s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificate,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  generateKeyPair,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  parseCertificatePem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  unwrap,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  checkCertificateRevocation,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificateRevocationList,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createOcspResponse,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  revocationReasonFromCode,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509/revocation'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    basicConstraints: { ca: `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    keyUsage: [`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCertSign'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'cRLSign'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leafKeys`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` generateKeyPair`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`();`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leaf`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificate`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuer: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'app.example.com'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  publicKey: leafKeys.publicKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Leaf serial as bytes for the CRL entry`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` parsedLeaf`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` unwrap`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`parseCertificatePem`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(leaf.pem));`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` serialHex`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` parsedLeaf.serialNumberHex;`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leafSerial`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` Uint8Array.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`from`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(serialHex.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`match`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`/`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`.`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`{2}`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`/`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`g`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`) `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`??`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` [], (`),s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`byte`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`) `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`=>`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`  parseInt`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(byte, `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`16`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`),`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// CRL evidence that revokes the leaf`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` crl`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificateRevocationList`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuer: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  crlNumber: `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`1`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  nextUpdate: `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`new`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Date`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(Date.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`now`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`() `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`+`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 7`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` *`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 24`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` *`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 60`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` *`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 60`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` *`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 1000`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`),`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  revokedCertificates: [`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      serialNumber: leafSerial,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      revocationDate: `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`new`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Date`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(),`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      reasonCode: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCompromise'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// OCSP evidence that also reports revoked`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ocsp`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createOcspResponse`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  responses: [`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      certificate: leaf.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      issuerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      certStatus: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'revoked'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      revokedAt: `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`new`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Date`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(),`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      revocationReasonCode: `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`1`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` result`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` checkCertificateRevocation`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  certificate: leaf.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  evidence: [`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    { kind: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'crl'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, crl: crl.pem },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    { kind: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'ocsp'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, response: ocsp.der },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Evidence failures are represented by an indeterminate status.`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` status`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` unwrap`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(result);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`if`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (status.status `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`===`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'revoked'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`) {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`  // CRL evidence reports a RevocationReason name,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`  // OCSP a raw CRLReason integer;`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`  // revocationReasonFromCode() maps the integer to`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`  // the same name so either path yields one answer`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` reason`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    status.revocationReason `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`??`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`    revocationReasonFromCode`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(status.revocationReasonCode);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`status:     revoked`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"serial:     ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`serialHex`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"revoked at: ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`status`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`revokedAt`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`toISOString`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`()`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"reason:     ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`reason`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`else`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'status:'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, status.status);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`}`)])])])])],-1)]]),_:1})]),l[14]||=n("",4),o(m,null,{default:e(()=>[...l[6]||=[s(`div`,{"data-js":`import { createCertificate, createOcspResponse, createSelfSignedCertificate, generateKeyPair, verifyCertificateChain, } from 'micro509';
const ca = await createSelfSignedCertificate({
    subject: { commonName: 'Demo CA' },
    extensions: {
        basicConstraints: { ca: true },
        keyUsage: ['keyCertSign', 'cRLSign'],
    },
});
const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
    issuer: { commonName: 'Demo CA' },
    subject: { commonName: 'app.example.com' },
    publicKey: leafKeys.publicKey,
    signerPrivateKey: ca.keyPair.privateKey,
    issuerCertificate: ca.certificate.pem,
});
const ocsp = await createOcspResponse({
    signerPrivateKey: ca.keyPair.privateKey,
    signerCertificate: ca.certificate.pem,
    responses: [
        {
            certificate: leaf.pem,
            issuerCertificate: ca.certificate.pem,
            certStatus: 'good',
            thisUpdate: new Date(Date.now() - 60_000),
            nextUpdate: new Date(Date.now() + 3_600_000),
        },
    ],
});
const result = await verifyCertificateChain({
    leaf: leaf.pem,
    roots: [ca.certificate.pem],
    revocation: {
        // hard-fail is the default: indeterminate status ⇒ verification fails
        ocspResponses: [ocsp.der],
    },
});
if (result.ok) {
    const parsedLeaf = result.value.leaf;
    console.log(\`\\
verified: true
leaf:     \${parsedLeaf.subject.values.commonName}
serial:   \${parsedLeaf.serialNumberHex}
chain:    \${result.value.chain.length} certificates\`);
}
else {
    console.log(\`verified: false (\${result.error.code})\`);
}
`},[s(`div`,{class:`language-ts`,dir:`ltr`},[s(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),s(`span`,{class:`lang`},`ts`),s(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[s(`code`,null,[s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificate,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createOcspResponse,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  generateKeyPair,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  verifyCertificateChain,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    basicConstraints: { ca: `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    keyUsage: [`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCertSign'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'cRLSign'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leafKeys`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` generateKeyPair`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`();`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leaf`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificate`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuer: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'app.example.com'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  publicKey: leafKeys.publicKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ocsp`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createOcspResponse`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  responses: [`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      certificate: leaf.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      issuerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      certStatus: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'good'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      thisUpdate: `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`new`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Date`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(Date.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`now`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`() `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`-`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 60_000`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`),`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      nextUpdate: `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`new`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Date`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(Date.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`now`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`() `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`+`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 3_600_000`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`),`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` result`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` verifyCertificateChain`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  leaf: leaf.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  roots: [ca.certificate.pem],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  revocation: {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`    // hard-fail is the default: indeterminate status ⇒ verification fails`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    ocspResponses: [ocsp.der],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`if`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (result.ok) {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` parsedLeaf`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` result.value.leaf;`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`verified: true`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"leaf:     ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsedLeaf`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`subject`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`values`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`commonName`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"serial:   ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsedLeaf`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`serialNumberHex`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"chain:    ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`result`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`value`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`chain`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"} certificates`"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`else`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`verified: false (${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`result`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`error`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`code`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"})`"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`}`)])])])])],-1)]]),_:1})])}var f=i(u,[[`render`,d]]);export{l as __pageData,f as default};