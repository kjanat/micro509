import{_t as e,at as t,et as n,it as r,kt as i,n as a,ot as o,rt as s,xt as c}from"./chunks/framework.DvKJDiPS.js";var l=JSON.parse(`{"title":"Revocation","description":"","frontmatter":{"packageVersion":"0.10.0"},"headers":[],"relativePath":"guide/revocation.md","filePath":"site/versions/v0.10.0/guide/revocation.md","lastUpdated":0}`),u={name:`guide/revocation.md`};function d(a,l,u,d,f,p){let m=c(`LiveCode`);return e(),s(`div`,null,[l[6]||=r(`<h1 id="revocation" tabindex="-1">Revocation <a class="header-anchor" href="#revocation" aria-label="Permalink to “Revocation”">​</a></h1><p>The examples below build their own <code>ca</code>, <code>leaf</code>, CRL, and OCSP material inline so each one runs on its own.</p><div class="warning custom-block"><p class="custom-block-title">Revocation checking defaults to hard-fail</p><p>Revocation checking only runs when you supply evidence — and once you do, <code>RevocationPolicy.mode</code> defaults to <code>&#39;hard-fail&#39;</code>: certificates whose revocation status is <strong>indeterminate</strong> (no applicable CRL/OCSP evidence, expired evidence, untrusted signer) are <strong>denied</strong>. If availability matters more than strictness — partial evidence is normal in your setup — opt out explicitly with <code>policy: { mode: &#39;soft-fail&#39; }</code>, which allows indeterminate status and denies only on a confirmed <code>revoked</code> verdict.</p></div><h2 id="crl-lifecycle" tabindex="-1">CRL lifecycle <a class="header-anchor" href="#crl-lifecycle" aria-label="Permalink to “CRL lifecycle”">​</a></h2><h3 id="create-a-crl" tabindex="-1">Create a CRL <a class="header-anchor" href="#create-a-crl" aria-label="Permalink to “Create a CRL”">​</a></h3>`,5),o(m,null,{default:i(()=>[...l[0]||=[n(`div`,{"data-js":`import { createSelfSignedCertificate, createCertificateRevocationList, } from 'micro509';
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
    issuerPublicKey: ca.keyPair.publicKey,
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
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificateRevocationList,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'My CA'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    basicConstraints: { ca: `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    keyUsage: [`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCertSign'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'cRLSign'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` crl`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificateRevocationList`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuer: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'My CA'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerPublicKey: ca.keyPair.publicKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  thisUpdate: `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`new`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Date`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(),`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  nextUpdate: `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`new`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Date`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    Date.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`now`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`() `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`+`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 7`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` *`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 24`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` *`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 60`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` *`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 60`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` *`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 1000`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ),`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  revokedCertificates: [`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      serialNumber: Uint8Array.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`of`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`0x01`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`),`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      revocationDate: `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`new`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Date`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(),`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      reasonCode: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCompromise'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(crl.pem);`)])])])])],-1)]]),_:1}),l[7]||=n(`h3`,{id:`parse-and-verify-a-crl`,tabindex:`-1`},[t(`Parse and verify a CRL `),n(`a`,{class:`header-anchor`,href:`#parse-and-verify-a-crl`,"aria-label":`Permalink to “Parse and verify a CRL”`},`​`)],-1),o(m,null,{default:i(()=>[...l[1]||=[n(`div`,{"data-js":`import { createSelfSignedCertificate } from 'micro509';
import { createCertificateRevocationList, isCertificateRevoked, parseCertificateRevocationListPemOrThrow, verifyCertificateRevocationListSignature, } from 'micro509/revocation';
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
    issuerPublicKey: ca.keyPair.publicKey,
    revokedCertificates: [
        {
            serialNumber: Uint8Array.of(0x01),
            reasonCode: 'keyCompromise',
        },
    ],
});
const parsed = parseCertificateRevocationListPemOrThrow(crl.pem);
const verifyResult = await verifyCertificateRevocationListSignature(crl.pem, ca.certificate.pem);
console.log(\`\\
verified:   \${verifyResult.ok}
sig algo:   \${parsed.signatureAlgorithmName}
thisUpdate: \${parsed.thisUpdate.toISOString()}
entries:    \${parsed.revokedCertificates.length}
revoked 01: \${isCertificateRevoked('01', parsed)}\`);
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { createSelfSignedCertificate } `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificateRevocationList,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  isCertificateRevoked,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  parseCertificateRevocationListPemOrThrow,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  verifyCertificateRevocationListSignature,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509/revocation'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'My CA'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    basicConstraints: { ca: `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    keyUsage: [`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCertSign'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'cRLSign'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` crl`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificateRevocationList`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuer: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'My CA'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerPublicKey: ca.keyPair.publicKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  revokedCertificates: [`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      serialNumber: Uint8Array.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`of`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`0x01`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`),`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      reasonCode: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCompromise'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` parsed`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` parseCertificateRevocationListPemOrThrow`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  crl.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` verifyResult`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` verifyCertificateRevocationListSignature`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    crl.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    ca.certificate.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  );`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"verified:   ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`verifyResult`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`ok`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"sig algo:   ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`signatureAlgorithmName`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"thisUpdate: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`thisUpdate`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`toISOString`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`()`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"entries:    ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`revokedCertificates`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"revoked 01: ${"),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`isCertificateRevoked`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'01'`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`, `),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`)`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)])])])])],-1)]]),_:1}),l[8]||=n(`h2`,{id:`ocsp`,tabindex:`-1`},[t(`OCSP `),n(`a`,{class:`header-anchor`,href:`#ocsp`,"aria-label":`Permalink to “OCSP”`},`​`)],-1),l[9]||=n(`h3`,{id:`build-a-request`,tabindex:`-1`},[t(`Build a request `),n(`a`,{class:`header-anchor`,href:`#build-a-request`,"aria-label":`Permalink to “Build a request”`},`​`)],-1),o(m,null,{default:i(()=>[...l[2]||=[n(`div`,{"data-js":`import { createCertificate, createSelfSignedCertificate, generateKeyPair, } from 'micro509';
import { createOcspRequest } from 'micro509/revocation';
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
    issuerPublicKey: ca.keyPair.publicKey,
});
const request = await createOcspRequest({
    requests: [
        {
            certificate: leaf.pem,
            issuerCertificate: ca.certificate.pem,
        },
    ],
});
console.log(request.pem);
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  generateKeyPair,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { createOcspRequest } `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509/revocation'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    basicConstraints: { ca: `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    keyUsage: [`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCertSign'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'cRLSign'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leafKeys`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` generateKeyPair`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`();`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leaf`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuer: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'app.example.com'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  publicKey: leafKeys.publicKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerPublicKey: ca.keyPair.publicKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` request`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createOcspRequest`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  requests: [`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      certificate: leaf.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      issuerCertificate: ca.certificate.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(request.pem);`)])])])])],-1)]]),_:1}),l[10]||=n(`h3`,{id:`parse-and-validate-a-response`,tabindex:`-1`},[t(`Parse and validate a response `),n(`a`,{class:`header-anchor`,href:`#parse-and-validate-a-response`,"aria-label":`Permalink to “Parse and validate a response”`},`​`)],-1),o(m,null,{default:i(()=>[...l[3]||=[n(`div`,{"data-js":`import { createCertificate, createSelfSignedCertificate, generateKeyPair, } from 'micro509';
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
    issuerPublicKey: ca.keyPair.publicKey,
});
const request = await createOcspRequest({
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
    responses: [
        {
            certificate: leaf.pem,
            issuerCertificate: ca.certificate.pem,
            certStatus: 'good',
        },
    ],
});
const response = parseOcspResponseDerOrThrow(ocsp.der);
const result = await validateOcspResponse({
    response,
    request: request.der,
    issuerCertificate: ca.certificate.pem,
});
if (result.ok) {
    const entry = result.value.responses?.[0];
    console.log(\`\\
valid:      true
status:     \${entry?.certStatus}
sig algo:   \${response.signatureAlgorithmName}
producedAt: \${response.producedAt?.toISOString()}\`);
}
else {
    console.log(\`invalid: \${result.error.code}\`);
}
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  generateKeyPair,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createOcspRequest,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createOcspResponse,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  parseOcspResponseDerOrThrow,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  validateOcspResponse,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509/revocation'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    basicConstraints: { ca: `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    keyUsage: [`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCertSign'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'cRLSign'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leafKeys`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` generateKeyPair`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`();`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leaf`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuer: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'app.example.com'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  publicKey: leafKeys.publicKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerPublicKey: ca.keyPair.publicKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` request`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createOcspRequest`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  requests: [`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      certificate: leaf.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      issuerCertificate: ca.certificate.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Responder signs an OCSP response for the leaf`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ocsp`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createOcspResponse`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerCertificate: ca.certificate.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  responses: [`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      certificate: leaf.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      issuerCertificate: ca.certificate.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      certStatus: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'good'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` response`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` parseOcspResponseDerOrThrow`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(ocsp.der);`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` result`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` validateOcspResponse`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  response,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  request: request.der,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerCertificate: ca.certificate.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`if`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (result.ok) {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` entry`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` result.value.responses?.[`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`0`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`];`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`valid:      true`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"status:     ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`entry`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`certStatus`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"sig algo:   ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`response`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`signatureAlgorithmName`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"producedAt: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`response`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`producedAt`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`toISOString`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`()`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`else`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`invalid: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`result`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`error`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`code`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`}`)])])])])],-1)]]),_:1}),l[11]||=n(`h2`,{id:`orchestrated-revocation-check`,tabindex:`-1`},[t(`Orchestrated revocation check `),n(`a`,{class:`header-anchor`,href:`#orchestrated-revocation-check`,"aria-label":`Permalink to “Orchestrated revocation check”`},`​`)],-1),o(m,null,{default:i(()=>[...l[4]||=[n(`div`,{"data-js":`import { createCertificate, createSelfSignedCertificate, generateKeyPair, parseCertificatePem, unwrap, } from 'micro509';
import { checkCertificateRevocation, createCertificateRevocationList, createOcspResponse, } from 'micro509/revocation';
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
    issuerPublicKey: ca.keyPair.publicKey,
});
// Leaf serial as bytes for the CRL entry
const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
const serialHex = parsedLeaf.serialNumberHex;
const leafSerial = Uint8Array.from(serialHex.match(/.{2}/g) ?? [], (byte) => parseInt(byte, 16));
// CRL evidence that revokes the leaf
const crl = await createCertificateRevocationList({
    issuer: { commonName: 'Demo CA' },
    signerPrivateKey: ca.keyPair.privateKey,
    issuerPublicKey: ca.keyPair.publicKey,
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
// Check ok, then the status discriminator
if (!result.ok) {
    throw new Error('unreachable: evidence was supplied');
}
if (result.value.status === 'revoked') {
    console.log(\`\\
status:     revoked
serial:     \${serialHex}
revoked at: \${result.value.revokedAt?.toISOString()}\`);
}
else {
    console.log('status:', result.value.status);
}
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  generateKeyPair,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  parseCertificatePem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  unwrap,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  checkCertificateRevocation,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificateRevocationList,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createOcspResponse,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509/revocation'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    basicConstraints: { ca: `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    keyUsage: [`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCertSign'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'cRLSign'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leafKeys`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` generateKeyPair`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`();`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leaf`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuer: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'app.example.com'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  publicKey: leafKeys.publicKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerPublicKey: ca.keyPair.publicKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Leaf serial as bytes for the CRL entry`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` parsedLeaf`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` unwrap`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`parseCertificatePem`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(leaf.pem));`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` serialHex`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` parsedLeaf.serialNumberHex;`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leafSerial`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` Uint8Array.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`from`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  serialHex.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`match`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`/`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`.`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`{2}`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`/`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`g`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`) `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`??`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` [],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  (`),n(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`byte`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`) `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`=>`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` parseInt`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(byte, `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`16`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`),`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// CRL evidence that revokes the leaf`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` crl`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificateRevocationList`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuer: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerPublicKey: ca.keyPair.publicKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  revokedCertificates: [`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      serialNumber: leafSerial,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      revocationDate: `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`new`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Date`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(),`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      reasonCode: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCompromise'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// OCSP evidence that also reports revoked`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ocsp`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createOcspResponse`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerCertificate: ca.certificate.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  responses: [`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      certificate: leaf.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      issuerCertificate: ca.certificate.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      certStatus: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'revoked'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      revokedAt: `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`new`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Date`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(),`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` result`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` checkCertificateRevocation`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  certificate: leaf.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerCertificate: ca.certificate.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  evidence: [`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    { kind: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'crl'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, crl: crl.pem },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    { kind: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'ocsp'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, response: ocsp.der },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Check ok, then the status discriminator`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`if`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`!`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`result.ok) {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  throw`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` new`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Error`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'unreachable: evidence was supplied'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`if`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (result.value.status `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`===`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'revoked'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`) {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`status:     revoked`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"serial:     ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`serialHex`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"revoked at: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`result`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`value`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`revokedAt`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`toISOString`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`()`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`else`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'status:'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, result.value.status);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`}`)])])])])],-1)]]),_:1}),l[12]||=r(`<h2 id="chain-level-revocation" tabindex="-1">Chain-level revocation <a class="header-anchor" href="#chain-level-revocation" aria-label="Permalink to “Chain-level revocation”">​</a></h2><p><code>checkChainRevocation()</code> evaluates CRL <strong>and</strong> OCSP evidence for every certificate in a validated chain (the trust anchor is never checked). Each OCSP response is fully validated — signature, responder binding and authorization, freshness — before its verdict is trusted, and a validated <code>revoked</code> verdict from either evidence kind always wins, regardless of <code>policy.prefer</code>.</p><p>When both sources yield a validated <code>good</code> verdict, <code>policy.prefer</code> decides which one is reported: the default <code>&#39;best-available&#39;</code> picks the source with the fresher evidence (later <code>thisUpdate</code>, ties favoring OCSP), while <code>&#39;ocsp&#39;</code> and <code>&#39;crl&#39;</code> pin the reported source unconditionally. The winning evidence&#39;s timestamp is reported as <code>source.thisUpdate</code> on each certificate&#39;s status, so callers can enforce their own maximum evidence age.</p><p>The same inputs are available on <code>verifyCertificateChain()</code> via the <code>revocation</code> option:</p>`,4),o(m,null,{default:i(()=>[...l[5]||=[n(`div`,{"data-js":`import { createCertificate, createOcspResponse, createSelfSignedCertificate, generateKeyPair, verifyCertificateChain, } from 'micro509';
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
    issuerPublicKey: ca.keyPair.publicKey,
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
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createOcspResponse,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  generateKeyPair,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  verifyCertificateChain,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    basicConstraints: { ca: `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    keyUsage: [`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCertSign'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'cRLSign'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leafKeys`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` generateKeyPair`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`();`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leaf`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuer: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'app.example.com'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  publicKey: leafKeys.publicKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerPublicKey: ca.keyPair.publicKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ocsp`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createOcspResponse`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerCertificate: ca.certificate.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  responses: [`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      certificate: leaf.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      issuerCertificate: ca.certificate.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      certStatus: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'good'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      thisUpdate: `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`new`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Date`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(Date.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`now`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`() `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`-`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 60_000`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`),`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      nextUpdate: `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`new`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Date`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(Date.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`now`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`() `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`+`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 3_600_000`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`),`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` result`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` verifyCertificateChain`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  leaf: leaf.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  roots: [ca.certificate.pem],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  revocation: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`    // hard-fail is the default: indeterminate status ⇒ verification fails`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    ocspResponses: [ocsp.der],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`if`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (result.ok) {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` parsedLeaf`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` result.value.leaf;`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`verified: true`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"leaf:     ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsedLeaf`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`subject`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`values`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`commonName`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"serial:   ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsedLeaf`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`serialNumberHex`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"chain:    ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`result`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`value`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`chain`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"} certificates`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`else`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`verified: false (${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`result`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`error`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`code`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"})`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`}`)])])])])],-1)]]),_:1})])}var f=a(u,[[`render`,d]]);export{l as __pageData,f as default};