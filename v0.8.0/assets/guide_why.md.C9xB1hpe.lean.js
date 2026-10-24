import{_t as e,at as t,et as n,it as r,kt as i,n as a,ot as o,rt as s,xt as c}from"./chunks/framework.GQZN8auy.js";var l=JSON.parse(`{"title":"Why micro509","description":"","frontmatter":{"packageVersion":"0.8.0"},"headers":[],"relativePath":"guide/why.md","filePath":"site/versions/v0.8.0/guide/why.md","lastUpdated":0}`),u={name:`guide/why.md`};function d(a,l,u,d,f,p){let m=c(`LiveCode`);return e(),s(`div`,null,[l[1]||=r("",7),o(m,null,{default:i(()=>[...l[0]||=[n(`div`,{"data-js":`import { createSelfSignedCertificate, createCertificate, generateKeyPair, verifyCertificateChain, } from 'micro509';
// Build a CA and leaf
const ca = await createSelfSignedCertificate({
    subject: { commonName: 'Demo CA' },
    extensions: {
        basicConstraints: { ca: true },
        keyUsage: ['keyCertSign'],
    },
});
const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
    issuer: { commonName: 'Demo CA' },
    subject: { commonName: 'app.example.com' },
    publicKey: leafKeys.publicKey,
    signerPrivateKey: ca.keyPair.privateKey,
    issuerPublicKey: ca.keyPair.publicKey,
    extensions: {
        subjectAltNames: [
            { type: 'dns', value: 'app.example.com' },
        ],
    },
});
// Verify against the wrong hostname
const result = await verifyCertificateChain({
    leaf: leaf.pem,
    roots: [ca.certificate.pem],
    serviceIdentity: {
        type: 'dns',
        value: 'evil.example.com',
    },
});
if (!result.ok) {
    const e = result.error;
    const det = JSON.stringify(e.details, null, '  ');
    console.log(\`\\
code:    \${e.code}
message: \${e.message}
details: \${det}\`);
}
// result.error.code is a union of 21 codes, e.g.:
//   'signature_invalid'
//   'certificate_expired'
//   'name_constraints_violated'
//   ... (18 more)
// result.error.index: which cert in the chain
//   failed
// result.error.details: { expected, actual }
//   for identity mismatches
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  generateKeyPair,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  verifyCertificateChain,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Build a CA and leaf`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    basicConstraints: { ca: `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    keyUsage: [`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCertSign'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),t(`
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
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    subjectAltNames: [`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      { type: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'dns'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, value: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'app.example.com'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    ],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Verify against the wrong hostname`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` result`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` verifyCertificateChain`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  leaf: leaf.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  roots: [ca.certificate.pem],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  serviceIdentity: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    type: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'dns'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    value: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'evil.example.com'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`if`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`!`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`result.ok) {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` e`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` result.error;`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` det`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` JSON`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`stringify`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(e.details, `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`null`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'  '`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"code:    ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`e`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`code`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"message: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`e`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`message`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"details: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`det`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// result.error.code is a union of 21 codes, e.g.:`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`//   'signature_invalid'`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`//   'certificate_expired'`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`//   'name_constraints_violated'`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`//   ... (18 more)`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// result.error.index: which cert in the chain`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`//   failed`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// result.error.details: { expected, actual }`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`//   for identity mismatches`)])])])])],-1)]]),_:1}),l[2]||=r("",5)])}var f=a(u,[[`render`,d]]);export{l as __pageData,f as default};