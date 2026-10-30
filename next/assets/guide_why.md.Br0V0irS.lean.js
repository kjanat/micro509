import{At as e,St as t,at as n,it as r,n as i,ot as a,st as o,tt as s,vt as c}from"./chunks/framework.BmH7hI6Z.js";var l=JSON.parse(`{"title":"Why micro509","description":"","frontmatter":{"packageVersion":"0.17.1"},"headers":[],"relativePath":"guide/why.md","filePath":"site/guide/why.md","lastUpdated":1793377943000}`),u={name:`guide/why.md`};function d(i,l,u,d,f,p){let m=t(`LiveCode`);return c(),r(`div`,null,[l[1]||=n("",7),o(m,null,{default:e(()=>[...l[0]||=[s(`div`,{"data-js":`import { certificateFingerprint, createSelfSignedCertificate, createCertificate, generateKeyPair, verifyCertificateChain, } from 'micro509';
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
    issuerCertificate: ca.certificate.pem,
    extensions: {
        subjectAltNames: [{ type: 'dns', value: 'app.example.com' }],
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
    const { hex } = await certificateFingerprint(leaf.pem);
    console.log(\`\\
code:    \${e.code}
message: \${e.message}
details: \${det}
leaf:    \${hex.slice(0, 40)}…\`);
}
// result.error.code is a typed union, e.g.:
//   'signature_invalid'
//   'certificate_expired'
//   'name_constraints_violated'
//   ... (the verification guide tables every code)
// result.error.index: which cert in the chain
//   failed
// result.error.details: { expected, actual }
//   for identity mismatches
`},[s(`div`,{class:`language-ts`,dir:`ltr`},[s(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),s(`span`,{class:`lang`},`ts`),s(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[s(`code`,null,[s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  certificateFingerprint,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificate,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  generateKeyPair,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  verifyCertificateChain,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Build a CA and leaf`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    basicConstraints: { ca: `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    keyUsage: [`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCertSign'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),a(`
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
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    subjectAltNames: [{ type: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'dns'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, value: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'app.example.com'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` }],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Verify against the wrong hostname`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` result`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` verifyCertificateChain`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  leaf: leaf.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  roots: [ca.certificate.pem],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  serviceIdentity: {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    type: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'dns'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    value: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'evil.example.com'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`if`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`!`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`result.ok) {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` e`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` result.error;`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` det`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` JSON`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`stringify`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(e.details, `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`null`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'  '`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`hex`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` } `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`=`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` certificateFingerprint`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(leaf.pem);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"code:    ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`e`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`code`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"message: ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`e`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`message`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"details: ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`det`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"leaf:    ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`hex`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`slice`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`(`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`0`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`, `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`40`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`)`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}…`"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`}`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// result.error.code is a typed union, e.g.:`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`//   'signature_invalid'`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`//   'certificate_expired'`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`//   'name_constraints_violated'`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`//   ... (the verification guide tables every code)`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// result.error.index: which cert in the chain`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`//   failed`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// result.error.details: { expected, actual }`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`//   for identity mismatches`)])])])])],-1)]]),_:1}),l[2]||=n("",5)])}var f=i(u,[[`render`,d]]);export{l as __pageData,f as default};