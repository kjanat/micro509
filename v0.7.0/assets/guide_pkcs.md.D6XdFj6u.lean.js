import{_t as e,at as t,et as n,it as r,kt as i,n as a,ot as o,rt as s,xt as c}from"./chunks/framework.Bkm_XFEM.js";var l=JSON.parse(`{"title":"PKCS","description":"","frontmatter":{"packageVersion":"0.7.0"},"headers":[],"relativePath":"guide/pkcs.md","filePath":"site/versions/v0.7.0/guide/pkcs.md","lastUpdated":0}`),u={name:`guide/pkcs.md`};function d(a,l,u,d,f,p){let m=c(`LiveCode`);return e(),s(`div`,null,[l[6]||=r("",3),o(m,null,{default:i(()=>[...l[0]||=[n(`div`,{"data-js":`import { createSelfSignedCertificate, unwrap, } from 'micro509';
import { createPfx } from 'micro509/pkcs';
const ca = await createSelfSignedCertificate({
    subject: { commonName: 'Demo CA' },
    extensions: { basicConstraints: { ca: true } },
});
const cert = await createSelfSignedCertificate({
    subject: { commonName: 'leaf.example' },
});
// createPfx returns a typed result; unwrap once inputs are validated
const pfx = unwrap(await createPfx({
    certificates: [
        { certificate: cert.certificate.pem },
        { certificate: ca.certificate.pem },
    ],
    privateKeys: [{ privateKey: cert.keyPair.privateKey }],
    encryption: { password: 'secret' },
    mac: { password: 'secret' },
}));
console.log(\`\\
der bytes:  \${pfx.der.length}
base64 len: \${pfx.base64.length}\`);
console.log(pfx.pem);
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  unwrap,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { createPfx } `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509/pkcs'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Demo CA'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: { basicConstraints: { ca: `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` } },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` cert`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'leaf.example'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// createPfx returns a typed result; unwrap once inputs are validated`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` pfx`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` unwrap`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createPfx`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    certificates: [`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      { certificate: cert.certificate.pem },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      { certificate: ca.certificate.pem },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    ],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    privateKeys: [{ privateKey: cert.keyPair.privateKey }],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    encryption: { password: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'secret'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    mac: { password: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'secret'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  }),`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"der bytes:  ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`pfx`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`der`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"base64 len: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`pfx`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`base64`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(pfx.pem);`)])])])])],-1)]]),_:1}),l[7]||=n(`h3`,{id:`parse-a-pfx-bundle`,tabindex:`-1`},[t(`Parse a PFX bundle `),n(`a`,{class:`header-anchor`,href:`#parse-a-pfx-bundle`,"aria-label":`Permalink to “Parse a PFX bundle”`},`​`)],-1),o(m,null,{default:i(()=>[...l[1]||=[n(`div`,{"data-js":`import { createSelfSignedCertificate, unwrap, } from 'micro509';
import { createPfx, parsePfxDer } from 'micro509/pkcs';
// Build a PFX inline to parse back
const cert = await createSelfSignedCertificate({
    subject: { commonName: 'leaf.example' },
});
const pfx = unwrap(await createPfx({
    certificates: [{ certificate: cert.certificate.pem }],
    privateKeys: [{ privateKey: cert.keyPair.privateKey }],
    encryption: { password: 'secret' },
    mac: { password: 'secret' },
}));
const result = await parsePfxDer(pfx.der, {
    password: 'secret',
});
if (result.ok) {
    const { certificates, privateKeys, bags } = result.value;
    const leafCert = certificates[0];
    console.log(\`\\
certs:        \${certificates.length}
private keys: \${privateKeys.length}
bags:         \${bags.length}
subject:      \${leafCert?.subject.values.commonName}
\`);
}
else {
    console.log(\`parse failed: \${result.error.code}\`);
}
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  unwrap,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { createPfx, parsePfxDer } `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509/pkcs'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Build a PFX inline to parse back`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` cert`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'leaf.example'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` pfx`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` unwrap`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createPfx`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    certificates: [{ certificate: cert.certificate.pem }],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    privateKeys: [{ privateKey: cert.keyPair.privateKey }],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    encryption: { password: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'secret'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    mac: { password: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'secret'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  }),`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` result`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` parsePfxDer`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(pfx.der, {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  password: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'secret'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`if`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (result.ok) {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`certificates`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`privateKeys`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`bags`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` } `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`=`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` result.value;`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leafCert`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` certificates[`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`0`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`];`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"certs:        ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`certificates`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"private keys: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`privateKeys`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"bags:         ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`bags`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"subject:      ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`leafCert`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`subject`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`values`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`commonName`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`else`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`parse failed: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`result`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`error`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`code`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`}`)])])])])],-1)]]),_:1}),l[8]||=n(`h2`,{id:`pkcs-7-cms`,tabindex:`-1`},[t(`PKCS#7 / CMS `),n(`a`,{class:`header-anchor`,href:`#pkcs-7-cms`,"aria-label":`Permalink to “PKCS#7 / CMS”`},`​`)],-1),l[9]||=n(`h3`,{id:`create-a-certificate-bag`,tabindex:`-1`},[t(`Create a certificate bag `),n(`a`,{class:`header-anchor`,href:`#create-a-certificate-bag`,"aria-label":`Permalink to “Create a certificate bag”`},`​`)],-1),o(m,null,{default:i(()=>[...l[2]||=[n(`div`,{"data-js":`import { createSelfSignedCertificate, unwrap, } from 'micro509';
import { createPkcs7CertBag } from 'micro509/pkcs';
// Two real certificates to bundle
const a = await createSelfSignedCertificate({
    subject: { commonName: 'a.example' },
});
const b = await createSelfSignedCertificate({
    subject: { commonName: 'b.example' },
});
// createPkcs7CertBag returns a typed result; unwrap on the success path
const bag = unwrap(createPkcs7CertBag([
    a.certificate.pem,
    b.certificate.pem,
]));
console.log(\`der bytes: \${bag.der.length}\`);
console.log(bag.pem);
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  unwrap,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { createPkcs7CertBag } `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509/pkcs'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Two real certificates to bundle`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` a`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'a.example'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` b`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'b.example'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// createPkcs7CertBag returns a typed result; unwrap on the success path`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` bag`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` unwrap`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`  createPkcs7CertBag`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`([`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    a.certificate.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    b.certificate.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ]),`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`der bytes: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`bag`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`der`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(bag.pem);`)])])])])],-1)]]),_:1}),l[10]||=n(`h3`,{id:`parse-a-certificate-bag`,tabindex:`-1`},[t(`Parse a certificate bag `),n(`a`,{class:`header-anchor`,href:`#parse-a-certificate-bag`,"aria-label":`Permalink to “Parse a certificate bag”`},`​`)],-1),o(m,null,{default:i(()=>[...l[3]||=[n(`div`,{"data-js":`import { createSelfSignedCertificate, unwrap, } from 'micro509';
import { createPkcs7CertBag, parsePkcs7CertBagPem, } from 'micro509/pkcs';
// Build a real cert bag inline
const a = await createSelfSignedCertificate({
    subject: { commonName: 'a.example' },
});
const b = await createSelfSignedCertificate({
    subject: { commonName: 'b.example' },
});
const bag = unwrap(createPkcs7CertBag([
    a.certificate.pem,
    b.certificate.pem,
]));
const result = parsePkcs7CertBagPem(bag.pem);
if (result.ok) {
    const certificates = result.value;
    console.log(\`certs: \${certificates.length}\`);
    for (const cert of certificates) {
        console.log(cert.subject.values.commonName);
    }
}
else {
    console.log(\`parse failed: \${result.error.code}\`);
}
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  unwrap,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createPkcs7CertBag,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  parsePkcs7CertBagPem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509/pkcs'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Build a real cert bag inline`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` a`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'a.example'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` b`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'b.example'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` bag`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` unwrap`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`  createPkcs7CertBag`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`([`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    a.certificate.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    b.certificate.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ]),`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` result`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` parsePkcs7CertBagPem`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(bag.pem);`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`if`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (result.ok) {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` certificates`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` result.value;`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`certs: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`certificates`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  for`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` cert`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` of`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` certificates) {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(cert.subject.values.commonName);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  }`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`else`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`parse failed: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`result`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`error`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`code`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`}`)])])])])],-1)]]),_:1}),l[11]||=n(`h3`,{id:`sign-and-verify-content`,tabindex:`-1`},[t(`Sign and verify content `),n(`a`,{class:`header-anchor`,href:`#sign-and-verify-content`,"aria-label":`Permalink to “Sign and verify content”`},`​`)],-1),o(m,null,{default:i(()=>[...l[4]||=[n(`div`,{"data-js":`import { createSelfSignedCertificate } from 'micro509';
import { createPkcs7SignedData, verifyPkcs7SignedData, } from 'micro509/pkcs';
// A signer is a certificate + its matching private key
const signer = await createSelfSignedCertificate({
    subject: { commonName: 'signer.example' },
    extensions: { keyUsage: ['digitalSignature'] },
});
// Sign content -> attached CMS SignedData (RFC 5652)
const content = new TextEncoder().encode('hello');
const signed = await createPkcs7SignedData({
    content,
    signers: [
        {
            certificate: signer.certificate.pem,
            privateKey: signer.keyPair.privateKey,
        },
    ],
});
// Creation returns a typed result; verify on success
if (!signed.ok) {
    console.log(\`sign failed: \${signed.error.code}\`);
}
else {
    const result = await verifyPkcs7SignedData(signed.value.pem);
    if (result.ok) {
        const sd = result.value;
        const info = sd.signerInfos[0];
        console.log('verified: true');
        console.log(\`\\
signers:  \${sd.signerInfos.length}
digest:   \${info?.digestAlgorithmName}\`);
    }
    else {
        console.log(\`verify: \${result.error.code}\`);
    }
}
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { createSelfSignedCertificate } `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createPkcs7SignedData,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  verifyPkcs7SignedData,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509/pkcs'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// A signer is a certificate + its matching private key`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` signer`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'signer.example'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: { keyUsage: [`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'digitalSignature'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`] },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Sign content -> attached CMS SignedData (RFC 5652)`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` content`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` new`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` TextEncoder`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`().`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`encode`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'hello'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` signed`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createPkcs7SignedData`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  content,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signers: [`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      certificate: signer.certificate.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      privateKey: signer.keyPair.privateKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Creation returns a typed result; verify on success`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`if`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`!`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`signed.ok) {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`sign failed: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`signed`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`error`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`code`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`else`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` result`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` verifyPkcs7SignedData`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    signed.value.pem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  );`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  if`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (result.ok) {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`    const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` sd`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` result.value;`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`    const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` info`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` sd.signerInfos[`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`0`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`];`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'verified: true'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"signers:  ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`sd`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`signerInfos`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"digest:   ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`info`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`digestAlgorithmName`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  } `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`else`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`verify: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`result`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`error`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`code`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  }`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`}`)])])])])],-1)]]),_:1}),l[12]||=n(`h2`,{id:`pem-utilities`,tabindex:`-1`},[t(`PEM utilities `),n(`a`,{class:`header-anchor`,href:`#pem-utilities`,"aria-label":`Permalink to “PEM utilities”`},`​`)],-1),o(m,null,{default:i(()=>[...l[5]||=[n(`div`,{"data-js":`import { createSelfSignedCertificate } from 'micro509';
import { categorizePemBlocks, pemDecode, pemEncode, splitPemBlocks, } from 'micro509/pem';
// A real certificate to feed the PEM helpers
const { certificate } = await createSelfSignedCertificate({
    subject: { commonName: 'pem.example' },
});
const pem = certificate.pem;
// Decode a single PEM block to DER
const der = pemDecode('CERTIFICATE', pem);
// Encode DER back to PEM
const pemEncoded = pemEncode('CERTIFICATE', der);
// Split a multi-block PEM file
const multiPem = \`\${pem}\\n\${pem}\`;
const blocks = splitPemBlocks(multiPem);
// Categorize blocks by type
const { certificates, certificateRequests, privateKeys } = categorizePemBlocks(multiPem);
console.log(\`\\
der bytes:    \${der.length}
round-trip:   \${pemEncoded === pem}
blocks:       \${blocks.length}
certs:        \${certificates.length}
csrs:         \${certificateRequests.length}
private keys: \${privateKeys.length}\`);
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { createSelfSignedCertificate } `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  categorizePemBlocks,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  pemDecode,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  pemEncode,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  splitPemBlocks,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509/pem'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// A real certificate to feed the PEM helpers`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`certificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` } `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`=`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'pem.example'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` pem`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` certificate.pem;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Decode a single PEM block to DER`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` der`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` pemDecode`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'CERTIFICATE'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, pem);`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Encode DER back to PEM`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` pemEncoded`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` pemEncode`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'CERTIFICATE'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, der);`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Split a multi-block PEM file`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` multiPem`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}}," `${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`pem`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\n`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`pem`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` blocks`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` splitPemBlocks`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(multiPem);`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Categorize blocks by type`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`certificates`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`certificateRequests`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`privateKeys`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` } `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`=`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`  categorizePemBlocks`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(multiPem);`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"der bytes:    ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`der`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"round-trip:   ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`pemEncoded`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` ===`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` pem`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"blocks:       ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`blocks`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"certs:        ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`certificates`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"csrs:         ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`certificateRequests`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"private keys: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`privateKeys`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)])])])])],-1)]]),_:1})])}var f=a(u,[[`render`,d]]);export{l as __pageData,f as default};