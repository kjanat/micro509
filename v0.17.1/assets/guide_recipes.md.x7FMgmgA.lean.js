import{At as e,St as t,at as n,it as r,n as i,ot as a,st as o,tt as s,vt as c}from"./chunks/framework.aIoRY1TZ.js";var l=JSON.parse(`{"title":"Recipes","description":"","frontmatter":{"packageVersion":"0.17.1"},"headers":[],"relativePath":"guide/recipes.md","filePath":"site/guide/recipes.md","lastUpdated":1792971609000}`),u={name:`guide/recipes.md`};function d(i,l,u,d,f,p){let m=t(`LiveCode`);return c(),r(`div`,null,[l[3]||=n("",4),o(m,null,{default:e(()=>[...l[0]||=[s(`div`,{"data-js":`import { createCertificate, createSelfSignedCertificate, generateKeyPair, verifyCertificateChain, } from 'micro509';
async function verifyServer(leafPem, intermediatePems, trustedRootPems, hostname) {
    const result = await verifyCertificateChain({
        leaf: leafPem,
        intermediates: intermediatePems,
        roots: trustedRootPems,
        purpose: 'serverAuth',
        serviceIdentity: { type: 'dns', value: hostname },
    });
    if (!result.ok) {
        return {
            ok: false,
            code: result.error.code,
            index: result.error.index,
            details: result.error.details,
            message: result.error.message,
        };
    }
    return {
        ok: true,
        subject: result.value.leaf.subject.values.commonName,
        serialNumber: result.value.leaf.serialNumberHex,
        chainLength: result.value.chain.length,
    };
}
const ca = await createSelfSignedCertificate({
    subject: { commonName: 'Recipe CA' },
    extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] },
});
const keys = await generateKeyPair();
const leaf = await createCertificate({
    issuer: { commonName: 'Recipe CA' },
    subject: { commonName: 'app.example.com' },
    publicKey: keys.publicKey,
    signerPrivateKey: ca.keyPair.privateKey,
    issuerCertificate: ca.certificate.pem,
    extensions: {
        extendedKeyUsage: ['serverAuth'],
        subjectAltNames: [{ type: 'dns', value: 'app.example.com' }],
    },
});
console.log(await verifyServer(leaf.pem, [], [ca.certificate.pem], 'app.example.com'));
console.log(await verifyServer(leaf.pem, [], [ca.certificate.pem], 'wrong.example.com'));
`},[s(`div`,{class:`language-ts`,dir:`ltr`},[s(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),s(`span`,{class:`lang`},`ts`),s(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[s(`code`,null,[s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificate,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  generateKeyPair,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  verifyCertificateChain,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`async`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` function`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` verifyServer`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`  leafPem`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`:`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` string`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`  intermediatePems`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`:`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` readonly`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` string`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`[],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`  trustedRootPems`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`:`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` readonly`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` string`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`[],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`  hostname`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`:`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` string`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`) {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` result`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` verifyCertificateChain`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    leaf: leafPem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    intermediates: intermediatePems,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    roots: trustedRootPems,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    purpose: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'serverAuth'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    serviceIdentity: { type: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'dns'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, value: hostname },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  });`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  if`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`!`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`result.ok) {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`    return`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      ok: `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`false`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` as`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` const`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      code: result.error.code,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      index: result.error.index,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      details: result.error.details,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      message: result.error.message,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    };`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  }`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  return`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    ok: `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` as`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` const`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    subject: result.value.leaf.subject.values.commonName,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    serialNumber: result.value.leaf.serialNumberHex,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    chainLength: result.value.chain.`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  };`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`}`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Recipe CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: { basicConstraints: { ca: `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` }, keyUsage: [`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCertSign'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`] },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` keys`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` generateKeyPair`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`();`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leaf`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificate`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuer: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Recipe CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'app.example.com'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  publicKey: keys.publicKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerCertificate: ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    extendedKeyUsage: [`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'serverAuth'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    subjectAltNames: [{ type: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'dns'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, value: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'app.example.com'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` }],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` verifyServer`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(leaf.pem, [], [ca.certificate.pem], `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'app.example.com'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`),`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` verifyServer`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(leaf.pem, [], [ca.certificate.pem], `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'wrong.example.com'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`),`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)])])])])],-1)]]),_:1}),l[4]||=n("",3),o(m,null,{default:e(()=>[...l[1]||=[s(`div`,{"data-js":`import { createCertificate, createCertificateSigningRequest, createSelfSignedCertificate, generateKeyPair, getSubjectPublicKeyOrThrow, verifyCertificateSigningRequest, } from 'micro509';
async function issueApprovedServerCsr(csrPem, approvedDnsNames, issuerName, issuerCertificatePem, issuerPrivateKey) {
    const checked = await verifyCertificateSigningRequest(csrPem);
    if (!checked.ok) {
        throw new Error(\`CSR rejected: \${checked.error.code}\`);
    }
    const requestedCommonName = checked.value.subject.values.commonName;
    const requestedSans = checked.value.subjectAltNames ?? [];
    const requestedDnsNames = requestedSans
        .filter((name) => name.type === 'dns')
        .map((name) => name.value);
    if (requestedCommonName === undefined ||
        requestedDnsNames.length === 0 ||
        requestedDnsNames.some((name) => !approvedDnsNames.includes(name) || name !== requestedCommonName)) {
        throw new Error('CSR names are not approved');
    }
    const publicKey = await getSubjectPublicKeyOrThrow(checked.value);
    return createCertificate({
        issuer: issuerName,
        subject: { commonName: requestedCommonName },
        publicKey,
        signerPrivateKey: issuerPrivateKey,
        issuerCertificate: issuerCertificatePem,
        extensions: {
            extendedKeyUsage: ['serverAuth'],
            subjectAltNames: requestedDnsNames.map((value) => ({
                type: 'dns',
                value,
            })),
        },
    });
}
const ca = await createSelfSignedCertificate({
    subject: { commonName: 'Recipe CA' },
    extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] },
});
const keys = await generateKeyPair();
const csr = await createCertificateSigningRequest({
    subject: { commonName: 'app.example.com' },
    publicKey: keys.publicKey,
    signerPrivateKey: keys.privateKey,
    extensions: { subjectAltNames: [{ type: 'dns', value: 'app.example.com' }] },
});
const issued = await issueApprovedServerCsr(csr.pem, ['app.example.com'], { commonName: 'Recipe CA' }, ca.certificate.pem, ca.keyPair.privateKey);
console.log('Issued certificate:');
console.log(issued.pem);
`},[s(`div`,{class:`language-ts`,dir:`ltr`},[s(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),s(`span`,{class:`lang`},`ts`),s(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[s(`code`,null,[s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificate,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificateSigningRequest,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  generateKeyPair,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  getSubjectPublicKeyOrThrow,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  verifyCertificateSigningRequest,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`async`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` function`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` issueApprovedServerCsr`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`  csrPem`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`:`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` string`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`  approvedDnsNames`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`:`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` readonly`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` string`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`[],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`  issuerName`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`:`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`readonly`),s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},` commonName`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`:`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` string`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`  issuerCertificatePem`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`:`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` string`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`  issuerPrivateKey`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`:`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` CryptoKey`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`) {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` checked`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` verifyCertificateSigningRequest`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(csrPem);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  if`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`!`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`checked.ok) {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`    throw`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` new`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Error`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`CSR rejected: ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`checked`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`error`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`code`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  }`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` requestedCommonName`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` checked.value.subject.values.commonName;`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` requestedSans`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` checked.value.subjectAltNames `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`??`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` [];`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` requestedDnsNames`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` requestedSans`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    .`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`filter`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`((`),s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`name`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`) `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`=>`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` name.type `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`===`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'dns'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`)`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    .`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`map`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`((`),s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`name`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`) `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`=>`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` name.value);`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  if`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    requestedCommonName `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`===`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` undefined`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` ||`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    requestedDnsNames.`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`length`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` ===`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` 0`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` ||`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    requestedDnsNames.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`some`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      (`),s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`name`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`) `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`=>`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`        !`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`approvedDnsNames.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`includes`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(name) `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`||`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` name `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`!==`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` requestedCommonName,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    )`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ) {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`    throw`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` new`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Error`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'CSR names are not approved'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  }`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` publicKey`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` getSubjectPublicKeyOrThrow`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(checked.value);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  return`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificate`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    issuer: issuerName,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    subject: { commonName: requestedCommonName },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    publicKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    signerPrivateKey: issuerPrivateKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    issuerCertificate: issuerCertificatePem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    extensions: {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      extendedKeyUsage: [`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'serverAuth'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      subjectAltNames: requestedDnsNames.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`map`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`((`),s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`value`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`) `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`=>`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` ({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`        type: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'dns'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`        value,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      })),`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  });`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`}`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Recipe CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: { basicConstraints: { ca: `),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` }, keyUsage: [`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCertSign'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`] },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` keys`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` generateKeyPair`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`();`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` csr`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificateSigningRequest`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'app.example.com'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  publicKey: keys.publicKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: keys.privateKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: { subjectAltNames: [{ type: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'dns'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, value: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'app.example.com'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` }] },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` issued`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` issueApprovedServerCsr`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  csr.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  [`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'app.example.com'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Recipe CA'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ca.certificate.pem,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  ca.keyPair.privateKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Issued certificate:'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(issued.pem);`)])])])])],-1)]]),_:1}),l[5]||=s(`p`,null,`This deliberately constructs the issued extensions from approved values rather than copying the CSR's complete extension request. Add policy checks for the subject and any other requested fields your enrollment flow accepts.`,-1),l[6]||=s(`h2`,{id:`import-a-client-identity-from-pfx`,tabindex:`-1`},[a(`Import a client identity from PFX `),s(`a`,{class:`header-anchor`,href:`#import-a-client-identity-from-pfx`,"aria-label":`Permalink to “Import a client identity from PFX”`},`​`)],-1),l[7]||=s(`p`,null,`Parse a password-protected PFX, import its PKCS#8 keys, and compare each key against the available certificates. Pair by cryptographic key match instead of assuming bag order identifies the client certificate.`,-1),o(m,null,{default:e(()=>[...l[2]||=[s(`div`,{"data-js":`import { createSelfSignedCertificate, matchCertificatePrivateKey, unwrap, } from 'micro509';
import { importPkcs8DerOrThrow } from 'micro509/keys';
import { createPfx, parsePfxDer } from 'micro509/pkcs';
async function importClientIdentity(pfxDer, password) {
    const parsed = await parsePfxDer(pfxDer, { password });
    if (!parsed.ok) {
        throw new Error(\`PFX could not be read: \${parsed.error.code}\`);
    }
    for (const pkcs8Der of parsed.value.privateKeys) {
        const privateKey = await importPkcs8DerOrThrow(pkcs8Der);
        for (const certificate of parsed.value.certificates) {
            const match = await matchCertificatePrivateKey(certificate, privateKey);
            if (match.ok) {
                return { certificate, privateKey };
            }
        }
    }
    throw new Error('PFX contains no matching private key and certificate');
}
const original = await createSelfSignedCertificate({
    subject: { commonName: 'client.example.com' },
    extensions: { extendedKeyUsage: ['clientAuth'] },
});
const pfx = unwrap(await createPfx({
    certificates: [{ certificate: original.certificate.pem }],
    privateKeys: [{ privateKey: original.keyPair.privateKey }],
    encryption: { password: 'demo-password' },
    mac: { password: 'demo-password' },
}));
const identity = await importClientIdentity(pfx.der, 'demo-password');
console.log('Imported identity:', {
    subject: identity.certificate.subject.values,
    serialNumber: identity.certificate.serialNumberHex,
    privateKey: {
        type: identity.privateKey.type,
        algorithm: identity.privateKey.algorithm,
        usages: identity.privateKey.usages,
    },
});
`},[s(`div`,{class:`language-ts`,dir:`ltr`},[s(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),s(`span`,{class:`lang`},`ts`),s(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[s(`code`,null,[s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  matchCertificatePrivateKey,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  unwrap,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { importPkcs8DerOrThrow } `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509/keys'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { createPfx, parsePfxDer } `),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509/pkcs'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`async`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` function`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` importClientIdentity`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`pfxDer`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`:`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Uint8Array`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),s(`span`,{style:{"--shiki-light":`#c13617`,"--shiki-dark":`#FFAB70`}},`password`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`:`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` string`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`) {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` parsed`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` parsePfxDer`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(pfxDer, { password });`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  if`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`!`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed.ok) {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`    throw`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` new`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Error`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`PFX could not be read: ${"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`error`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`code`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  }`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  for`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` pkcs8Der`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` of`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` parsed.value.privateKeys) {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`    const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` privateKey`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` importPkcs8DerOrThrow`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(pkcs8Der);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`    for`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` certificate`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` of`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` parsed.value.certificates) {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`      const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` match`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` matchCertificatePrivateKey`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(certificate, privateKey);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`      if`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` (match.ok) {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`        return`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { certificate, privateKey };`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      }`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    }`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  }`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  throw`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` new`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` Error`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'PFX contains no matching private key and certificate'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`}`)]),a(`
`),s(`span`,{class:`line`}),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` original`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'client.example.com'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: { extendedKeyUsage: [`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'clientAuth'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`] },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` pfx`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` unwrap`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createPfx`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    certificates: [{ certificate: original.certificate.pem }],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    privateKeys: [{ privateKey: original.keyPair.privateKey }],`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    encryption: { password: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'demo-password'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    mac: { password: `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'demo-password'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  }),`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),s(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` identity`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),s(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` importClientIdentity`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(pfx.der, `),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'demo-password'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),s(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),s(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Imported identity:'`),s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: identity.certificate.subject.values,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  serialNumber: identity.certificate.serialNumberHex,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  privateKey: {`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    type: identity.privateKey.type,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    algorithm: identity.privateKey.algorithm,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    usages: identity.privateKey.usages,`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),a(`
`),s(`span`,{class:`line`},[s(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)])])])])],-1)]]),_:1}),l[8]||=s(`p`,null,`The parser verifies the PFX MAC when one is present and a password is supplied. This recipe establishes that the returned private key belongs to the returned certificate. Validate the certificate chain and client-auth purpose separately against the roots and policy your application trusts.`,-1)])}var f=i(u,[[`render`,d]]);export{l as __pageData,f as default};