import{_t as e,at as t,et as n,kt as r,n as i,ot as a,rt as o,xt as s}from"./chunks/framework.Ar7lzjLP.js";var c=JSON.parse(`{"title":"Certificates","description":"","frontmatter":{"packageVersion":"0.7.1"},"headers":[],"relativePath":"guide/certificates.md","filePath":"site/versions/v0.7.1/guide/certificates.md","lastUpdated":0}`),l={name:`guide/certificates.md`};function u(i,c,l,u,d,f){let p=s(`LiveCode`);return e(),o(`div`,null,[c[5]||=n(`h1`,{id:`certificates`,tabindex:`-1`},[t(`Certificates `),n(`a`,{class:`header-anchor`,href:`#certificates`,"aria-label":`Permalink to “Certificates”`},`​`)],-1),c[6]||=n(`h2`,{id:`create-a-self-signed-certificate`,tabindex:`-1`},[t(`Create a self-signed certificate `),n(`a`,{class:`header-anchor`,href:`#create-a-self-signed-certificate`,"aria-label":`Permalink to “Create a self-signed certificate”`},`​`)],-1),a(p,null,{default:r(()=>[...c[0]||=[n(`div`,{"data-js":`import { createSelfSignedCertificate } from 'micro509';
const { certificate, keyPair } = await createSelfSignedCertificate({
    subject: {
        commonName: 'example.com',
        organization: 'Acme',
        country: 'US',
    },
    validity: { days: 365 },
    extensions: {
        keyUsage: ['digitalSignature', 'keyEncipherment'],
        subjectAltNames: [
            { type: 'dns', value: 'example.com' },
            { type: 'dns', value: '*.example.com' },
        ],
    },
});
console.log(certificate.pem);
console.log(await keyPair.exportPkcs8Pem());
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { createSelfSignedCertificate } `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`certificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`keyPair`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` } `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`=`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`  await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    subject: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'example.com'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      organization: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Acme'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      country: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'US'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    validity: { days: `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`365`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    extensions: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      keyUsage: [`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'digitalSignature'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyEncipherment'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      subjectAltNames: [`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`        { type: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'dns'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, value: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'example.com'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`        { type: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'dns'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, value: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'*.example.com'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      ],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  });`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(certificate.pem);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`await`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` keyPair.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`exportPkcs8Pem`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`());`)])])])])],-1)]]),_:1}),c[7]||=n(`h2`,{id:`create-a-ca-signed-certificate`,tabindex:`-1`},[t(`Create a CA-signed certificate `),n(`a`,{class:`header-anchor`,href:`#create-a-ca-signed-certificate`,"aria-label":`Permalink to “Create a CA-signed certificate”`},`​`)],-1),a(p,null,{default:r(()=>[...c[1]||=[n(`div`,{"data-js":`import { createCertificate, createSelfSignedCertificate, generateKeyPair, parseCertificatePem, unwrap, } from 'micro509';
// Create a CA
const ca = await createSelfSignedCertificate({
    subject: { commonName: 'My CA' },
    validity: { days: 3650 },
    extensions: {
        basicConstraints: { ca: true },
        keyUsage: ['keyCertSign', 'cRLSign'],
    },
});
// Generate a key pair for the leaf certificate
const leafKeyPair = await generateKeyPair({
    kind: 'ecdsa',
    curve: 'P-256',
});
// Issue a leaf certificate
const leaf = await createCertificate({
    issuer: { commonName: 'My CA' },
    subject: { commonName: 'leaf.example.com' },
    validity: { days: 90 },
    publicKey: leafKeyPair.publicKey,
    signerPrivateKey: ca.keyPair.privateKey,
    issuerPublicKey: ca.keyPair.publicKey,
    extensions: {
        keyUsage: ['digitalSignature'],
        subjectAltNames: [
            { type: 'dns', value: 'leaf.example.com' },
        ],
    },
});
const parsed = unwrap(parseCertificatePem(leaf.pem));
console.log(\`\\
leaf:   \${parsed.subject.values.commonName}
issuer: \${parsed.issuer.values.commonName}\`);
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  generateKeyPair,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  parseCertificatePem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  unwrap,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Create a CA`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` ca`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'My CA'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  validity: { days: `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`3650`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    basicConstraints: { ca: `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`true`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    keyUsage: [`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyCertSign'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'cRLSign'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Generate a key pair for the leaf certificate`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leafKeyPair`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` generateKeyPair`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  kind: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'ecdsa'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  curve: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'P-256'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Issue a leaf certificate`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` leaf`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuer: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'My CA'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'leaf.example.com'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  validity: { days: `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`90`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  publicKey: leafKeyPair.publicKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: ca.keyPair.privateKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  issuerPublicKey: ca.keyPair.publicKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    keyUsage: [`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'digitalSignature'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    subjectAltNames: [`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      { type: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'dns'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, value: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'leaf.example.com'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    ],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` parsed`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` unwrap`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`parseCertificatePem`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(leaf.pem));`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"leaf:   ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`subject`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`values`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`commonName`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"issuer: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`issuer`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`values`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`commonName`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)])])])])],-1)]]),_:1}),c[8]||=n(`h2`,{id:`create-a-csr`,tabindex:`-1`},[t(`Create a CSR `),n(`a`,{class:`header-anchor`,href:`#create-a-csr`,"aria-label":`Permalink to “Create a CSR”`},`​`)],-1),a(p,null,{default:r(()=>[...c[2]||=[n(`div`,{"data-js":`import { createCertificateSigningRequest, generateKeyPair, } from 'micro509';
const keyPair = await generateKeyPair({ kind: 'ed25519' });
const csr = await createCertificateSigningRequest({
    subject: { commonName: 'csr.example' },
    publicKey: keyPair.publicKey,
    signerPrivateKey: keyPair.privateKey,
    extensions: {
        subjectAltNames: [
            { type: 'dns', value: 'csr.example' },
        ],
    },
});
console.log(csr.pem);
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificateSigningRequest,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  generateKeyPair,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` keyPair`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` generateKeyPair`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({ kind: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'ed25519'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` });`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` csr`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificateSigningRequest`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'csr.example'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  publicKey: keyPair.publicKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: keyPair.privateKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    subjectAltNames: [`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      { type: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'dns'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, value: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'csr.example'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    ],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(csr.pem);`)])])])])],-1)]]),_:1}),c[9]||=n(`h2`,{id:`parse-a-certificate`,tabindex:`-1`},[t(`Parse a certificate `),n(`a`,{class:`header-anchor`,href:`#parse-a-certificate`,"aria-label":`Permalink to “Parse a certificate”`},`​`)],-1),a(p,null,{default:r(()=>[...c[3]||=[n(`div`,{"data-js":`import { createSelfSignedCertificate, parseCertificatePem, unwrap, } from 'micro509';
// Build a certificate inline, then parse it back
const { certificate } = await createSelfSignedCertificate({
    subject: {
        commonName: 'example.com',
        organization: 'Acme',
        country: 'US',
    },
    validity: { days: 365 },
    extensions: {
        keyUsage: ['digitalSignature', 'keyEncipherment'],
        subjectAltNames: [
            { type: 'dns', value: 'example.com' },
            { type: 'dns', value: '*.example.com' },
        ],
    },
});
const parsed = unwrap(parseCertificatePem(certificate.pem));
// Typed metadata
const sans = parsed.subjectAltNames ?? [];
console.log(\`\\
subject:   \${parsed.subject.values.commonName}
org:       \${parsed.subject.values.organization}
issuer:    \${parsed.issuer.values.commonName}
notBefore: \${parsed.notBefore.toISOString()}
notAfter:  \${parsed.notAfter.toISOString()}
sig algo:  \${parsed.signatureAlgorithmName}
ca:        \${parsed.basicConstraints?.ca ?? false}
key usage: \${parsed.keyUsage?.flags.join(', ')}
SANs:      \${sans.map((n) => n.value).join(', ')}\`);
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createSelfSignedCertificate,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  parseCertificatePem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  unwrap,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Build a certificate inline, then parse it back`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` { `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`certificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` } `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`=`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createSelfSignedCertificate`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'example.com'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    organization: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'Acme'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    country: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'US'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  validity: { days: `),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`365`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    keyUsage: [`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'digitalSignature'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'keyEncipherment'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    subjectAltNames: [`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      { type: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'dns'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, value: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'example.com'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      { type: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'dns'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, value: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'*.example.com'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    ],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` parsed`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` unwrap`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`parseCertificatePem`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(certificate.pem));`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Typed metadata`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` sans`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` parsed.subjectAltNames `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`??`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` [];`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"subject:   ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`subject`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`values`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`commonName`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"org:       ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`subject`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`values`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`organization`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"issuer:    ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`issuer`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`values`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`commonName`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"notBefore: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`notBefore`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`toISOString`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`()`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"notAfter:  ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`notAfter`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`toISOString`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`()`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"sig algo:  ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`signatureAlgorithmName`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"ca:        ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`basicConstraints`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`ca`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` ??`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` false`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"key usage: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`keyUsage`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`?.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`flags`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`join`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`', '`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`)`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"SANs:      ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`sans`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`map`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`((`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`n`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`) `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`=>`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` n`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`value`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`).`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`join`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`', '`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`)`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)])])])])],-1)]]),_:1}),c[10]||=n(`h2`,{id:`parse-a-csr`,tabindex:`-1`},[t(`Parse a CSR `),n(`a`,{class:`header-anchor`,href:`#parse-a-csr`,"aria-label":`Permalink to “Parse a CSR”`},`​`)],-1),a(p,null,{default:r(()=>[...c[4]||=[n(`div`,{"data-js":`import { createCertificateSigningRequest, generateKeyPair, parseCertificateSigningRequestPem, unwrap, } from 'micro509';
// Build a CSR inline, then parse it back
const keyPair = await generateKeyPair({ kind: 'ed25519' });
const csr = await createCertificateSigningRequest({
    subject: { commonName: 'csr.example' },
    publicKey: keyPair.publicKey,
    signerPrivateKey: keyPair.privateKey,
    extensions: {
        subjectAltNames: [
            { type: 'dns', value: 'csr.example' },
        ],
    },
});
const parsed = unwrap(parseCertificateSigningRequestPem(csr.pem));
const sans = parsed.subjectAltNames ?? [];
console.log(\`\\
subject:  \${parsed.subject.values.commonName}
sig algo: \${parsed.signatureAlgorithmName}
SANs:     \${sans.map((n) => n.value).join(', ')}\`);
`},[n(`div`,{class:`language-ts`},[n(`button`,{title:`Copy code`,"data-copied":`Copied`,class:`copy`}),n(`span`,{class:`lang`},`ts`),n(`pre`,{class:`shiki shiki-themes github-light github-dark`,style:{"--shiki-light":`#24292e`,"--shiki-dark":`#e1e4e8`,"--shiki-light-bg":`#fff`,"--shiki-dark-bg":`#24292e`},tabindex:`0`,dir:`ltr`},[n(`code`,null,[n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`import`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  createCertificateSigningRequest,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  generateKeyPair,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  parseCertificateSigningRequestPem,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  unwrap,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`} `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`from`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},` 'micro509'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`;`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#62687b`,"--shiki-dark":`#818e99`}},`// Build a CSR inline, then parse it back`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` keyPair`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` generateKeyPair`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({ kind: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'ed25519'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` });`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` csr`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` await`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` createCertificateSigningRequest`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`({`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  subject: { commonName: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'csr.example'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  publicKey: keyPair.publicKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  signerPrivateKey: keyPair.privateKey,`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  extensions: {`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    subjectAltNames: [`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`      { type: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'dns'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`, value: `),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`'csr.example'`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`    ],`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`  },`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`});`)]),t(`
`),n(`span`,{class:`line`}),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` parsed`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},` unwrap`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`  parseCertificateSigningRequestPem`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(csr.pem),`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`const`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},` sans`),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},` =`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` parsed.subjectAltNames `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`??`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` [];`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`console.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`log`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"`"),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`\\`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"subject:  ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`subject`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`values`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`commonName`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"sig algo: ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`parsed`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`signatureAlgorithmName`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`}`)]),t(`
`),n(`span`,{class:`line`},[n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"SANs:     ${"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`sans`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`map`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`((`),n(`span`,{style:{"--shiki-light":`#005CC5`,"--shiki-dark":`#79B8FF`}},`n`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`) `),n(`span`,{style:{"--shiki-light":`#c62739`,"--shiki-dark":`#F97583`}},`=>`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},` n`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`.`),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`value`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`).`),n(`span`,{style:{"--shiki-light":`#6F42C1`,"--shiki-dark":`#B392F0`}},`join`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`(`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`', '`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},`)`),n(`span`,{style:{"--shiki-light":`#032F62`,"--shiki-dark":`#9ECBFF`}},"}`"),n(`span`,{style:{"--shiki-light":`#24292E`,"--shiki-dark":`#E1E4E8`}},`);`)])])])])],-1)]]),_:1})])}var d=i(l,[[`render`,u]]);export{c as __pageData,d as default};