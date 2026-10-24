import{_t as e,it as t,n,rt as r}from"./chunks/framework.Dp2H9twy.js";var i=JSON.parse(`{"title":"Certificates","description":"","frontmatter":{"packageVersion":"0.1.0"},"headers":[],"relativePath":"guide/certificates.md","filePath":"site/versions/v0.1.0/guide/certificates.md","lastUpdated":0}`),a={name:`guide/certificates.md`};function o(n,i,a,o,s,c){return e(),r(`div`,null,[...i[0]||=[t(`<h1 id="certificates" tabindex="-1">Certificates <a class="header-anchor" href="#certificates" aria-label="Permalink to “Certificates”">​</a></h1><h2 id="create-a-self-signed-certificate" tabindex="-1">Create a self-signed certificate <a class="header-anchor" href="#create-a-self-signed-certificate" aria-label="Permalink to “Create a self-signed certificate”">​</a></h2><div data-js="import { createSelfSignedCertificate } from &#39;micro509&#39;;
const { certificate, keyPair } = await createSelfSignedCertificate({
    subject: {
        commonName: &#39;example.com&#39;,
        organization: &#39;Acme&#39;,
        country: &#39;US&#39;,
    },
    validity: { days: 365 },
    extensions: {
        keyUsage: [&#39;digitalSignature&#39;, &#39;keyEncipherment&#39;],
        subjectAltNames: [
            { type: &#39;dns&#39;, value: &#39;example.com&#39; },
            { type: &#39;dns&#39;, value: &#39;*.example.com&#39; },
        ],
    },
});
"><div class="language-ts"><button title="Copy code" data-copied="Copied" class="copy"></button><span class="lang">ts</span><pre class="shiki shiki-themes github-light github-dark" style="--shiki-light:#24292e;--shiki-dark:#e1e4e8;--shiki-light-bg:#fff;--shiki-dark-bg:#24292e;" tabindex="0" dir="ltr"><code><span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">import</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> { createSelfSignedCertificate } </span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">from</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> &#39;micro509&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">;</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> { </span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;">certificate</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">, </span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;">keyPair</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> } </span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">=</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">  await</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> createSelfSignedCertificate</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">({</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    subject: {</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">      commonName: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;example.com&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">      organization: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;Acme&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">      country: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;US&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    validity: { days: </span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;">365</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    extensions: {</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">      keyUsage: [</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;digitalSignature&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">, </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;keyEncipherment&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">],</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">      subjectAltNames: [</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">        { type: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;dns&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">, value: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;example.com&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">        { type: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;dns&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">, value: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;*.example.com&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">      ],</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  });</span></span></code></pre></div></div><h2 id="create-a-ca-signed-certificate" tabindex="-1">Create a CA-signed certificate <a class="header-anchor" href="#create-a-ca-signed-certificate" aria-label="Permalink to “Create a CA-signed certificate”">​</a></h2><div data-js="import { createCertificate, createSelfSignedCertificate, generateKeyPair, } from &#39;micro509&#39;;
// Create a CA
const ca = await createSelfSignedCertificate({
    subject: { commonName: &#39;My CA&#39; },
    validity: { days: 3650 },
    extensions: {
        basicConstraints: { ca: true },
        keyUsage: [&#39;keyCertSign&#39;, &#39;cRLSign&#39;],
    },
});
// Generate a key pair for the leaf certificate
const leafKeyPair = await generateKeyPair({
    kind: &#39;ecdsa&#39;,
    curve: &#39;P-256&#39;,
});
// Issue a leaf certificate
const leaf = await createCertificate({
    issuer: { commonName: &#39;My CA&#39; },
    subject: { commonName: &#39;leaf.example.com&#39; },
    validity: { days: 90 },
    publicKey: leafKeyPair.publicKey,
    signerPrivateKey: ca.keyPair.privateKey,
    issuerPublicKey: ca.keyPair.publicKey,
    extensions: {
        keyUsage: [&#39;digitalSignature&#39;],
        subjectAltNames: [
            { type: &#39;dns&#39;, value: &#39;leaf.example.com&#39; },
        ],
    },
});
"><div class="language-ts"><button title="Copy code" data-copied="Copied" class="copy"></button><span class="lang">ts</span><pre class="shiki shiki-themes github-light github-dark" style="--shiki-light:#24292e;--shiki-dark:#e1e4e8;--shiki-light-bg:#fff;--shiki-dark-bg:#24292e;" tabindex="0" dir="ltr"><code><span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">import</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> {</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  createCertificate,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  createSelfSignedCertificate,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  generateKeyPair,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">} </span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">from</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> &#39;micro509&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">;</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// Create a CA</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> ca</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> await</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> createSelfSignedCertificate</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">({</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  subject: { commonName: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;My CA&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  validity: { days: </span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;">3650</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  extensions: {</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    basicConstraints: { ca: </span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;">true</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    keyUsage: [</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;keyCertSign&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">, </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;cRLSign&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">],</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">});</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// Generate a key pair for the leaf certificate</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> leafKeyPair</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> await</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> generateKeyPair</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">({</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  kind: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;ecdsa&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  curve: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;P-256&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">});</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// Issue a leaf certificate</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> leaf</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> await</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> createCertificate</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">({</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  issuer: { commonName: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;My CA&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  subject: { commonName: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;leaf.example.com&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  validity: { days: </span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;">90</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  publicKey: leafKeyPair.publicKey,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  signerPrivateKey: ca.keyPair.privateKey,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  issuerPublicKey: ca.keyPair.publicKey,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  extensions: {</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    keyUsage: [</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;digitalSignature&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">],</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    subjectAltNames: [</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">      { type: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;dns&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">, value: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;leaf.example.com&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    ],</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">});</span></span></code></pre></div></div><h2 id="create-a-csr" tabindex="-1">Create a CSR <a class="header-anchor" href="#create-a-csr" aria-label="Permalink to “Create a CSR”">​</a></h2><div data-js="import { createCertificateSigningRequest, generateKeyPair, } from &#39;micro509&#39;;
const keyPair = await generateKeyPair({ kind: &#39;ed25519&#39; });
const csr = await createCertificateSigningRequest({
    subject: { commonName: &#39;csr.example&#39; },
    publicKey: keyPair.publicKey,
    signerPrivateKey: keyPair.privateKey,
    extensions: {
        subjectAltNames: [
            { type: &#39;dns&#39;, value: &#39;csr.example&#39; },
        ],
    },
});
"><div class="language-ts"><button title="Copy code" data-copied="Copied" class="copy"></button><span class="lang">ts</span><pre class="shiki shiki-themes github-light github-dark" style="--shiki-light:#24292e;--shiki-dark:#e1e4e8;--shiki-light-bg:#fff;--shiki-dark-bg:#24292e;" tabindex="0" dir="ltr"><code><span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">import</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> {</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  createCertificateSigningRequest,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  generateKeyPair,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">} </span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">from</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> &#39;micro509&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">;</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> keyPair</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> await</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> generateKeyPair</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">({ kind: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;ed25519&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> });</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> csr</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> await</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> createCertificateSigningRequest</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">({</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  subject: { commonName: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;csr.example&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  publicKey: keyPair.publicKey,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  signerPrivateKey: keyPair.privateKey,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  extensions: {</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    subjectAltNames: [</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">      { type: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;dns&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">, value: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;csr.example&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    ],</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">});</span></span></code></pre></div></div><h2 id="parse-a-certificate" tabindex="-1">Parse a certificate <a class="header-anchor" href="#parse-a-certificate" aria-label="Permalink to “Parse a certificate”">​</a></h2><div data-js="import { parseCertificatePem } from &#39;micro509&#39;;
const parsed = parseCertificatePem(pem);
// Typed metadata
parsed.subject.values.commonName;
parsed.issuer.values.organizationName;
parsed.validity.notBefore;
parsed.validity.notAfter;
// Typed extensions
parsed.basicConstraints; // { ca: boolean, pathLenConstraint?: number }
parsed.keyUsage; // readonly KeyUsageFlag[]
parsed.extendedKeyUsage; // readonly string[]
parsed.subjectAltNames; // readonly SubjectAltName[]
parsed.authorityInfoAccess; // readonly AuthorityInformationAccess[]
"><div class="language-ts"><button title="Copy code" data-copied="Copied" class="copy"></button><span class="lang">ts</span><pre class="shiki shiki-themes github-light github-dark" style="--shiki-light:#24292e;--shiki-dark:#e1e4e8;--shiki-light-bg:#fff;--shiki-dark-bg:#24292e;" tabindex="0" dir="ltr"><code><span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">import</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> { parseCertificatePem } </span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">from</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> &#39;micro509&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">;</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> parsed</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> parseCertificatePem</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(pem);</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// Typed metadata</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">parsed.subject.values.commonName;</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">parsed.issuer.values.organizationName;</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">parsed.validity.notBefore;</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">parsed.validity.notAfter;</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// Typed extensions</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">parsed.basicConstraints; </span><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// { ca: boolean, pathLenConstraint?: number }</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">parsed.keyUsage; </span><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// readonly KeyUsageFlag[]</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">parsed.extendedKeyUsage; </span><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// readonly string[]</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">parsed.subjectAltNames; </span><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// readonly SubjectAltName[]</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">parsed.authorityInfoAccess; </span><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// readonly AuthorityInformationAccess[]</span></span></code></pre></div></div><h2 id="parse-a-csr" tabindex="-1">Parse a CSR <a class="header-anchor" href="#parse-a-csr" aria-label="Permalink to “Parse a CSR”">​</a></h2><div data-js="import { parseCertificateSigningRequestPem } from &#39;micro509&#39;;
const parsed = parseCertificateSigningRequestPem(pem);
parsed.subject.values.commonName;
"><div class="language-ts"><button title="Copy code" data-copied="Copied" class="copy"></button><span class="lang">ts</span><pre class="shiki shiki-themes github-light github-dark" style="--shiki-light:#24292e;--shiki-dark:#e1e4e8;--shiki-light-bg:#fff;--shiki-dark-bg:#24292e;" tabindex="0" dir="ltr"><code><span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">import</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> { parseCertificateSigningRequestPem } </span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">from</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> &#39;micro509&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">;</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> parsed</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> parseCertificateSigningRequestPem</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(pem);</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">parsed.subject.values.commonName;</span></span></code></pre></div></div>`,11)]])}var s=n(a,[[`render`,o]]);export{i as __pageData,s as default};