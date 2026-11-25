import{_t as e,it as t,n,rt as r}from"./chunks/framework.1B5JQyNh.js";var i=JSON.parse(`{"title":"PKCS","description":"","frontmatter":{"packageVersion":"0.1.1"},"headers":[],"relativePath":"guide/pkcs.md","filePath":"site/versions/v0.1.1/guide/pkcs.md","lastUpdated":0}`),a={name:`guide/pkcs.md`};function o(n,i,a,o,s,c){return e(),r(`div`,null,[...i[0]||=[t(`<h1 id="pkcs" tabindex="-1">PKCS <a class="header-anchor" href="#pkcs" aria-label="Permalink to “PKCS”">​</a></h1><h2 id="pfx-pkcs-12" tabindex="-1">PFX / PKCS#12 <a class="header-anchor" href="#pfx-pkcs-12" aria-label="Permalink to “PFX / PKCS#12”">​</a></h2><h3 id="create-a-pfx-bundle" tabindex="-1">Create a PFX bundle <a class="header-anchor" href="#create-a-pfx-bundle" aria-label="Permalink to “Create a PFX bundle”">​</a></h3><div data-js="import { createPfx } from &#39;micro509/pkcs&#39;;
const pfx = await createPfx({
    certificates: [
        { certificate: cert.pem },
        { certificate: ca.certificate.pem },
    ],
    privateKeys: [{ privateKey: keyPair.privateKey }],
    encryption: { password: &#39;secret&#39; },
    mac: { password: &#39;secret&#39; },
});
// pfx.der — Uint8Array
// pfx.pem — PKCS12 PEM string
// pfx.base64 — base64-encoded string
"><div class="language-ts"><button title="Copy code" data-copied="Copied" class="copy"></button><span class="lang">ts</span><pre class="shiki shiki-themes github-light github-dark" style="--shiki-light:#24292e;--shiki-dark:#e1e4e8;--shiki-light-bg:#fff;--shiki-dark-bg:#24292e;" tabindex="0" dir="ltr"><code><span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">import</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> { createPfx } </span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">from</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> &#39;micro509/pkcs&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">;</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> pfx</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> await</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> createPfx</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">({</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  certificates: [</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    { certificate: cert.pem },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    { certificate: ca.certificate.pem },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  ],</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  privateKeys: [{ privateKey: keyPair.privateKey }],</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  encryption: { password: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;secret&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  mac: { password: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;secret&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">});</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// pfx.der — Uint8Array</span></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// pfx.pem — PKCS12 PEM string</span></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// pfx.base64 — base64-encoded string</span></span></code></pre></div></div><h3 id="parse-a-pfx-bundle" tabindex="-1">Parse a PFX bundle <a class="header-anchor" href="#parse-a-pfx-bundle" aria-label="Permalink to “Parse a PFX bundle”">​</a></h3><div data-js="import { parsePfxDer } from &#39;micro509/pkcs&#39;;
const result = await parsePfxDer(pfx.der, {
    password: &#39;secret&#39;,
});
if (result.ok) {
    const certificates = result.value.certificates;
    const privateKeys = result.value.privateKeys;
    const bags = result.value.bags;
}
"><div class="language-ts"><button title="Copy code" data-copied="Copied" class="copy"></button><span class="lang">ts</span><pre class="shiki shiki-themes github-light github-dark" style="--shiki-light:#24292e;--shiki-dark:#e1e4e8;--shiki-light-bg:#fff;--shiki-dark-bg:#24292e;" tabindex="0" dir="ltr"><code><span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">import</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> { parsePfxDer } </span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">from</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> &#39;micro509/pkcs&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">;</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> result</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> await</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> parsePfxDer</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(pfx.der, {</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  password: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;secret&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">});</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">if</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> (result.ok) {</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">  const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> certificates</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> result.value.certificates;</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">  const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> privateKeys</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> result.value.privateKeys;</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">  const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> bags</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> result.value.bags;</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">}</span></span></code></pre></div></div><h2 id="pkcs-7-cms" tabindex="-1">PKCS#7 / CMS <a class="header-anchor" href="#pkcs-7-cms" aria-label="Permalink to “PKCS#7 / CMS”">​</a></h2><h3 id="create-a-certificate-bag" tabindex="-1">Create a certificate bag <a class="header-anchor" href="#create-a-certificate-bag" aria-label="Permalink to “Create a certificate bag”">​</a></h3><div data-js="import { createPkcs7CertBagPem } from &#39;micro509/pkcs&#39;;
const bag = createPkcs7CertBagPem([cert1.pem, cert2.pem]);
// bag.der — Uint8Array
// bag.pem — PKCS7 PEM string
"><div class="language-ts"><button title="Copy code" data-copied="Copied" class="copy"></button><span class="lang">ts</span><pre class="shiki shiki-themes github-light github-dark" style="--shiki-light:#24292e;--shiki-dark:#e1e4e8;--shiki-light-bg:#fff;--shiki-dark-bg:#24292e;" tabindex="0" dir="ltr"><code><span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">import</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> { createPkcs7CertBagPem } </span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">from</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> &#39;micro509/pkcs&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">;</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> bag</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> createPkcs7CertBagPem</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">([cert1.pem, cert2.pem]);</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// bag.der — Uint8Array</span></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// bag.pem — PKCS7 PEM string</span></span></code></pre></div></div><h3 id="parse-a-certificate-bag" tabindex="-1">Parse a certificate bag <a class="header-anchor" href="#parse-a-certificate-bag" aria-label="Permalink to “Parse a certificate bag”">​</a></h3><div data-js="import { parsePkcs7CertBagPem } from &#39;micro509/pkcs&#39;;
const result = parsePkcs7CertBagPem(bag.pem);
if (result.ok) {
    const certificates = result.value;
}
"><div class="language-ts"><button title="Copy code" data-copied="Copied" class="copy"></button><span class="lang">ts</span><pre class="shiki shiki-themes github-light github-dark" style="--shiki-light:#24292e;--shiki-dark:#e1e4e8;--shiki-light-bg:#fff;--shiki-dark-bg:#24292e;" tabindex="0" dir="ltr"><code><span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">import</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> { parsePkcs7CertBagPem } </span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">from</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> &#39;micro509/pkcs&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">;</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> result</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> parsePkcs7CertBagPem</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(bag.pem);</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">if</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> (result.ok) {</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">  const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> certificates</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> result.value;</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">}</span></span></code></pre></div></div><h3 id="verify-signeddata" tabindex="-1">Verify SignedData <a class="header-anchor" href="#verify-signeddata" aria-label="Permalink to “Verify SignedData”">​</a></h3><div data-js="import { parsePkcs7SignedDataDer, verifyPkcs7SignedData, } from &#39;micro509/pkcs&#39;;
const result = parsePkcs7SignedDataDer(der);
if (result.ok) {
    const verifyResult = await verifyPkcs7SignedData(result.value);
    if (verifyResult.ok) {
        console.log(&#39;All signers verified&#39;);
    }
}
"><div class="language-ts"><button title="Copy code" data-copied="Copied" class="copy"></button><span class="lang">ts</span><pre class="shiki shiki-themes github-light github-dark" style="--shiki-light:#24292e;--shiki-dark:#e1e4e8;--shiki-light-bg:#fff;--shiki-dark-bg:#24292e;" tabindex="0" dir="ltr"><code><span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">import</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> {</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  parsePkcs7SignedDataDer,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  verifyPkcs7SignedData,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">} </span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">from</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> &#39;micro509/pkcs&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">;</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> result</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> parsePkcs7SignedDataDer</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(der);</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">if</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> (result.ok) {</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">  const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> verifyResult</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> await</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> verifyPkcs7SignedData</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    result.value,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  );</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">  if</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> (verifyResult.ok) {</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    console.</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">log</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;All signers verified&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">);</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  }</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">}</span></span></code></pre></div></div><h2 id="pem-utilities" tabindex="-1">PEM utilities <a class="header-anchor" href="#pem-utilities" aria-label="Permalink to “PEM utilities”">​</a></h2><div data-js="import { pemDecode, pemEncode, splitPemBlocks, categorizePemBlocks, } from &#39;micro509/pem&#39;;
// Decode a single PEM block
const pem = \`-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----\`;
const der = pemDecode(&#39;CERTIFICATE&#39;, pem);
// Encode DER as PEM
const pemEncoded = pemEncode(&#39;CERTIFICATE&#39;, der);
// Split a multi-block PEM file
const blocks = splitPemBlocks(multiPem);
// Categorize blocks by type
const { certificates, privateKeys, csrs } = categorizePemBlocks(multiPem);
"><div class="language-ts"><button title="Copy code" data-copied="Copied" class="copy"></button><span class="lang">ts</span><pre class="shiki shiki-themes github-light github-dark" style="--shiki-light:#24292e;--shiki-dark:#e1e4e8;--shiki-light-bg:#fff;--shiki-dark-bg:#24292e;" tabindex="0" dir="ltr"><code><span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">import</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> {</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  pemDecode,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  pemEncode,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  splitPemBlocks,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  categorizePemBlocks,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">} </span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">from</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> &#39;micro509/pem&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">;</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// Decode a single PEM block</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> pem</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> \`-----BEGIN CERTIFICATE-----</span></span>
<span class="line"><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">...</span></span>
<span class="line"><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">-----END CERTIFICATE-----\`</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">;</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> der</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> pemDecode</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;CERTIFICATE&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">, pem);</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// Encode DER as PEM</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> pemEncoded</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> pemEncode</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;CERTIFICATE&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">, der);</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// Split a multi-block PEM file</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> blocks</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> splitPemBlocks</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(multiPem);</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// Categorize blocks by type</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> { </span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;">certificates</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">, </span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;">privateKeys</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">, </span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;">csrs</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> } </span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">=</span></span>
<span class="line"><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">  categorizePemBlocks</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(multiPem);</span></span></code></pre></div></div>`,15)]])}var s=n(a,[[`render`,o]]);export{i as __pageData,s as default};