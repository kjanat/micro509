import{_t as e,it as t,n,rt as r}from"./chunks/framework.1B5JQyNh.js";var i=JSON.parse(`{"title":"Verification","description":"","frontmatter":{"packageVersion":"0.1.1"},"headers":[],"relativePath":"guide/verification.md","filePath":"site/versions/v0.1.1/guide/verification.md","lastUpdated":0}`),a={name:`guide/verification.md`};function o(n,i,a,o,s,c){return e(),r(`div`,null,[...i[0]||=[t(`<h1 id="verification" tabindex="-1">Verification <a class="header-anchor" href="#verification" aria-label="Permalink to “Verification”">​</a></h1><h2 id="chain-verification" tabindex="-1">Chain verification <a class="header-anchor" href="#chain-verification" aria-label="Permalink to “Chain verification”">​</a></h2><div data-js="import { verifyCertificateChain } from &#39;micro509&#39;;
const result = await verifyCertificateChain({
    leaf: leaf.pem,
    intermediates: [intermediate.pem],
    roots: [root.pem],
    purpose: &#39;serverAuth&#39;,
    serviceIdentity: {
        type: &#39;dns&#39;,
        value: &#39;api.example.com&#39;,
    },
});
if (result.ok) {
    console.log(&#39;Valid chain:&#39;, result.value.chain.length, &#39;certificates&#39;);
}
else {
    console.log(&#39;Failed:&#39;, result.error.code);
    console.log(&#39;At index:&#39;, result.error.index);
}
"><div class="language-ts"><button title="Copy code" data-copied="Copied" class="copy"></button><span class="lang">ts</span><pre class="shiki shiki-themes github-light github-dark" style="--shiki-light:#24292e;--shiki-dark:#e1e4e8;--shiki-light-bg:#fff;--shiki-dark-bg:#24292e;" tabindex="0" dir="ltr"><code><span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">import</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> { verifyCertificateChain } </span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">from</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> &#39;micro509&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">;</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> result</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> await</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> verifyCertificateChain</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">({</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  leaf: leaf.pem,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  intermediates: [intermediate.pem],</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  roots: [root.pem],</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  purpose: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;serverAuth&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  serviceIdentity: {</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    type: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;dns&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    value: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;api.example.com&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">});</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">if</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> (result.ok) {</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  console.</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">log</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(</span></span>
<span class="line"><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">    &#39;Valid chain:&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    result.value.chain.</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;">length</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">,</span></span>
<span class="line"><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">    &#39;certificates&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  );</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">} </span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">else</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> {</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  console.</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">log</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;Failed:&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">, result.error.code);</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  console.</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">log</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;At index:&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">, result.error.index);</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">}</span></span></code></pre></div></div><h2 id="verification-purposes" tabindex="-1">Verification purposes <a class="header-anchor" href="#verification-purposes" aria-label="Permalink to “Verification purposes”">​</a></h2><p>Four built-in validation profiles:</p><div data-js="&quot;use strict&quot;;
// TLS server (default)
await verifyCertificateChain({
    leaf: leaf.pem,
    intermediates: [intermediate.pem],
    roots: [root.pem],
    purpose: &#39;serverAuth&#39;,
});
// TLS client
await verifyCertificateChain({
    leaf: leaf.pem,
    intermediates: [intermediate.pem],
    roots: [root.pem],
    purpose: &#39;clientAuth&#39;,
});
// Code signing
await verifyCertificateChain({
    leaf: leaf.pem,
    intermediates: [intermediate.pem],
    roots: [root.pem],
    purpose: &#39;codeSigning&#39;,
});
// CA certificate
await verifyCertificateChain({
    leaf: intermediate.pem,
    roots: [root.pem],
    purpose: &#39;ca&#39;,
});
"><div class="language-ts"><button title="Copy code" data-copied="Copied" class="copy"></button><span class="lang">ts</span><pre class="shiki shiki-themes github-light github-dark" style="--shiki-light:#24292e;--shiki-dark:#e1e4e8;--shiki-light-bg:#fff;--shiki-dark-bg:#24292e;" tabindex="0" dir="ltr"><code><span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// TLS server (default)</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">await</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> verifyCertificateChain</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">({</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  leaf: leaf.pem,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  intermediates: [intermediate.pem],</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  roots: [root.pem],</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  purpose: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;serverAuth&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">});</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// TLS client</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">await</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> verifyCertificateChain</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">({</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  leaf: leaf.pem,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  intermediates: [intermediate.pem],</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  roots: [root.pem],</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  purpose: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;clientAuth&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">});</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// Code signing</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">await</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> verifyCertificateChain</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">({</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  leaf: leaf.pem,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  intermediates: [intermediate.pem],</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  roots: [root.pem],</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  purpose: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;codeSigning&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">});</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">// CA certificate</span></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">await</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> verifyCertificateChain</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">({</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  leaf: intermediate.pem,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  roots: [root.pem],</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  purpose: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;ca&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">});</span></span></code></pre></div></div><h2 id="service-identity-matching" tabindex="-1">Service identity matching <a class="header-anchor" href="#service-identity-matching" aria-label="Permalink to “Service identity matching”">​</a></h2><div data-js="import { matchServiceIdentity } from &#39;micro509/verify&#39;;
const result = matchServiceIdentity({
    certificate: parsed,
    identity: { type: &#39;dns&#39;, value: &#39;example.com&#39; },
});
if (!result.ok) {
    console.log(result.error.code);
    // &#39;san_mismatch&#39; | &#39;no_san_extension&#39; | ...
}
"><div class="language-ts"><button title="Copy code" data-copied="Copied" class="copy"></button><span class="lang">ts</span><pre class="shiki shiki-themes github-light github-dark" style="--shiki-light:#24292e;--shiki-dark:#e1e4e8;--shiki-light-bg:#fff;--shiki-dark-bg:#24292e;" tabindex="0" dir="ltr"><code><span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">import</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> { matchServiceIdentity } </span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">from</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> &#39;micro509/verify&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">;</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> result</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> matchServiceIdentity</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">({</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  certificate: parsed,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  identity: { type: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;dns&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">, value: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;example.com&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> },</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">});</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">if</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> (</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">!</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">result.ok) {</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  console.</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">log</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(result.error.code);</span></span>
<span class="line"><span style="--shiki-light:#62687b;--shiki-dark:#818e99;">  // &#39;san_mismatch&#39; | &#39;no_san_extension&#39; | ...</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">}</span></span></code></pre></div></div><p>Supported identity types:</p><ul><li><strong>DNS-ID</strong> — with wildcard matching and case-insensitive comparison</li><li><strong>IP-ID</strong> — with IPv6 normalization</li><li><strong>URI-ID</strong> — scheme + host matching</li><li><strong>SRV-ID</strong> — service name matching via otherName SAN</li></ul><h2 id="error-codes" tabindex="-1">Error codes <a class="header-anchor" href="#error-codes" aria-label="Permalink to “Error codes”">​</a></h2><p>The <code>VerifyErrorCode</code> type covers 21 failure modes:</p><table tabindex="0"><thead><tr><th>Code</th><th>Meaning</th></tr></thead><tbody><tr><td><code>no_trusted_root</code></td><td>No trust anchor matched the chain</td></tr><tr><td><code>issuer_not_found</code></td><td>Could not find issuer for a certificate</td></tr><tr><td><code>signature_invalid</code></td><td>Cryptographic signature check failed</td></tr><tr><td><code>certificate_expired</code></td><td>Certificate outside validity window</td></tr><tr><td><code>ca_required</code></td><td>Non-CA certificate used as issuer</td></tr><tr><td><code>key_cert_sign_required</code></td><td>Issuer missing <code>keyCertSign</code> key usage</td></tr><tr><td><code>path_length_exceeded</code></td><td>Chain exceeds <code>pathLenConstraint</code></td></tr><tr><td><code>authority_key_identifier_mismatch</code></td><td>AKI/SKI cross-check failed</td></tr><tr><td><code>extended_key_usage_invalid</code></td><td>EKU doesn&#39;t match requested purpose</td></tr><tr><td><code>subject_alt_name_mismatch</code></td><td>SAN doesn&#39;t match service identity</td></tr><tr><td><code>common_name_fallback_suppressed</code></td><td>CN match suppressed by presented identifiers</td></tr><tr><td><code>self_signed_leaf_not_allowed</code></td><td>Self-signed leaf without explicit opt-in</td></tr><tr><td><code>unrecognized_critical_extension</code></td><td>Unknown critical extension</td></tr><tr><td><code>intermediate_eku_constraint</code></td><td>Intermediate has restrictive EKU</td></tr><tr><td><code>policy_processing_not_implemented</code></td><td>Policy processing not implemented</td></tr><tr><td><code>name_constraints_violated</code></td><td>Name constraints check failed</td></tr><tr><td><code>initial_name_constraints_not_implemented</code></td><td>Initial name constraints not implemented</td></tr><tr><td><code>unsupported_name_constraints</code></td><td>Unsupported name constraint form</td></tr><tr><td><code>explicit_policy_required</code></td><td>Policy required but not satisfied</td></tr><tr><td><code>initial_policy_set_not_satisfied</code></td><td>Initial policy set not met</td></tr><tr><td><code>unsupported_signature_algorithm_parameters</code></td><td>Unknown signature algorithm</td></tr></tbody></table><h2 id="csr-verification" tabindex="-1">CSR verification <a class="header-anchor" href="#csr-verification" aria-label="Permalink to “CSR verification”">​</a></h2><div data-js="import { verifyCertificateSigningRequest } from &#39;micro509&#39;;
const result = await verifyCertificateSigningRequest(csr.pem);
if (result.ok) {
    console.log(&#39;CSR signature valid&#39;);
}
"><div class="language-ts"><button title="Copy code" data-copied="Copied" class="copy"></button><span class="lang">ts</span><pre class="shiki shiki-themes github-light github-dark" style="--shiki-light:#24292e;--shiki-dark:#e1e4e8;--shiki-light-bg:#fff;--shiki-dark-bg:#24292e;" tabindex="0" dir="ltr"><code><span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">import</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> { verifyCertificateSigningRequest } </span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">from</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> &#39;micro509&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">;</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">const</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> result</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#c62739;--shiki-dark:#F97583;"> await</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> verifyCertificateSigningRequest</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  csr.pem,</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">);</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#c62739;--shiki-dark:#F97583;">if</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> (result.ok) {</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">  console.</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">log</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&#39;CSR signature valid&#39;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">);</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">}</span></span></code></pre></div></div>`,15)]])}var s=n(a,[[`render`,o]]);export{i as __pageData,s as default};