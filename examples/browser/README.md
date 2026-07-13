# micro509 in the browser

One HTML file. Open it.

[![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/kjanat/micro509/tree/master/examples/browser)

No `package.json`, no npm, no bundler. [`index.html`] imports micro509 from a CDN and issues
a self-signed certificate, then parses it back out of its own PEM:

```html
<script type="module">
  import { createSelfSignedCertificate } from 'https://esm.run/micro509@0.11.0';
</script>
```

That works because the library is ESM and WebCrypto, and nothing else.

For the same demo with types, hot reload and micro509 as an npm dependency, see [`../vite`].

[`index.html`]: ./index.html
[`../vite`]: ../vite/README.md
