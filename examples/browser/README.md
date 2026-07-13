# micro509 in the browser

One HTML file. Open it.

[![Open in StackBlitz]][stackblitz] or view the HTML as it's intended: [https://esm.sh/gh/kjanat/micro509/examples/browser/index.html]

No `package.json`, no npm, no bundler.\
[`index.html`] imports micro509 from a CDN and issues a self-signed certificate, then parses it back out of its own PEM:

```html
<script type="module">
  import { createSelfSignedCertificate } from 'https://esm.run/micro509@0.11.0';
</script>
```

That works because the library is ESM and WebCrypto, and nothing else.

For the same demo with types, hot reload and micro509 as an npm dependency, see [`examples/vite`].

[`index.html`]: ./index.html
[`examples/vite`]: https://github.com/kjanat/micro509/tree/HEAD/examples/vite
[https://esm.sh/gh/kjanat/micro509/examples/browser/index.html]: https://esm.sh/gh/kjanat/micro509@c84b7197fd94746e324fe27d119a035fae67666d/examples/browser/index.html
[Open in StackBlitz]: https://developer.stackblitz.com/img/open_in_stackblitz_small.svg
[stackblitz]: https://stackblitz.com/github/kjanat/micro509/tree/master/examples/browser?title=micro509%20in%20the%20browser
