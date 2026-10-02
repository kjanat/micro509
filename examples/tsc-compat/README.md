# tsc-compat AST explorer

A small web page for exploring the syntax tree that [`@kjanat/tsc-compat`](../../tsc/compat/README.md) builds. The package runs the parser of the pinned TypeScript Go compiler as WebAssembly behind the TypeScript 6 API.

Type TypeScript or TSX on the left, and the tree and the parse diagnostics update on the right. Clicking a node or a diagnostic selects its source range.

```sh
npm install
npm start
```

`server.js` parses on the Node side and serves `index.html` on port 3000, or on `PORT` when it is set.
