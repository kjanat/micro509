# Web IDL snapshot

`webidl.txt` is a plain-text rendering of the WHATWG Web IDL Living Standard
for offline standards research.

## Source

| File         | Source                            | Snapshot                                                                    |
| ------------ | --------------------------------- | --------------------------------------------------------------------------- |
| `webidl.txt` | <https://webidl.spec.whatwg.org/> | Living Standard last updated 23 September 2026, retrieved 24 September 2026 |

## License

Copyright © WHATWG (Apple, Google, Mozilla, Microsoft). The standard is
licensed under the
[Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/);
portions incorporated into source code are licensed under the
[BSD 3-Clause License](https://opensource.org/licenses/BSD-3-Clause). It
includes material copied from W3C's WebIDL Level 1, available under the
[W3C Software and Document License](https://www.w3.org/Consortium/Legal/2015/copyright-software-and-document).

The rendering converts the HTML to text and makes no other change.

## Regenerate

```sh
bun w3c webidl
```

The fetcher appends the source URL, the retrieval date and each license URI
the page links to the end of the rendered text.
