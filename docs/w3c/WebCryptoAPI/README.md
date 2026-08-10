# Web Crypto specification snapshots

This directory vendors plain-text renderings for offline standards research.
The downloaded or generated HTML is temporary input and is not committed.

## Sources

| File                                | Source                                                                                                                                       | Snapshot                                           |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `W3C-REC-WebCryptoAPI-20170126.txt` | <https://www.w3.org/TR/2017/REC-WebCryptoAPI-20170126/>                                                                                      | Immutable Recommendation dated 26 January 2017     |
| `W3C-TR-webcrypto-current.txt`      | <https://www.w3.org/TR/webcrypto-2/>                                                                                                         | Latest published version retrieved 10 August 2026  |
| `w3c-webcrypto-editors-draft.txt`   | [`w3c/webcrypto@27b3faad99dac4f9bf036f038ef1f0cd04e748a1`](https://github.com/w3c/webcrypto/commit/27b3faad99dac4f9bf036f038ef1f0cd04e748a1) | Editor's draft built from source on 10 August 2026 |

The deployed editor's draft still represented the 29 April 2026 build when
these files were refreshed. The vendored snapshot was therefore built from the
newer pinned source commit instead of copied from GitHub Pages.

## Regenerate

The text rendering uses `w3m 0.5.6` with a fixed 110-column width. The editor's
draft additionally uses ReSpec 37.2.0.

```sh
snapshot_dir=$(mktemp -d)
render_text() {
  w3m -dump -cols 110 "$1" |
    perl -0pe 's/[ \t]+(?=\n)//g; s/\n+\z/\n/' > "$2"
}

curl --fail --location --silent --show-error \
  https://www.w3.org/TR/2017/REC-WebCryptoAPI-20170126/ \
  --output "$snapshot_dir/recommendation.html"
render_text "$snapshot_dir/recommendation.html" \
  docs/w3c/WebCryptoAPI/W3C-REC-WebCryptoAPI-20170126.txt

curl --fail --location --silent --show-error \
  https://www.w3.org/TR/webcrypto-2/ \
  --output "$snapshot_dir/published.html"
render_text "$snapshot_dir/published.html" \
  docs/w3c/WebCryptoAPI/W3C-TR-webcrypto-current.txt

gh repo clone w3c/webcrypto "$snapshot_dir/webcrypto"
git -C "$snapshot_dir/webcrypto" checkout --detach \
  27b3faad99dac4f9bf036f038ef1f0cd04e748a1
(
  cd "$snapshot_dir/webcrypto"
  bunx respec@37.2.0 --localhost spec/Overview.html \
    "$snapshot_dir/editor.html" --timeout 60
)
render_text "$snapshot_dir/editor.html" \
  docs/w3c/WebCryptoAPI/w3c-webcrypto-editors-draft.txt
```

Update the retrieval dates and pinned editor commit whenever the mutable
snapshots are refreshed.
