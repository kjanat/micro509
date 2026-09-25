# IDNA2008 data

The IDNA2008 tables micro509 freezes in `src/internal/shared/idna-tables.ts`
come from the files in this directory, all for Unicode 12.0.0. That is the
latest Unicode version IANA publishes derived property values for.

| File                                    | Source                                                                           |
| --------------------------------------- | -------------------------------------------------------------------------------- |
| `idna-tables-properties-12.0.0.csv`     | <https://www.iana.org/assignments/idna-tables-12.0.0/idna-tables-properties.csv> |
| `ucd-12.0.0/DerivedBidiClass.txt`       | <https://www.unicode.org/Public/12.0.0/ucd/extracted/DerivedBidiClass.txt>       |
| `ucd-12.0.0/DerivedJoiningType.txt`     | <https://www.unicode.org/Public/12.0.0/ucd/extracted/DerivedJoiningType.txt>     |
| `ucd-12.0.0/DerivedCombiningClass.txt`  | <https://www.unicode.org/Public/12.0.0/ucd/extracted/DerivedCombiningClass.txt>  |
| `ucd-12.0.0/DerivedGeneralCategory.txt` | <https://www.unicode.org/Public/12.0.0/ucd/extracted/DerivedGeneralCategory.txt> |
| `ucd-12.0.0/Scripts.txt`                | <https://www.unicode.org/Public/12.0.0/ucd/Scripts.txt>                          |
| `ucd-12.0.0/UnicodeData.txt`            | <https://www.unicode.org/Public/12.0.0/ucd/UnicodeData.txt>                      |

The IANA table is the RFC 5892 derived property value of every code point:
PVALID, CONTEXTJ, CONTEXTO, DISALLOWED or UNASSIGNED. The Unicode Character
Database files supply the properties the RFC 5892 Appendix A contextual rules
and the RFC 5893 Bidi rule read, and the `<wide>` and `<narrow>`
decompositions the RFC 5895 mapping reads. The CSV's CRLF line endings are
stored as LF.

## License

The Unicode Character Database files are © Unicode, Inc. and distributed under
the Unicode License v3, whose copyright and permission notice must accompany
copies. It is vendored beside them as `UNICODE-LICENSE.txt`, from
<https://www.unicode.org/license.txt>. IANA's licensing terms for registry
content are at <https://www.iana.org/help/licensing-terms>.

## Regenerate

```sh
curl -fsSL https://www.iana.org/assignments/idna-tables-12.0.0/idna-tables-properties.csv |
  tr -d '\r' > docs/idna/idna-tables-properties-12.0.0.csv
for file in extracted/DerivedBidiClass.txt extracted/DerivedJoiningType.txt \
  extracted/DerivedCombiningClass.txt extracted/DerivedGeneralCategory.txt Scripts.txt \
  UnicodeData.txt; do
  curl -fsSL "https://www.unicode.org/Public/12.0.0/ucd/$file" \
    -o "docs/idna/ucd-12.0.0/$(basename "$file")"
done
bun scripts/idna-tables.bun.ts
```

`test/idna-tables.test.ts` re-derives every table from these files and fails
if `src/internal/shared/idna-tables.ts` disagrees.
