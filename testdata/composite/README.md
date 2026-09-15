# Composite signature test vectors

Source: `draft-ietf-jose-pq-composite-sigs-04` (September 10, 2026), Appendix A.1
(JOSE examples), <https://www.ietf.org/archive/id/draft-ietf-jose-pq-composite-sigs-04.txt>.

| File | Draft figure |
|---|---|
| `ML-DSA-65-Ed25519.jose.json` | Figure 4 — the suite Warden uses |
| `ML-DSA-44-Ed25519.jose.json` | Figure 2 — second check of the same construction |

## How they were extracted

1. Took the figure's lines from the plain-text draft.
2. Removed page footers, page headers, and form feeds.
3. Unfolded RFC 8792 single-backslash line wrapping: a line ending in `\` is joined
   to the next line with that line's leading whitespace removed.
4. Parsed the result as JSON and wrote it unchanged, pretty-printed.

Values are exactly as published. Do not edit them. If the draft is revised, extract
the new figures into new files and keep these for receipts signed under `-04`.
