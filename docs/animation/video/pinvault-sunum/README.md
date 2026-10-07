# PinVault — presentation film (Turkish)

A silent 5:08 film for presenting PinVault, in three parts, each opened by a chapter card:

1. **Amaç: SSL pinning** — who could sit in the middle, what normal TLS trusts, how pinning checks the
   fingerprint, and the three things pinning alone does not solve.
2. **PinVault ne ekler** — one answer per gap (signed pin list, device identity, attestation) and where the
   parts run.
3. **Baştan sona** — ten rings from the server's first start to the first protected API call, what happens
   to a phone that fails attestation, what happens afterwards, and a summary.

The rendered file is [`../../pinvault-sunum.tr.mp4`](../../pinvault-sunum.tr.mp4).

Most frames are copied from the two sister projects ([`../pinvault-nasil-calisir/`](../pinvault-nasil-calisir)
and [`../pinvault-bastan-sona/`](../pinvault-bastan-sona)); only their top-bar label, pill and counter were
changed. The new frames are the chapter cards (`p1`, `p4`, `p5`), "Normal TLS neye güvenir" (`p2`) and
"Pinlemenin üç eksiği" (`p3`). Edits to a copied frame belong here, not in the sister project.

## Rebuild

HyperFrames needs Node.js 22 or newer.

```bash
cd docs/animation/video/pinvault-sunum
npx hyperframes@0.8.140 check
npx hyperframes@0.8.140 render --quality high --output renders/video.mp4
ffmpeg -i renders/video.mp4 -c:v libx264 -preset slow -crf 24 -pix_fmt yuv420p -movflags +faststart ../../pinvault-sunum.tr.mp4
```
