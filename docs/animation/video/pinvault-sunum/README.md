# PinVault — presentation film (Turkish)

A silent 6:52 film for presenting PinVault, in four parts, each opened by a chapter card:

1. **Amaç: SSL pinning** — who could sit in the middle, what normal TLS trusts, how pinning checks the
   fingerprint, and the three things pinning alone does not solve.
2. **PinVault ne ekler** — one answer per gap (signed pin list, device identity, attestation) and where the
   parts run. Each answer card names where it lives in the panel.
3. **Baştan sona** — ten rings from the server's first start to the first protected API call, what happens
   to a phone that fails attestation, and where the attestation policy is set in the panel.
4. **Dosyalar ve şifreleme** — uploading a file in the panel (Policy and Encryption), the per-device file
   token, the phone's download and the panel's download history, the three protections (at_rest,
   end_to_end, user_auth), and unlock, offline lifetime and wipe on revocation on the phone.

The film ends with what happens afterwards and a summary.

The rendered file is [`../../pinvault-sunum.tr.mp4`](../../pinvault-sunum.tr.mp4).

Most frames are copied from the two sister projects ([`../pinvault-nasil-calisir/`](../pinvault-nasil-calisir)
and [`../pinvault-bastan-sona/`](../pinvault-bastan-sona)); only their top-bar label, pill and counter were
changed. The new frames are the chapter cards (`p1`, `p4`, `p5`, `p6`), "Normal TLS neye güvenir" (`p2`),
"Pinlemenin üç eksiği" (`p3`), "Panelde: atestasyon ayarı" (`a1`) and the files part (`d1`–`d5`). The footer
counters and part labels are renumbered with `node .hyperframes/renumber.cjs` after the frame order
(`.hyperframes/order.json`) changes. Edits to a copied frame belong here, not in the sister project.

## Rebuild

HyperFrames needs Node.js 22 or newer.

```bash
cd docs/animation/video/pinvault-sunum
npx hyperframes@0.8.140 check
npx hyperframes@0.8.140 render --quality high --output renders/video.mp4
ffmpeg -i renders/video.mp4 -c:v libx264 -preset slow -crf 24 -pix_fmt yuv420p -movflags +faststart ../../pinvault-sunum.tr.mp4
```
