# PinVault baştan sona — end-to-end video (Turkish)

A silent explainer built with [HyperFrames](https://hyperframes.heygen.com) that walks the whole chain
in order, from the server's first start to the app's first protected API call. Ten rings:

1. Kurulum (server first start, setup wizard) · 2. APK (bootstrap pins, init block) ·
3. Host (API host and its pins in the panel) · 4. Token (generated in the panel or by your login server) ·
5. Telefona (delivery, `enrollForResult` before `init`) · 6. Kayıt isteği (8091, CSR, token) ·
7. Kart (server checks, token spent, 90-day certificate) · 8. Pin listesi (8092, signed list) ·
9. Bilet (attestation, 5-minute PinVault-Token) · 10. İlk istek (API server verifies the token itself).

The rendered file is [`../../pinvault-bastan-sona.tr.mp4`](../../pinvault-bastan-sona.tr.mp4). Its sister video,
the concept overview, lives in [`../pinvault-nasil-calisir/`](../pinvault-nasil-calisir).

## Files

| Path | What it is |
|---|---|
| `BRIEF.md` | Intent, audience, decisions and the verified order. |
| `STORYBOARD.md` | The 14 frames with the exact on-screen text. Edit text here first. |
| `frame.md` | Design tokens (creative-mode preset), shared with the sister video. |
| `compositions/frames/NN-*.html` | One HTML composition per frame. |
| `index.html` | Assembled root timeline with transitions (generated). |

## Rebuild

HyperFrames needs Node.js 22 or newer.

```bash
cd docs/animation/video/pinvault-bastan-sona
npx hyperframes@0.8.140 check
npx hyperframes@0.8.140 render --quality high --output renders/video.mp4
ffmpeg -i renders/video.mp4 -c:v libx264 -preset slow -crf 24 -pix_fmt yuv420p -movflags +faststart ../../pinvault-bastan-sona.tr.mp4
```
