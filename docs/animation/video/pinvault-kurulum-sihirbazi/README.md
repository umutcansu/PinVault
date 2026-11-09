# PinVault Kurulum Sihirbazı — setup wizard film (Turkish)

A silent explainer built with [HyperFrames](https://hyperframes.heygen.com) that walks the dashboard's
Setup Wizard from the first question ("the server runs, is it ready for production?") to the first phone,
step by step and with the reason for every row:

1. Sunucu (13 checks, the real "now" column, fixed from the Settings card or `.env`) ·
2. Sertifikalar (the Config API's own certificate, the client CA and device certificates, pinned hosts
and whose key the backup pin trusts, vault file expiry) · 3. Uygulama (which Config API, which
protections, what each box answers) · 4. Kod (generated from the server's own values, where each value
comes from) · the first phone · afterwards (daily expiry reminders, pin history and restore, two-person
approval).

The rendered file is [`../../pinvault-kurulum-sihirbazi.tr.mp4`](../../pinvault-kurulum-sihirbazi.tr.mp4).
Its sister films: the concept overview [`../pinvault-nasil-calisir/`](../pinvault-nasil-calisir) and the
chain from the server's first start to the first protected call [`../pinvault-bastan-sona/`](../pinvault-bastan-sona).

The English version is [`../pinvault-setup-wizard/`](../pinvault-setup-wizard): the same frames with the
`English screen text` block of each storyboard frame; make a frame change in both and re-render.

## Files

| Path | What it is |
|---|---|
| `BRIEF.md` | Intent, audience, decisions and the verified facts. |
| `STORYBOARD.md` | The 15 frames with the exact on-screen text in Turkish and English. Edit text here first. |
| `frame.md` | Design tokens (creative-mode preset), shared with the sister films. |
| `.hyperframes/video-direction.md` | Palette meanings, fixed actors, the step-strip geometry, the NEDEN strip, motion rules. |
| `compositions/frames/NN-*.html` | One HTML composition per frame. |
| `index.html` | Assembled root timeline with transitions. |

## Rebuild

HyperFrames needs Node.js 22 or newer.

```bash
cd docs/animation/video/pinvault-kurulum-sihirbazi
npx hyperframes@0.8.140 check
npx hyperframes@0.8.140 render --quality high --output renders/video.mp4
ffmpeg -i renders/video.mp4 -c:v libx264 -preset slow -crf 24 -pix_fmt yuv420p -movflags +faststart ../../pinvault-kurulum-sihirbazi.tr.mp4
```
