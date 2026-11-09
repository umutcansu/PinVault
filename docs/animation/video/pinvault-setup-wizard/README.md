# PinVault — Setup Wizard film (English)

The English version of [`../pinvault-kurulum-sihirbazi/`](../pinvault-kurulum-sihirbazi): a silent film that
walks the dashboard's Setup Wizard step by step, with the reason for every row — 1 · Server (13 checks),
2 · Certificates (the Config API's own certificate, device certificates, pinned hosts, vault file expiry),
3 · App (which protections and what each one answers), 4 · Code (generated from the server's own values),
then the first phone and what the dashboard keeps reminding you of afterwards. Same 15 frames, timing and
design as the Turkish original; only the strings differ. The rendered file is
[`../../pinvault-setup-wizard.en.mp4`](../../pinvault-setup-wizard.en.mp4).

The storyboard and brief live in the Turkish project (`STORYBOARD.md` there carries an `English screen text`
block per frame); the English text lives in `compositions/frames/*.html` here. Terms and fixed strings are
in [`../translation-glossary.md`](../translation-glossary.md).

When a frame changes in the Turkish film, make the same change here and re-render both films.

## Rebuild

HyperFrames needs Node.js 22 or newer.

```bash
cd docs/animation/video/pinvault-setup-wizard
npx hyperframes@0.8.140 check
npx hyperframes@0.8.140 render --quality high --output renders/video.mp4
ffmpeg -i renders/video.mp4 -c:v libx264 -preset slow -crf 24 -pix_fmt yuv420p -movflags +faststart ../../pinvault-setup-wizard.en.mp4
```
