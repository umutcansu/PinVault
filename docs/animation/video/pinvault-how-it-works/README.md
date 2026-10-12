# PinVault — how it works (English)

The English version of [`../pinvault-nasil-calisir/`](../pinvault-nasil-calisir): a silent 2:49
explainer of the problem, the three layers (pinning, device identity, attestation), the topology, a
certificate's lifetime and the per-start order. Same 13 frames, timing and design as the Turkish
original. Five frames (01, 04, 05, 10, 12) are the English copies from
[`../pinvault-presentation/`](../pinvault-presentation) with this film's top bar and counters; the
other eight are translated here. The rendered file is
[`../../pinvault-how-it-works.en.mp4`](../../pinvault-how-it-works.en.mp4).

`STORYBOARD.md` and `BRIEF.md` are the Turkish source documents and are kept as they are; the English
text lives in `compositions/frames/*.html`. Terms and fixed strings are in
[`../translation-glossary.md`](../translation-glossary.md).

When a frame changes in the Turkish film, make the same change here (same file name) and re-render
both.

## Rebuild

HyperFrames needs Node.js 22 or newer.

```bash
cd docs/animation/video/pinvault-how-it-works
npx hyperframes@0.8.140 check
npx hyperframes@0.8.140 render --quality high --output renders/video.mp4
ffmpeg -i renders/video.mp4 -c:v libx264 -preset slow -crf 24 -pix_fmt yuv420p -movflags +faststart ../../pinvault-how-it-works.en.mp4
```
