# PinVault — presentation film (English)

The English version of the presentation film. Same 39 frames, timing and design as the Turkish
original in [`../pinvault-sunum/`](../pinvault-sunum); only the on-screen text is translated, with the
dashboard's own English labels. The rendered file is
[`../../pinvault-presentation.en.mp4`](../../pinvault-presentation.en.mp4).

`STORYBOARD.md` and `BRIEF.md` are the Turkish source documents and are kept as they are; the English
text lives in `compositions/frames/*.html`. Terms and fixed strings are in
[`../translation-glossary.md`](../translation-glossary.md).

When a frame changes in the Turkish film, make the same change here (same file name) and re-render
both. Do not run `.hyperframes/renumber.cjs` in this project: it rewrites Turkish part labels.

## Rebuild

HyperFrames needs Node.js 22 or newer.

```bash
cd docs/animation/video/pinvault-presentation
npx hyperframes@0.8.140 check
npx hyperframes@0.8.140 render --quality high --output renders/video.mp4
ffmpeg -i renders/video.mp4 -c:v libx264 -preset slow -crf 24 -pix_fmt yuv420p -movflags +faststart ../../pinvault-presentation.en.mp4
```
