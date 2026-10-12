# PinVault — end to end (English)

The English version of [`../pinvault-bastan-sona/`](../pinvault-bastan-sona): a silent 3:16 film of ten
rings, from the PinVault server's first start to the first protected API call. Same 14 frames, timing
and design as the Turkish original. The frames are the English copies from
[`../pinvault-presentation/`](../pinvault-presentation) (which carries every frame of this film); only
the top-bar label, the opening pill and the footer counters differ, as between the two Turkish
projects. The rendered file is [`../../pinvault-end-to-end.en.mp4`](../../pinvault-end-to-end.en.mp4).

`STORYBOARD.md` and `BRIEF.md` are the Turkish source documents and are kept as they are; the English
text lives in `compositions/frames/*.html`. Terms and fixed strings are in
[`../translation-glossary.md`](../translation-glossary.md).

When a frame changes in the Turkish film, make the same change here and in
`../pinvault-presentation/` (same file name) and re-render the films.

## Rebuild

HyperFrames needs Node.js 22 or newer.

```bash
cd docs/animation/video/pinvault-end-to-end
npx hyperframes@0.8.140 check
npx hyperframes@0.8.140 render --quality high --output renders/video.mp4
ffmpeg -i renders/video.mp4 -c:v libx264 -preset slow -crf 24 -pix_fmt yuv420p -movflags +faststart ../../pinvault-end-to-end.en.mp4
```
