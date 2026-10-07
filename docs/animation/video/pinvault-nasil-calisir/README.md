# PinVault nasıl çalışır — explainer video (Turkish)

A silent 2:49 explainer built with [HyperFrames](https://hyperframes.heygen.com).
It introduces the request-flow animation one level up: the problem, the three
layers (pinning, device identity, attestation), the topology, a certificate's
lifetime and the per-start order. The rendered file is
[`../../pinvault-nasil-calisir.tr.mp4`](../../pinvault-nasil-calisir.tr.mp4).

The narration is the on-screen Turkish text, so the video works muted (README
embeds, autoplay). There is no voice, music or sound.

## Files

| Path | What it is |
|---|---|
| `BRIEF.md` | The intent: message, audience, length, decisions. |
| `STORYBOARD.md` | The 13 frames: exact on-screen text, timing, visual direction. Edit text here first. |
| `frame.md` | Design tokens (creative-mode preset): colors, type, rules. |
| `compositions/frames/NN-*.html` | One HTML composition per frame. |
| `index.html` | Assembled root timeline with transitions (generated). |
| `capture/extracted/visible-text.txt` | Source text pulled from the step-by-step animation. |

## Rebuild

HyperFrames needs Node.js 22 or newer.

```bash
cd docs/animation/video/pinvault-nasil-calisir
npx hyperframes@0.8.140 check
npx hyperframes@0.8.140 render --quality high --output renders/video.mp4
cp renders/video.mp4 ../../pinvault-nasil-calisir.tr.mp4
```

To preview and edit interactively: `npx hyperframes@0.8.140 preview`.
