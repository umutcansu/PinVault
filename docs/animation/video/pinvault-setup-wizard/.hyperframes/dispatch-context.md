## Dispatch context

- PROJECT_DIR (TR): docs/animation/video/pinvault-kurulum-sihirbazi
- TWIN_DIR (EN): docs/animation/video/pinvault-setup-wizard (same frame file names; English screen text)
- Canvas: 1920×1080
- Captions: disabled (no caption track; keep load-bearing content at y ≤ 900; only the mono footer chrome sits below)
- Confirmed sketch: none (autonomous run; no storyboard.html)
- Audio: none. Fully SILENT film (music: none, no SCRIPT.md, no sfx).
- Total frames in this film: 15 (footer counter reads "NN • 15").

### Exception to "visible text is short motion-graphics copy / never render narration"

This film has NO voiceover and NO captions. The on-screen text under `Ekran metni` in your frame block IS the narration and MUST be rendered word for word as written (Turkish, including İ Ş Ğ Ü Ö Ç ı, the ellipsis "…", arrows "→", and code lines). Do not shorten, translate, paraphrase or re-case it. Pace reveals to READING time: a line waits about 0.35 s per word (minimum 1.2 s) before the next piece arrives. Follow the Scene windows in your block.

The English twin file renders the `English screen text` block of the same frame, word for word, with `lang="en"` on the frame root, the top-bar label "PINVAULT · SETUP WIZARD", the step cells "1 · SERVER", "2 · CERTIFICATES", "3 · APP", "4 · CODE", the strip label "WHY" instead of "NEDEN", the kicker prefix "WHO: … · WHERE: …", and the same footer counter. Same layout, same timeline, same ids; only strings change. Where the English string is longer, reduce that element's font size a step (never below 18 px) rather than changing the layout.

### Visual reference (read-only)

A sister film in the same design already exists. For consistent drawing of the shared actors (phone, PinVault server box with port labels, panel-like boxes with black header strips, ink-bordered buttons and the press gesture, analogy/NEDEN strip, chrome, chain strip geometry, closing green plate), open these finished frames read-only and match their look:
- docs/animation/video/pinvault-bastan-sona/compositions/frames/03-kurulum.html (chrome, strip cells, kicker + title, server box with ports, panel box with inputs and a pressed button, analogy strip + footnote, typeIn helper, GSAP timeline pattern)
- docs/animation/video/pinvault-bastan-sona/compositions/frames/02-iki-yanlis.html (wrong/right card with the orange strike-through and green ✓)
- docs/animation/video/pinvault-bastan-sona/compositions/frames/13-sonrasi.html (timeline with stations)
- docs/animation/video/pinvault-bastan-sona/compositions/frames/14-kapanis.html (green closing plate, cream chrome variant, self-hosted @font-face declarations)
Never copy their ids: your ids must be prefixed with your own frame_id. The step strip of THIS film has 4 cells of 400 px at x = 96 + i × 432 (see video direction), not the 10-cell chain.

### Composition contract (HyperFrames)

- The file is `<template id="<frame_id>-template"> … </template>` wrapping one `<div id="root" data-composition-id="<frame_id>" data-start="0" data-duration="<D>" data-width="1920" data-height="1080" lang="tr">` exactly like the reference frames; inside it a `<style>`, the stage `<div id="<frame_id>-stage" class="clip" data-start="0" data-duration="<D>" data-track-index="0">`, then the GSAP script tag and an IIFE that builds `gsap.timeline({ paused: true })` and registers it at `window.__timelines["<frame_id>"]`.
- `<D>` is the frame's duration from the storyboard plus 0.5 s (the transition overlap), e.g. duration 15s → data-duration="15.5"; the last animated beat ends at the storyboard duration, and a `tl.to({}, { duration: 0.01 }, D - 0.01)` anchor pins the total length.
- Deterministic and seek-safe: every motion is a GSAP tween on the paused timeline (`fromTo` with explicit from values); no CSS transition/keyframes, no `tl.call`, no `Math.random`, no `Date`, no setTimeout, no autoplay. Fonts via the Google Fonts `@import` with `display=block` (as in 03-kurulum.html) or the self-hosted `@font-face` block (as in 14-kapanis.html).
- Element ids start with the frame_id (digits first): in JS use `host.querySelector('[id="' + FID + '-' + n + '"]')`, never `#01-…` in a selector; CSS selects with `[id="…"]` / `[class~="…"]`.
- Everything is absolutely positioned inside the 1920×1080 stage; nothing overflows it. Text that must not wrap gets `white-space: nowrap`; long body text gets an explicit width.
- Press gesture for a button: scale to 0.92 for 0.1 s, an ink fill child fades in, scale back with power3.out.

### Practical notes

- Fonts: Archivo Black, Space Grotesk, JetBrains Mono (latin-ext subset for Turkish). Put `lang="tr"` on the frame root (`lang="en"` in the twin).
- Never use CSS text-transform; uppercase strings are already uppercase.
- Respect the fixed geometry of the step strip exactly, so the strip does not jump between frames. Frames 1 and 2 have no strip; frame 1 introduces it large; frames 3–14 show it at y = 104 with the current step highlighted (done steps ink-filled, future steps at 35 % opacity); frame 15 shows it filled on the green plate.
- Badges: "HAZIR" = cream fill, 2 px green border, green text; "UYARI" = yellow fill, 2 px ink border, ink text; "EKSİK" = orange fill, cream text. Mono 15 px, letter-spacing 0.06em, padding 3px 10px.
- Your terminal action is writing `compositions/frames/<frame_id>.html` in PROJECT_DIR and the same file name in TWIN_DIR. Do not edit STORYBOARD.md; do not run the CLI; do not write any other file.
