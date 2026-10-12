# Animation and films

Material that shows how PinVault works: an interactive walkthrough of every
request and three short films, each in English and Turkish. Linked from the [main README](../../README.md#animation-and-films) (under "How it works").

## Request-flow animation

A single-file, step-by-step animation of what PinVault does on the wire:
the product introduction, the two kinds of Config API, the init order
(pending enrollments → certificate renewal → config / host certificate /
health per API → attestation → key registration → stale-file wipe), the
attestation and token refresh loop (a token lasts 5 minutes and is renewed
about every 4), the policy, trust roots,
revocation, and a drawing of the whole topology. 15 chapters, 100 steps; it
runs offline in any browser.

| Language | Open (renders in the browser) | Source |
|---|---|---|
| English | [▶ pinvault-request-flow.en.html](https://raw.githack.com/umutcansu/PinVault/main/docs/animation/pinvault-request-flow.en.html) | [`pinvault-request-flow.en.html`](./pinvault-request-flow.en.html) |
| Türkçe | [▶ pinvault-request-flow.tr.html](https://raw.githack.com/umutcansu/PinVault/main/docs/animation/pinvault-request-flow.tr.html) | [`pinvault-request-flow.tr.html`](./pinvault-request-flow.tr.html) |

The "open" links go through raw.githack.com, which serves the file from
this repository's `main` branch as a real page (GitHub's own file view
shows the source); githack first shows a one-click notice ("Open the page").
The films play on one page the same way: [▶ films.html](https://raw.githack.com/umutcansu/PinVault/main/docs/animation/films.html) (source
[`films.html`](./films.html); covers in [`posters/`](posters)). Offline:
download the source file and double-click it; it has no external dependencies.

## Presentation film (English and Turkish)

The one to show first: a silent 9:58 film in four parts. It starts with the
purpose (what SSL pinning is, why normal TLS is not enough, and what pinning
alone leaves open), then what PinVault adds (including the two kinds of
Config API, TLS and mTLS, and how an mTLS one is opened in the panel), then the
whole flow from the
server's first start to the first protected API call (with the choice of
where the signing key lives: file, HSM or KMS, and why the phone's key is an
elliptic-curve key), and finally file
delivery: uploading in the panel, who may download, the phone's download, and
the three protections (encrypted on the server, end to end, screen lock).
Each step shows its panel screen first. Near the end a single "working
factory" scene plays the whole flow on one fixed map of the system.

| Language | Video | Source |
|---|---|---|
| English | [▶ pinvault-presentation.en.mp4](https://raw.githack.com/umutcansu/PinVault/main/docs/animation/films.html#presentation) | [`video/pinvault-presentation/`](video/pinvault-presentation) |
| Türkçe | [▶ pinvault-sunum.tr.mp4](https://raw.githack.com/umutcansu/PinVault/main/docs/animation/films.html#sunum) | [`video/pinvault-sunum/`](video/pinvault-sunum) |

Both are 1920×1080 and about 15 MB. Every claim on screen was checked
against the library, the reference server and the dashboard. The two
videos below are its shorter parts, also in both languages.

## Explainer video (English and Turkish)

A silent 2:49 video that introduces the animation one level up: the problem,
the three layers (pinning, device identity, attestation), the topology, a
certificate's lifetime and the order of work on every start. The narration is
the on-screen text, so it plays fine muted.

| Language | Video | Source |
|---|---|---|
| English | [▶ pinvault-how-it-works.en.mp4](https://raw.githack.com/umutcansu/PinVault/main/docs/animation/films.html#how-it-works) | [`video/pinvault-how-it-works/`](video/pinvault-how-it-works) |
| Türkçe | [▶ pinvault-nasil-calisir.tr.mp4](https://raw.githack.com/umutcansu/PinVault/main/docs/animation/films.html#nasil-calisir) | [`video/pinvault-nasil-calisir/`](video/pinvault-nasil-calisir) |

1920×1080, about 4.4 MB each, built with HyperFrames; each folder's README
explains how to edit and re-render it.

## End-to-end video (English and Turkish)

A silent 3:16 video that walks the whole chain in order, ring by ring, with the
real panel and phone screens: the server's first start and setup wizard, what
goes into the APK, adding the API host, issuing the enrollment token, getting it
to the phone, the enrollment request, the certificate, the signed pin list, the
PinVault-Token from attestation and the first protected API call.

| Language | Video | Source |
|---|---|---|
| English | [▶ pinvault-end-to-end.en.mp4](https://raw.githack.com/umutcansu/PinVault/main/docs/animation/films.html#end-to-end) | [`video/pinvault-end-to-end/`](video/pinvault-end-to-end) |
| Türkçe | [▶ pinvault-bastan-sona.tr.mp4](https://raw.githack.com/umutcansu/PinVault/main/docs/animation/films.html#bastan-sona) | [`video/pinvault-bastan-sona/`](video/pinvault-bastan-sona) |

1920×1080, about 5.2 MB each.
