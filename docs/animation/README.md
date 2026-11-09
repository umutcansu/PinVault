# Animation and films

Material that shows how PinVault works: an interactive walkthrough of every
request, four short films and a recorded dashboard tour, each in English and Turkish. Linked from the [main README](../../README.md#animation-and-films) (under "How it works").

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

## Setup wizard film (English and Turkish)

A silent 3:32 film that walks the dashboard's Setup Wizard step by step, with
the reason for every row: 1 · Server (the 13 production checks, the real "now"
column, fixed from the Settings card or `.env`), 2 · Certificates (the Config
API's own certificate and its backup key, the client CA and device
certificates, pinned hosts and whose key the backup pin trusts, vault file
expiry), 3 · App (which Config API, which protections, what each box answers),
4 · Code (generated from the server's own values, where each value comes
from), then the first phone and what the dashboard keeps reminding you of
afterwards (daily expiry checks, pin history and one-click restore, two-person
approval).

| Language | Video | Source |
|---|---|---|
| English | [▶ pinvault-setup-wizard.en.mp4](https://raw.githack.com/umutcansu/PinVault/main/docs/animation/films.html#setup-wizard) | [`video/pinvault-setup-wizard/`](video/pinvault-setup-wizard) |
| Türkçe | [▶ pinvault-kurulum-sihirbazi.tr.mp4](https://raw.githack.com/umutcansu/PinVault/main/docs/animation/films.html#kurulum-sihirbazi) | [`video/pinvault-kurulum-sihirbazi/`](video/pinvault-kurulum-sihirbazi) |

## Recorded dashboard tour (English and Turkish)

Not a drawn film: a screen recording of the real dashboard, driven click by
click on a throwaway server, with a caption under every step that says what
is being done and why. The path is the one in [SETUP.md](../../SETUP.md): the
address and the API key, the listeners in the sidebar, the wizard's 1 · Server
(the checks, *How to*, the `.env` lines, *Open in the Settings card*), 2 ·
Certificates (which of the four cards is ours), the Bootstrap tab where the
server's production certificate is managed (*Regenerate Cert*, *Upload JKS*),
adding your own API host (*Fetch from URL*, the backup pin box, *Manual*), the
enrollment token for a phone with a device identity (shown once), 3 · App and
4 · Code with *Next steps*. 1440×900 with the panel enlarged 1.35× so its
12–13 px text reads in the video; about 6 minutes, around 20 MB each. Each
video has a chapter list under it on the films page (nine chapters, one per
stop of the tour), read from the `.chapters.vtt` file next to the mp4.

| Language | Video | Chapters | Captions |
|---|---|---|---|
| English | [▶ pinvault-setup-in-the-dashboard.en.mp4](https://raw.githack.com/umutcansu/PinVault/main/docs/animation/films.html#setup-in-the-dashboard) | `pinvault-setup-in-the-dashboard.en.chapters.vtt` | [`sample-e2e/scripts/setup-tour-captions.js`](../../sample-e2e/scripts/setup-tour-captions.js) |
| Türkçe | [▶ pinvault-panelde-kurulum.tr.mp4](https://raw.githack.com/umutcansu/PinVault/main/docs/animation/films.html#panelde-kurulum) | `pinvault-panelde-kurulum.tr.chapters.vtt` | same file, `tr` block |

It is re-recorded, not edited: `sample-e2e/scripts/record-setup-tour.js`
starts the E2E suite's temporary host (`lib/freshHost.js`, Docker, no phone
needed), drives the dashboard with Playwright while recording, converts with
ffmpeg and writes the mp4s, posters and chapter files (WebVTT, the second
each chapter starts at) here.

```bash
cd sample-e2e && E2E_FRESH_PORT_BASE=6950 node scripts/record-setup-tour.js --fresh   # tr + en
```

`--lang tr` records one language, `--keep-host` leaves the temporary server
for the next run, `--fresh` rebuilds it per language so no token or host from
the other recording shows, `--zoom 1.5` changes how much the panel is
enlarged. Whenever the panel changes (labels, a new step), run it again; the
captions and chapter titles live in `setup-tour-captions.js`.

1920×1080, built with HyperFrames; each folder's README explains how to edit and re-render it.

To look at `films.html` locally run `node docs/animation/serve.js` and open
`http://127.0.0.1:8766/films.html`; a plain `python3 -m http.server` serves no
byte ranges, so the videos cannot be seeked there and the chapter list does nothing.
