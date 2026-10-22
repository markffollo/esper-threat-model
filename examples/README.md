# Example reports

Four full STRIDE / DREAD threat model reports produced by this skill, one per
app type it handles. Open any HTML file in a browser; each is a single
self-contained file with a sticky header, sidebar navigation, a data flow
diagram, DREAD-scored findings with file:line evidence, severity filters, and
a machine-readable `.yaml` copy where noted.

| Report | App type | Findings |
|---|---|---|
| [stealthit-threat-model.html](stealthit-threat-model.html) | Electron-style desktop overlay app, two shipped variants compared | 8 |
| [vibeyard-threat-model.html](vibeyard-threat-model.html) | Electron desktop app managing local AI coding agents, ASTRIDE applied | 8 |
| [tolink-threat-model.html](tolink-threat-model.html) + [yaml](tolink-threat-model.yaml) | Go/TS URL shortener: browser-to-API, API-to-DB/cache, outbound redirect | 8 |
| [standup-buddy-threat-model.html](standup-buddy-threat-model.html) + [yaml](standup-buddy-threat-model.yaml) | NativePHP single-user desktop app, loopback server | 6 |

Notes on two of them, since both corrected a wrong first assumption about app
type, which is exactly the skill's classification-first pitfall in action:

- **StandUp Buddy** was described as a standup-order web app but is a
  NativePHP single-user desktop app (loopback Laravel server, no database).
- **StealthIt** ships two variants (original + rebuild); each finding names
  which variant it applies to.
