# Frontend verification

## Gates

- **D1** captured 9 original screenshots from the overview, evidence and evaluation views. The [framework decision](frontend-decision.md) documents the compatibility and service boundaries.
- **D2–D8** captured the shared design patterns and all 14 application pages against the disposable verification case. The fixture contains measurements produced by the original experiment engine and prepared LANL exports.
- **D9** exercised all 15 routes with Playwright on Chromium 157.0.8103.79. It checked deep-linked cases, command search, Simple and Advanced setup, a keyboard route shortcut and a PDF download. Browser requests stayed on loopback. Screenshots cover 1280 × 800, 1440 × 900 and 1920 × 1080. The deuteranopia capture checks that timeline lane labels and marker shapes remain distinguishable.
- **Python verification** passed 33 tests. It includes a Simple-mode run using stored E0/E1 results, an Advanced E0–E4 run and rerun, evidence verification and ingestion, saved findings, and report generation.

Axe reported zero serious or critical findings on the rendered routes. One minor presentation-role finding belongs to the native Streamlit upload widget. The browser showed no console errors in this verification run. This is an automated check of the exercised states, with manual review of the key desktop captures.

[Browser verification measurements](screenshots/browser-verification.json)

## Browser loading measurements

The budgets were assigned to interactive routes before the browser run. The measurements below are encoded same-origin JavaScript resource sizes from the Resource Timing API. First view is the time to the visible route heading and loaded case footer. The tests use an already running local Streamlit process on this machine.

| Route | Budget (KiB) | Measured (KiB) | First view (ms) |
| --- | ---: | ---: | ---: |
| design-system | 3,072 | 3,907 | 538 |
| overview | 3,072 | 3,907 | 403 |
| investigations | 3,072 | 3,928 | 476 |
| evidence | 3,072 | 3,978 | 425 |
| datasets | 4,096 | 4,794 | 478 |
| correlation | 4,096 | 4,801 | 519 |
| privacy-assessment | 3,072 | 3,925 | 407 |
| protection | 3,072 | 2,243 | 381 |
| analysis | 4,096 | 4,783 | 419 |
| evaluation | 4,096 | 4,768 | 376 |
| privacy-diagnostics | 4,096 | 4,748 | 420 |
| performance | 4,096 | 4,748 | 401 |
| reports | 3,072 | 3,909 | 369 |
| audit | 3,072 | 4,154 | 409 |
| settings | 3,072 | 2,243 | 892 |

The local verification run recorded 64 redesigned captures. Several routes exceed their initial JavaScript budgets. Streamlit supplies a shared client bundle and loads additional table and chart code where those components are used.

## Scope

This implementation retains Streamlit's inline, responsive inspector and bounded Vega charts. The filterable table and keyboard-operable range control accompany the timeline brush. The existing worker result schema supplies the measured privacy diagnostics and integrity status. A full recomputed digest display and a complete membership ROC curve need additional stored results. Timed audited reveal and key rotation require a separate security authorization.
