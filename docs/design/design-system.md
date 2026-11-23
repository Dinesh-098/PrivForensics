# PrivForensics design system

The living guide is available from **Specialist tools → Design system** or the local query route `/?page=design-system`. It uses the same controls and spacing as the console.

## Foundations

| Role | Values |
| --- | --- |
| Surfaces | Background #0B1017, rail #101722, workspace #111923, panel #172230, raised #1D2A3A |
| Borders | Default #263344, strong #35465A |
| Text | Primary #E8EEF5, secondary #9AA9B9, disabled #6F7F92 |
| State | Action #4C8DCE, verified #43B5A0, review #D9A441, error #D96868 |
| Geometry | 4 px grid, 4/6/8 px radii, 1 px borders, 2 px focus ring |
| Density | Compact 28 px, default 32 px, comfortable 40 px in shared data grids |

Use the CSS properties in `console.css`. The typed design reference in `src/design/tokens.ts` mirrors the palette, geometry and evidence vocabulary. Inter and IBM Plex Mono are bundled locally with their licenses. Use Inter for interface text and Plex Mono for hashes, case IDs and technical values. Keep numeric columns aligned and labels in sentence case.

The logo assets are under `assets/brand/`. The mark is a lens with a trace line and a teal segment. Use the SVG lockup for print or handoff and the supplied 16, 32, 64 px PNG or ICO for application icons. The primary navigation uses local Lucide glyphs.

## Components and behavior

| Component | Use |
| --- | --- |
| Toolbar and rail | Show the active case, page, interface mode, search, jobs and presentation control. Preserve the case using the URL. |
| Case checklist | Derive status from stored evidence, analyses, privacy operations, results and reports. Link each stage to its workflow. |
| Buttons and forms | Keep a single primary action per task. Place the reason beside an unavailable action. Use native form validation and explicit confirmation for a case status change and protected CSV export. |
| Table and inspector | Keep the first columns actionable. Use labels beside grades and states. Show source metadata in a selectable inspector or disclosure. Large data reads use the existing Parquet page limits. |
| Provenance chip | Show the short hash and source label. The popover holds the full fingerprint, source line or run metadata and the copy control. |
| Chart and dataset note | Label units, attach source and scope, and offer table data and the native Altair chart toolbar where applicable. Plot stored values. The noise explorer identifies itself as an illustration. |
| Job tray | Read worker state and progress from the job store. Where repeated byte samples exist, label sample rate and ETA as estimates. |
| Empty states | Say what is missing and provide the action that can populate it. |
| Presentation | Enlarge interface text and redact known identifier columns in the supported review views. Simple mode also masks identifiers in event review. Advanced retains the prior de-identified LANL inspection workflow. |

## Evidence vocabulary

| Type | Colour | Marker | Link style |
| --- | --- | --- | --- |
| Exact identifier | Teal | Circle | Solid |
| Temporal association | Blue | Square | Dashed |
| Heuristic | Amber | Triangle | Dotted |
| Known red-team reference | Coral | Diamond | Solid |
| Model prediction | Steel | Cross | Long dash |

The timeline uses colour, marker shape, and text labels. Its inspector states the recorded criterion and time window. Model observations in the same time range carry their own provenance. The brush controls the timeline viewport and leaves the stored matching window intact.

## Motion and keyboard

Interface transitions are limited to feedback such as row and control state. The 90/160/240/400 ms tokens use `cubic-bezier(.2, 0, 0, 1)`. System reduced motion and the override in Settings disable CSS animations and transitions. The timeline brush remains a direct manipulation control.

Command or Control + K and / open workspace search. ? opens the shortcut sheet. Press G then O, I, E, A, P, L or R to open a primary page. Native widgets keep their arrow and Tab-key interactions. Case, mode and appearance choices are URL-addressable. The rail can be compacted from its bottom control.

## Extension checklist

Use the shared UI helpers in `modules/ui.py`, the same case navigation and the same provenance wording. Start with the action a first-time investigator can take. Put model parameters and secondary views in Advanced mode or a labelled disclosure. Use a measured source, sensitivity label, and explicit scope on every data panel. Validate the visible route and the underlying operation with the existing test services.
