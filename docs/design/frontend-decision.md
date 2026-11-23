# Frontend decision

## Baseline

The installed Streamlit console routes 14 views from one sidebar radio and holds the active case in session state. The evidence, forensic analysis and Lab views use the existing SQLite registry, Parquet readers and durable worker. Background jobs, archive verification, case findings and report exports already work end to end.

The baseline captures Overview, Evidence Management and the Lab against the disposable verification case at 1280 × 800, 1440 × 900 and 1920 × 1080. The overview mixes project-wide LANL measurements with case activity. The path from adding evidence to generating a report is implicit. The Lab puts configuration controls before an explanation of the experiment and repeats long variant names in charts. The app lacks shareable case navigation and a global job view.

## Decision

Keep Streamlit for this increment. The usability brief prioritizes changing the existing application incrementally and avoiding a major framework change. A React and FastAPI interface is technically possible. Page parity would require replacing Streamlit-native upload, download, keyboard focus, job polling and session handling, plus defining and reviewing new evidence, redaction and export API boundaries. That migration is outside the incremental design scope and would need a separate compatibility and security decision.

The Streamlit implementation reuses the registry, job store, comparability checks, trace rules and report renderer. Altair provides the bounded timeline and measured experiment charts. The interface can use built-in controls for keyboard operation, disclosures and progress while sharing one local stylesheet. Streamlit constrains persistent docked inspectors, exact route transitions and high-density canvas interaction. Use a selectable provenance inspector, bounded charts, and query-parameter routes inside this shell.

## Existing data and UI coverage

| Need | Existing data | UI treatment |
| --- | --- | --- |
| Investigation progress | Evidence rows, custody events, findings, jobs, snapshots | Derive status from existing records |
| Integrity feedback | Registered hash, last-check result, bytes scanned in worker phase | Show measured progress and registered hash |
| Comparison and frontier | Per-run metrics, actual accountant values, cohort identifiers | Require matching cohorts and real accounted epsilon |
| Provenance | File digests, source lines, case IDs, job configuration | Shared source chip and inspector |
| Threat descriptions | Aggregate detection outputs and study scope | Label rules, predictions and synthetic tests |
| Report previews | Case snapshots, category rows and generated PDF | Paper-style preview and preserved exports |

Measured full verification digests, calibration ROC points and optional attacker-knowledge re-evaluation are absent from the current retained results. Key rotation and temporary audited reveal would change security-sensitive behaviour. Those items need explicit authorization for backend or policy work.
