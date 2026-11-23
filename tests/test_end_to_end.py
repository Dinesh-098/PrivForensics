from pathlib import Path
from time import monotonic, sleep

import pytest
from streamlit.testing.v1 import AppTest

from modules.evidence import Registry
from modules.investigation import Investigation
from modules.jobs import ACTIVE, JobStore
from modules.lab_ui import LAB_PAGE
from modules.reporting import case_pdf
from test_dashboard import create_case, element, go


APP = Path(__file__).resolve().parents[1] / "app.py"


def wait_for(store, case, kind):
    deadline = monotonic() + 25
    while monotonic() < deadline:
        jobs = store.list(case, kind, limit=1)
        if jobs and jobs[0].status not in ACTIVE:
            job = jobs[0]
            assert job.status == "succeeded", job.error
            return job
        sleep(.12)
    pytest.fail(f"{kind} did not complete")


def test_evidence_lab_timeline_and_report(app_environment):
    app = AppTest.from_file(str(APP), default_timeout=30).run()
    case = create_case(app, "Case workflow")
    element(app.button_group, "Interface mode").set_value("Advanced").run()
    registry = Registry(app_environment)
    store = JobStore(registry)

    go(app, "Evidence Management")
    element(app.radio, "Registration method").set_value("Prepared LANL archives").run()
    element(app.multiselect, "Archives to register").set_value(["auth", "proc", "redteam"]).run()
    element(app.button, "Queue LANL archive registration").click().run()
    registration = wait_for(store, case, "register_lanl")
    assert len(registration.result["registered"]) == 3
    app.run()
    item = next(row for row in registry.list("evidence", case) if row["name"] == "redteam.txt.gz")
    element(app.selectbox, "Inspect evidence").set_value(item["id"]).run()
    element(app.button, "Queue SHA-256 verification").click().run()
    assert wait_for(store, case, "verify_evidence").result["matches"]
    app.run()
    element(app.selectbox, "LANL schema").set_value("redteam").run()
    element(app.button, "Queue LANL ingestion").click().run()
    ingest = wait_for(store, case, "ingest_lanl")
    assert ingest.result["valid_records"] == 10
    go(app, "Dataset Explorer")
    element(app.radio, "Data source").set_value("Case LANL exports").run()
    assert "timestamp_s" in app.dataframe[0].value
    assert "account" not in app.dataframe[0].value

    go(app, "Event Correlation")
    anchor = element(app.selectbox, "Inspect event timeline")
    anchor.select(anchor.options[0]).run()
    element(app.button, "Save timeline finding").click().run()
    assert len(Investigation(registry).findings(case)[0]["references"]) >= 3

    go(app, LAB_PAGE)
    element(app.button, "Register synthetic dataset").click().run()
    element(app.number_input, "Training epochs").set_value(2)
    element(app.text_input, "Target epsilons").set_value("8")
    element(app.button, "Queue evaluation run").click().run()
    baseline = wait_for(store, case, "evaluation")
    app.run()
    assert not app.error and not app.exception
    assert len(baseline.result["variants"]) == 5
    element(app.button, "Rerun saved configuration").click().run()
    rerun = wait_for(store, case, "evaluation")
    assert rerun.parent_id == baseline.id
    assert [row["utility"] for row in baseline.result["variants"]] == [
        row["utility"] for row in rerun.result["variants"]]
    app.run()
    element(app.radio, "Lab workspace").set_value("Compare").run()
    element(app.multiselect, "Completed runs").set_value([baseline.id, rerun.id]).run()
    assert app.dataframe and not app.error and not app.exception

    go(app, "Attack Simulation")
    assert app.dataframe and not app.error
    go(app, "Reports")
    element(app.button, "Generate investigation report").click().run()
    assert not app.error and not app.exception
    workspace = Investigation(registry)
    report_id = workspace.reports(case)[0]["id"]
    report = workspace.report(case, report_id)
    assert len(report["evaluations"]) == 2
    assert report["evidence"][2]["last_integrity_check"]["passed"]
    assert report["findings"][0]["kind"] == "Event correlation"
    assert case_pdf(report).startswith(b"%PDF-")
    assert not workspace.reports(registry.case("Separate case"))
    assert registry.checked_audit()



def test_simple_mode_runs_a_real_masking_comparison(app_environment):
    app = AppTest.from_file(str(APP), default_timeout=30).run()
    case = create_case(app, "Beginner workflow")
    go(app, LAB_PAGE)
    assert element(app.button, "Run experiment").disabled
    element(app.button, "Register synthetic dataset").click().run()
    element(app.selectbox, "Experiment preset").set_value("Quick trial")
    element(app.button, "Run experiment").click().run()
    store = JobStore(Registry(app_environment))
    result = wait_for(store, case, "evaluation")
    assert result.config["configurations"] == ["E0", "E1"]
    assert result.config["neural"]["epochs"] == 2
    app.run()
    assert not app.exception
    assert not app.error
    go(app, "Dashboard")
    assert element(app.button, "Protect records")
    go(app, "Privacy Protection")
    element(app.button, "Protect selected records").click().run()
    assert any("Applied" in item.value for item in app.success)
