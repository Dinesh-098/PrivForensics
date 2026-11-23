import pytest

from modules.evidence import Registry
from modules.jobs import JobStore
from modules.lab import SYNTHETIC, evaluation_config, synthetic_fingerprint
from modules.worker import drain


def test_actual_lab_variants_and_accounting(tmp_path, prepared_project):
    project = prepared_project
    registry = Registry(tmp_path)
    case = registry.case("Evaluation")
    registry.register_reference(case, project / SYNTHETIC, expected=synthetic_fingerprint(project))
    item = registry.list("evidence", case)[0]
    cfg = evaluation_config(project, item, "synthetic", "Neural Network",
                            ["E0", "E1", "E2", "E3", "E4"], epochs=2, budgets=[8.])
    store = JobStore(registry)
    job_id, _ = store.submit(case, "evaluation", cfg)
    drain(registry, project)
    run = store.get(case, job_id)
    assert run.status == "succeeded", run.error
    assert set(run.result["cohort"]["splits"]) == {"train", "validation", "test", "nonmembers"}
    variants = run.result["variants"]
    assert [row["configuration"] for row in variants] == ["E0", "E1", "E2", "E3", "E4"]
    assert variants[0]["utility"] == variants[1]["utility"] == variants[2]["utility"] == variants[3]["utility"]
    assert variants[0]["privacy"]["unchanged_fraction"] == 1
    assert variants[3]["privacy"]["unchanged_fraction"] == 0
    dp = variants[-1]["privacy"]
    assert 0 < dp["epsilon_spent"] <= 8.01
    assert dp["noise_multiplier"] > 0 and dp["optimizer_steps"] > 0
    assert dp["membership"]["held_out_queries"] > 0
    assert variants[-1]["phase_metrics"]["train"]["sampled_peak_rss_bytes"] > 0
    assert store.private_training_ledger(item["sha256"])["fits"] == 1

    with pytest.raises(ValueError, match="requires the synthetic neural network"):
        evaluation_config(project, item, "synthetic", "Random Forest", ["E4"])
