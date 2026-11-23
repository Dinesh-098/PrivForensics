import numpy as np
import pandas as pd
import pytest

from modules.analysis_models import AUTH_COLUMNS, fit_lanl_model, write_json
from modules.forest_artifact import FORMAT, freeze_forest, score_forest


@pytest.mark.parametrize("model", ["Random Forest", "Isolation Forest"])
def test_numeric_artifact_matches_fitted_estimator(tmp_path, model):
    n = 300
    rng = np.random.default_rng(7)
    categorical = AUTH_COLUMNS[2:]
    frame = pd.DataFrame({name: rng.choice(["one", "two", None], n) for name in categorical})
    frame["hour_in_day"] = rng.integers(0, 24, n)
    frame["positive"] = (frame["hour_in_day"] > 12) & frame[categorical[0]].eq("two")
    fitted = fit_lanl_model(frame, model, 42)
    features = frame.loc[:40, [*categorical, "hour_in_day"]].copy()
    features.loc[0, categorical[0]] = "unseen"
    expected = fitted.predict_proba(features)[:, 1] if model == "Random Forest" else -fitted.score_samples(features)
    output = tmp_path / "predictor.json"
    artifact = {"schema_version": FORMAT, "archive_sha256": "a" * 64, "models": {
        model: {"predictor": freeze_forest(fitted, model), "threshold": .5},
    }}
    write_json(output, artifact)
    values, threshold = score_forest(output, "a" * 64, model, features, categorical)
    np.testing.assert_allclose(values, expected, atol=1e-12)
    assert threshold == .5
    with pytest.raises(ValueError, match="provenance"):
        score_forest(output, "b" * 64, model, features, categorical)
    first = artifact["models"][model]["predictor"]["trees"][0]
    first["left"][0] = 0
    write_json(output, artifact)
    with pytest.raises(ValueError, match="tree structure"):
        score_forest(output, "a" * 64, model, features, categorical)
