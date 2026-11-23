"""Small, local evidence fixtures for exercising the normal application entry point."""
import gzip
from pathlib import Path
import subprocess
import sys

import pytest

from modules.analysis_models import lanl_experiment, process_experiment, write_json
from modules.lanl_correlation import correlate
from modules.lanl_parquet import export_archive


@pytest.fixture(scope="session")
def prepared_project(tmp_path_factory):
    project = tmp_path_factory.mktemp("prepared-project")
    csv = project / "dataset/forensic_auth_logs.csv"
    csv.parent.mkdir()
    generator = project / "dataset/generate_dataset.py"
    generator.write_bytes((Path(__file__).resolve().parents[1] / "dataset/generate_dataset.py").read_bytes())
    subprocess.run([sys.executable, "-B", "-c",
                    "from dataset.generate_dataset import generate_dataset; generate_dataset(850)"],
                   cwd=project, check=True, capture_output=True)
    archive = project / "dataset/lanl"
    archive.mkdir()
    exported = project / "dataset/processed/lanl-v1"
    feeds = {kind: [] for kind in ("auth", "proc", "redteam")}
    for day in range(1, 11):
        time = 86_400 * day + 100
        feeds["auth"].append(f"{time},U1@D,U1@D,C1,C2,NTLM,Network,LogOn,Fail")
        feeds["redteam"].append(f"{time},U1@D,C1,C2")
        feeds["proc"].extend([f"{time-1},U1@D,C2,P2,Start", f"{time+1},U1@D,C2,P2,End"])
        for ordinal in range(1, 12):
            feeds["auth"].append(f"{time+ordinal},U2@D,U2@D,C3,C2,Kerberos,Interactive,LogOn,Success")
            feeds["proc"].append(f"{time+ordinal+1},U2@D,C3,P{ordinal % 4},Start")
    # Keep the process feed a true demonstration of chronological sampling.
    feeds["proc"] = sorted(feeds["proc"], key=lambda line: int(line.split(",", 1)[0]))
    for kind, lines in feeds.items():
        path = archive / f"{kind}.txt.gz"
        path.write_bytes(gzip.compress(("\n".join(lines) + "\n").encode(), mtime=0))
        export_archive(path, kind, exported / kind, block_bytes=1024)
    correlate(exported, exported / "correlation")
    output = project / "models/lanl_auth.json"
    write_json(project / "reports/experiments/lanl.json",
               lanl_experiment(exported, model_path=output))
    write_json(project / "reports/experiments/process.json", process_experiment(exported))
    return project


@pytest.fixture
def app_environment(monkeypatch, prepared_project, tmp_path):
    state = tmp_path / "state"
    monkeypatch.setenv("PRIVFORENSICS_PROJECT_ROOT", str(prepared_project))
    monkeypatch.setenv("PRIVFORENSICS_STATE_DIR", str(state))
    monkeypatch.delenv("PRIVFORENSICS_AUTH_MODEL", raising=False)
    monkeypatch.delenv("PRIVFORENSICS_RESULTS", raising=False)
    return state
