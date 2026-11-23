"""Run measured PrivForensics experiments against the supplied evidence."""
import argparse
from pathlib import Path

import pandas as pd

from modules.analysis_models import lanl_experiment, process_experiment, synthetic_experiment, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("all", "synthetic", "lanl", "process"), default="all")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--model-output", type=Path)
    args = parser.parse_args()
    root = args.root
    output = args.output or root / "reports" / "experiments"
    exports = root / "dataset/processed/lanl-v1"
    jobs = {
        "synthetic": lambda: synthetic_experiment(pd.read_csv(root / "dataset/forensic_auth_logs.csv")),
        "lanl": lambda: lanl_experiment(exports, model_path=args.model_output or root / "models/lanl_auth.json"),
        "process": lambda: process_experiment(exports),
    }
    for kind, run in jobs.items():
        if args.kind in (kind, "all"):
            result = run()
            write_json(output / f"{kind}.json", result)
            print(f"{kind} results saved to {output / (kind + '.json')}", flush=True)


if __name__ == "__main__":
    main()
