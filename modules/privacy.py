"""Direct-identifier analysis, masking, keyed pseudonyms and privacy benchmarks."""
from functools import lru_cache
import hashlib
import hmac
import os
import re

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix


IDENTIFIERS = ("User_ID", "Email", "IP_Address")
QUASI = ("Login_Hour", "Device_Type", "Location", "Access_Type")


@lru_cache(maxsize=1)
def presidio():
    import tldextract
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    from presidio_anonymizer import AnonymizerEngine
    tldextract.extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    engine = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]
    }).create_engine()
    return AnalyzerEngine(nlp_engine=engine), AnonymizerEngine()


def text_privacy(text):
    analyzer, anonymizer = presidio()
    findings = analyzer.analyze(text=text, language="en")
    return ([{"type": r.entity_type, "start": r.start, "end": r.end,
              "confidence": round(r.score, 3)} for r in findings],
            anonymizer.anonymize(text=text, analyzer_results=findings).text)


def assess(frame):
    groups = frame.groupby(list(QUASI), dropna=False)["Status"].transform("size")
    return {
        "rows": len(frame),
        "direct_identifier_counts": {name: int(frame[name].notna().sum()) for name in IDENTIFIERS},
        "quasi_identifier_singletons": int(groups.eq(1).sum()),
        "groups_under_five_rows": int(groups.lt(5).sum()),
        "risks": ["Direct exposure", "Quasi-identifier linkage", "Training membership leakage"],
    }


def secret():
    value = os.environ.get("PRIVFORENSICS_HMAC_KEY")
    if not value or not re.fullmatch(r"[a-fA-F0-9]{64,}", value) or len(value) % 2:
        raise ValueError("Set PRIVFORENSICS_HMAC_KEY to at least 32 random bytes encoded in hex")
    return bytes.fromhex(value)


def pseudonym(value, namespace, key):
    if len(key) < 32:
        raise ValueError("HMAC key must contain at least 32 bytes")
    message = f"privforensics:v1:{namespace}\0{value}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()[:32]


def _transform(frame, columns, method, key):
    if method not in {"mask", "hmac"}:
        raise ValueError("Unknown protection method")
    if method == "hmac" and key is None:
        key = secret()
    result = frame.copy()
    for name, namespace in columns.items():
        if name not in result:
            continue
        if method == "mask":
            result[name] = result[name].map(lambda x: f"<{namespace.upper()}>" if pd.notna(x) else x)
        else:
            result[name] = result[name].map(lambda x: pseudonym(x, namespace, key) if pd.notna(x) else x)
    return result


def _field_scopes(columns, fields, scope):
    return {
        name: f"{scope}/{namespace}" if scope else namespace
        for name, namespace in columns.items() if fields is None or name in fields
    }


def protect(frame, method, key=None, *, fields=None, scope=None):
    columns = {name: name for name in IDENTIFIERS}
    return _transform(frame, _field_scopes(columns, fields, scope), method, key)


LANL_IDENTIFIERS = {
    "account": "lanl.account", "source_account": "lanl.account",
    "destination_account": "lanl.account", "computer": "lanl.computer",
    "source_computer": "lanl.computer", "destination_computer": "lanl.computer",
    "process": "lanl.process",
}


def protect_lanl(frame, method, key=None, *, fields=None, scope=None):
    """Use the same scope for an identifier type across LANL roles and feeds."""
    return _transform(frame, _field_scopes(LANL_IDENTIFIERS, fields, scope), method, key)


def binary_metrics(y, prediction):
    tn, fp, fn, tp = confusion_matrix(y, prediction, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if fp + tn else 0
    tpr = tp / (tp + fn) if tp + fn else 0
    return {"accuracy": float(accuracy_score(y, prediction)),
            "precision": float(precision_score(y, prediction, zero_division=0)),
            "recall": float(recall_score(y, prediction, zero_division=0)),
            "false_positive_rate": float(fpr), "false_negative_rate": float(1-tpr),
            "advantage": float(tpr-fpr)}


def linkage_benchmark(seed):
    """Measure uniqueness and correct record linkage on generated identities."""
    rng = np.random.default_rng(seed)
    n = 2000
    identities = pd.DataFrame({
        "identity": np.arange(n), "hour": rng.integers(0, 24, n),
        "area": rng.integers(0, 45, n), "device": rng.integers(0, 4, n),
    })
    # Auxiliary data knows fine-grained quasi-identifiers for half of the targets.
    known = identities.sample(n=n//2, random_state=seed)
    target = identities.sample(frac=1, random_state=seed+1)
    direct = np.array(target["identity"].isin(known["identity"]), dtype=int)
    rows = []
    for variant in ("direct identifiers", "masked identifiers", "HMAC identifiers",
                    "masking with generalized quasi-identifiers"):
        candidate = target.copy()
        auxiliary = known
        if variant == "direct identifiers":
            key = ["identity"]
        elif variant == "masking with generalized quasi-identifiers":
            candidate = candidate.assign(hour=candidate.hour//6, area=candidate.area//15)
            auxiliary = known.assign(hour=known.hour//6, area=known.area//15)
            key = ["hour", "area", "device"]
        else:
            key = ["hour", "area", "device"]
        unique = auxiliary.drop_duplicates(key, keep=False)
        proposed = candidate.merge(unique[key + ([] if key == ["identity"] else ["identity"])],
                                   how="left", on=key, suffixes=("", "_match"))
        if key == ["identity"]:
            prediction = direct
            correct = direct
        else:
            prediction = proposed["identity_match"].notna().to_numpy(dtype=int)
            correct = proposed["identity"].eq(proposed["identity_match"]).to_numpy(dtype=int)
        true_links = int(correct.sum())
        attempted = int(prediction.sum())
        recall = true_links / int(direct.sum())
        false_link_rate = int(((direct == 0) & (prediction == 1)).sum()) / int((1-direct).sum())
        rows.append({
            "protection": variant, "targets": n, "known_targets": int(direct.sum()),
            "attempted_links": attempted, "correct_links": true_links,
            "success_rate": true_links/n, "precision": true_links/attempted if attempted else 0.,
            "recall": recall, "accuracy": (true_links + int(((direct == 0) & (prediction == 0)).sum()))/n,
            "advantage": recall - false_link_rate,
        })
    return rows


def sensitive_inventory(frame, selected=(), *, lanl=False):
    """Report field-level exposure counts, using names and operator selections."""
    structured = {
        "email": "Email address", "email_address": "Email address",
        "phone": "Phone number", "phone_number": "Phone number",
        "ip": "IP address", "ip_address": "IP address",
        "account": "Account", "account_id": "Account", "user_id": "Account", "username": "Account",
        "device_id": "Device", "device": "Device", "computer": "Device", "host": "Device",
    }
    rows = []
    for field in frame.columns:
        name = str(field).strip().casefold().replace(" ", "_")
        if lanl and name in LANL_IDENTIFIERS:
            category = f"De-identified {LANL_IDENTIFIERS[name].split('.')[-1]}"
        else:
            category = structured.get(name)
        if category or field in selected:
            rows.append({"field": field, "sensitivity": category or "Selected by investigator",
                         "populated": int(frame[field].notna().sum()),
                         "distinct": int(frame[field].nunique())})
    return rows
