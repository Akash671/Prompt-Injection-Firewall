"""Train the local classifier on separate training and validation datasets.

Generate the datasets with python tests/generate_training.py, then run
python app/train_ml.py. Benchmark records are used only for evaluation.
"""

import argparse
import base64
from collections import Counter
from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import platform
import re
import shutil
import tempfile
import time
import unicodedata
from urllib.parse import unquote

import joblib
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.pipeline import Pipeline


BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "data" / "training"
BENCHMARK_DIR = BASE_DIR / "tests" / "benchmark"
MODEL_DIR = BASE_DIR / "app" / "models"
RANDOM_SEED = 42
CATEGORIES = {
    "benign", "instruction_override", "role_change", "secret_extraction",
    "credential_theft", "tool_abuse", "context_poisoning",
    "multi_step_jailbreak", "indirect", "encoded",
}


def normalize_text(text):
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def text_keys(sample):
    """Compare plaintext as well as encoded text to detect split leakage."""
    text = sample["text"]
    texts = {text, sample.get("plaintext", text)}
    try:
        if re.fullmatch(r"(?:&#(?:[0-9]+|x[0-9a-fA-F]+);)+", text):
            texts.add(html.unescape(text))
        elif len(text) >= 32 and len(text) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", text):
            texts.add(bytes.fromhex(text).decode("utf-8"))
        elif len(text) >= 16 and len(text) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text):
            texts.add(base64.b64decode(text, validate=True).decode("utf-8"))
        elif re.search(r"%[0-9a-fA-F]{2}", text):
            texts.add(unquote(text, errors="strict"))
    except (ValueError, UnicodeError):
        pass
    return {normalize_text(value) for value in texts}


def load_samples(path, expected_split=None):
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(
            f"Missing dataset: {path}. Run python tests/generate_training.py first."
        )
    samples = []
    seen = set()
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            sample = json.loads(line)
            location = f"{path}:{line_number}"
            if not isinstance(sample, dict):
                raise ValueError(f"{location}: expected a JSON object")
            if not isinstance(sample.get("text"), str) or not sample["text"].strip():
                raise ValueError(f"{location}: text must be a nonempty string")
            if sample.get("label") not in {"benign", "malicious"}:
                raise ValueError(f"{location}: label must be benign or malicious")
            if sample.get("category") not in CATEGORIES:
                raise ValueError(f"{location}: unknown category")
            if (sample["category"] == "benign") != (sample["label"] == "benign"):
                raise ValueError(f"{location}: category and label disagree")
            if "plaintext" in sample and (
                not isinstance(sample["plaintext"], str) or not sample["plaintext"].strip()
            ):
                raise ValueError(f"{location}: plaintext must be a nonempty string")
            if expected_split is not None:
                if sample.get("split") != expected_split:
                    raise ValueError(f"{location}: expected split {expected_split!r}")
                if not isinstance(sample.get("template_id"), str) or not sample["template_id"]:
                    raise ValueError(f"{location}: template_id is required")
                group = sample.get("template_group", sample["template_id"])
                if not isinstance(group, str) or not group:
                    raise ValueError(f"{location}: template_group must be a nonempty string")
            keys = text_keys(sample)
            if keys & seen:
                raise ValueError(f"{location}: duplicate text or decoded payload")
            seen.update(keys)
            samples.append(sample)
    if not samples:
        raise ValueError(f"{path}: dataset is empty")
    return samples


def load_data(dataset_dir=None):
    """Return only the training split; retained for callers of the old API."""
    directory = Path(dataset_dir) if dataset_dir is not None else DATASET_DIR
    samples = load_samples(directory / "train.jsonl", expected_split="train")
    return [sample["text"] for sample in samples], [
        int(sample["label"] == "malicious") for sample in samples
    ]


def validate_splits(training, validation, benchmark):
    for name, samples in (("train", training), ("validation", validation)):
        if {sample["label"] for sample in samples} != {"benign", "malicious"}:
            raise ValueError(f"{name}: both benign and malicious samples are required")
    named = [("train", training), ("validation", validation), ("benchmark", benchmark)]
    key_sets = {
        name: set().union(*(text_keys(sample) for sample in samples))
        for name, samples in named
    }
    for index, (left, _) in enumerate(named):
        for right, _ in named[index + 1:]:
            if key_sets[left] & key_sets[right]:
                raise ValueError(f"Data leakage: {left} and {right} share text or decoded payloads")
    train_groups = {sample.get("template_group", sample["template_id"]) for sample in training}
    validation_groups = {sample.get("template_group", sample["template_id"]) for sample in validation}
    if train_groups & validation_groups:
        raise ValueError("Data leakage: train and validation share template families")
    if {sample["template_id"] for sample in training} & {
        sample["template_id"] for sample in validation
    }:
        raise ValueError("Data leakage: train and validation share template IDs")


def evaluate_model(model, samples):
    labels = [int(sample["label"] == "malicious") for sample in samples]
    predictions = model.predict([sample["text"] for sample in samples])
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    by_category = {}
    for category in sorted({sample["category"] for sample in samples}):
        indices = [index for index, sample in enumerate(samples) if sample["category"] == category]
        correct = sum(int(predictions[index] == labels[index]) for index in indices)
        by_category[category] = {"samples": len(indices), "accuracy": correct / len(indices)}
    return {
        "samples": len(samples),
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision), "recall": float(recall), "f1": float(f1),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "false_positive_rate": float(fp / (tn + fp)) if tn + fp else 0.0,
        "by_category": by_category,
    }


def dataset_summary(samples, path):
    return {
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "samples": len(samples),
        "labels": dict(Counter(sample["label"] for sample in samples)),
        "categories": dict(Counter(sample["category"] for sample in samples)),
        "template_groups": sorted({
            sample.get("template_group", sample["template_id"]) for sample in samples
        }),
    }


def train(dataset_dir=None, model_dir=None):
    directory = Path(dataset_dir) if dataset_dir is not None else DATASET_DIR
    destination = Path(model_dir) if model_dir is not None else MODEL_DIR
    training_path = directory / "train.jsonl"
    validation_path = directory / "validation.jsonl"
    training = load_samples(training_path, expected_split="train")
    validation = load_samples(validation_path, expected_split="validation")
    benchmark_paths = sorted(BENCHMARK_DIR.glob("*.jsonl"))
    benchmark = [
        sample
        for path in benchmark_paths
        for sample in load_samples(path)
    ]
    validate_splits(training, validation, benchmark)

    output = destination / "injection_classifier.joblib"
    previous_metrics = {}
    if output.exists():
        previous = joblib.load(output)
        previous_metrics["validation"] = evaluate_model(previous, validation)
        if benchmark:
            previous_metrics["benchmark"] = evaluate_model(previous, benchmark)

    # Keep the standard sklearn pipeline and binary class ordering used by
    # app.ml_detector; no validation or benchmark examples enter model.fit.
    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True, ngram_range=(1, 2), sublinear_tf=True,
        )),
        ("classifier", LogisticRegression(
            max_iter=1000, class_weight="balanced", random_state=RANDOM_SEED,
        )),
    ])
    started = time.monotonic()
    model.fit(
        [sample["text"] for sample in training],
        [int(sample["label"] == "malicious") for sample in training],
    )
    fit_seconds = time.monotonic() - started
    validation_metrics = evaluate_model(model, validation)
    benchmark_metrics = evaluate_model(model, benchmark) if benchmark else None

    destination.mkdir(parents=True, exist_ok=True)
    backup = None
    if output.exists():
        digest = hashlib.sha256(output.read_bytes()).hexdigest()[:12]
        backup = output.with_name(f"injection_classifier.previous-{digest}.joblib")
        if not backup.exists():
            shutil.copy2(output, backup)

    # Verify serialization before replacing the model used by the application.
    descriptor, temporary_name = tempfile.mkstemp(suffix=".joblib", dir=destination)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        joblib.dump(model, temporary)
        restored = joblib.load(temporary)
        if list(restored.classes_) != [0, 1]:
            raise ValueError("Saved classifier must use class order [0, 1]")
        probe = [sample["text"] for sample in validation[:20]]
        if not (restored.predict_proba(probe) == model.predict_proba(probe)).all():
            raise ValueError("Saved model predictions differ after loading")
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()

    report = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "evaluation_scope": "ML classifier on raw synthetic text; not the combined firewall",
        "limitations": "Template families are separated, but synthetic vocabulary and scenarios remain related.",
        "python_version": platform.python_version(),
        "sklearn_version": sklearn.__version__,
        "random_seed": RANDOM_SEED,
        "fit_seconds": fit_seconds,
        "training": dataset_summary(training, training_path),
        "validation": dataset_summary(validation, validation_path),
        "validation_metrics": validation_metrics,
        "benchmark_metrics": benchmark_metrics,
        "benchmark_files": {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in benchmark_paths
        },
        "previous_model_metrics": previous_metrics,
        "model_path": str(output),
        "model_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "previous_model_backup": str(backup) if backup else None,
    }
    report_path = destination / "training_report.json"
    descriptor, temporary_report_name = tempfile.mkstemp(suffix=".json", dir=destination)
    temporary_report = Path(temporary_report_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
        os.replace(temporary_report, report_path)
    finally:
        if temporary_report.exists():
            temporary_report.unlink()

    print(f"Training samples: {len(training):,} (fit only on train.jsonl)")
    print(f"Fit time: {fit_seconds:.2f}s")
    for name, metrics in (("Validation", validation_metrics), ("Benchmark", benchmark_metrics)):
        if metrics is not None:
            print(
                f"{name} ML-only: {metrics['samples']:,} samples | "
                f"Precision {metrics['precision']:.4f} | Recall {metrics['recall']:.4f} | "
                f"F1 {metrics['f1']:.4f} | TN {metrics['tn']} FP {metrics['fp']} "
                f"FN {metrics['fn']} TP {metrics['tp']}"
            )
    print(f"Model saved: {output}")
    print(f"Training report: {report_path}")
    if backup:
        print(f"Previous model backup: {backup}")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DATASET_DIR)
    parser.add_argument("--model-dir", type=Path, default=MODEL_DIR)
    args = parser.parse_args()
    try:
        train(args.data_dir, args.model_dir)
    except (ValueError, FileNotFoundError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
