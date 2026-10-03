# Agentic Cybersecurity – Prompt Injection Firewall

Hackathon prototype: a security gateway that detects and mitigates prompt injection before untrusted content can influence an AI agent.

## Architecture

```text
                 INPUT
                   ↓
            Parser / OCR
                   ↓
          Normalize + Decode
                   ↓
        Segment + Provenance
                   ↓
       ┌────────────────────┐
       │ Fast detectors      │
       │ Rules               │
       │ Tool detector       │
       │ ML                  │
       │ Semantic            │
       │ Context/Jailbreak   │
       └─────────┬──────────┘
                 ↓
             Risk Engine
                 │
        ┌────────┴────────┐
        │                 │
    LOW RISK          AMBIGUOUS /
        │             HIGH RISK
        │                 ↓
       PASS          LLM Security
                         Analyst
                              ↓
                     Structured verdict
                              ↓
                       Final Policy
                              ↓
                PASS / SANITIZE / BLOCK
```

The policy engine remains authoritative. LLM recommendations are advisory only.

## Threats covered

Instruction override, role change, secret extraction, credential theft, tool abuse, context poisoning, multi-step jailbreaks, indirect prompt injection and encoded instructions.

## Content sources

Text, HTML, PDF, DOCX and image/OCR content are supported. Source/trust metadata is preserved through the pipeline.

## Technology

Python 3.9, scikit-learn, TF-IDF + Logistic Regression, SentenceTransformers, Cohere, BeautifulSoup, pypdf, python-docx, Tesseract/pytesseract, Streamlit, pytest, GitHub Actions and Docker.

## Current benchmark

Curated seed benchmark: 43 samples, Precision 1.00, Recall 1.00, F1 1.00.

Unseen benchmark: 90 samples, Precision 0.976, Recall 1.00, F1 0.988.

These are small curated engineering benchmarks, not production-scale statistical validation.

## Run

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
streamlit run app.py
```

Optional Cohere escalation:

```bash
# PowerShell
$env:COHERE_API_KEY="YOUR_KEY"

# Linux/macOS
export COHERE_API_KEY="YOUR_KEY"
```

Tests:

```bash
python run_tests.py
```

## CI/CD

GitHub Actions performs dependency installation, Python compilation and the project test suite. Production deployment can extend this pipeline with security/dependency scanning, Docker build, registry push, staging smoke tests and controlled production deployment.

## Future roadmap

1. Fine-tuned DeBERTa/DistilBERT classifier.
2. FAISS/Chroma semantic attack memory.
3. Human-validated feedback and controlled retraining.
4. Model registry, drift monitoring, SIEM/SOC integration and enterprise policy management.

