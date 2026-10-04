# Agentic Cybersecurity – Prompt Injection Firewall

Hackathon prototype: a security gateway that detects and mitigates prompt injection before untrusted content can influence an AI agent.

## Architecture

```text
                 INPUT
 (text,code,web,html,pdf,docs,image etc.)
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

```
1. Instruction override
2. role change
3. secret extraction
4. credential theft
5. tool abuse
6. context poisoning
7. multi-step jailbreaks
8. indirect prompt injection
9. encoded instructions.
```

## Input Content sources

```
1. User messages
2. Web pages
3. PDFs
4. Emails
5. Markdown
6. HTML
7. Word documents
8. API responses
9. OCR text
10. Source code
11. Images (via OCR) 
```

## Technology Used

```
Python 3.9
scikit-learn
TF-IDF + Logistic Regression
SentenceTransformers
LLMs(Cohere)
BeautifulSoup
pypdf
python-docx
Tesseract/pytesseract
Streamlit
pytest
GitHub Actions.
OpenAI Codex,Antropic Claude for writing code 
```


## Current Banchmark Score

```
Samples    : 10000
TP         : 8921
TN         : 771
FP         : 229
FN         : 79
Precision  : 0.975
Recall     : 0.991
F1         : 0.983
```

These are small curated engineering benchmarks, not production-scale statistical validation.

## How to Run

```bash

# first download and install Tesseract-OCR then follow below steps

$ python -m venv .venv
# Windows:
$ .venv\Scripts\activate
# Linux/macOS:
$ source .venv/bin/activate

$ git clone https://github.com/Akash671/Prompt-Injection-Firewall.git
# go to directory
$ cd Prompt-Injection-Firewall

$ pip install -r requirements.txt

# set cohere llm api key here
$ export COHERE_API_KEY="YOUR_KEY"

$ streamlit run app.py
```

Optional Cohere escalation:

```bash
# PowerShell
$env:COHERE_API_KEY="YOUR_KEY"

# Linux/macOS
$ export COHERE_API_KEY="YOUR_KEY"
```

Tests:

```bash
$ python -m tests.evaluate_benchmark
$ python run_tests.py
```

## CI/CD

GitHub Actions performs dependency installation, Python compilation and the project test suite. Production deployment can extend this pipeline with security/dependency scanning, Docker build, registry push, staging smoke tests and controlled production deployment.

## Future roadmap

1. Fine-tuned DeBERTa/DistilBERT classifier.
2. FAISS/Chroma semantic attack memory.
3. Human-validated feedback and controlled retraining.
4. Model registry, drift monitoring, SIEM/SOC integration and enterprise policy management.


```text
                   ┌──────────────┐
                   │   API / SDK  │
                   └──────┬───────┘
                          │
                    INPUT FIREWALL
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
     Parser          Provenance         Normalizer
        │                 │                 │
        └─────────────────┼─────────────────┘
                          ▼
                     Segmentation
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
           Rules  Transformer,ML+DL Semantic
             │            │            │
             │            │          FAISS
             └────────────┼────────────┘
                          ▼
                    Ensemble Engine
                          │
                    Risk / Policy
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
           PASS        SANITIZE      BLOCK
                          │
                    if ambiguous
                          ▼
                         LLMs
                          │
                          ▼
                    Final Policy
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
        Tool Guard    Memory Guard  Output Guard
                          │
                          ▼
                         AGENT
```