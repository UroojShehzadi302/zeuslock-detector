# ZeusLock Detector

A local detector for sensitive data in AI prompts. It finds card numbers, API keys, contact
details, government IDs, private IP addresses and proprietary code **before** a prompt leaves the
machine. Everything runs locally: a small open-weights model (≤ 4B parameters) served by Ollama,
plus regex rules and validators. No cloud APIs.

> **Status:** work in progress (see [Progress](#progress) below).

## Categories

| Category | Examples |
|---|---|
| `PAYMENT` | card numbers, IBANs, crypto wallet addresses |
| `CREDENTIAL` | API keys, tokens, passwords, private keys, connection strings with credentials |
| `CONTACT` | email addresses, phone numbers, postal addresses |
| `GOV_ID` | US SSN, French NIR, passport numbers |
| `NETWORK` | private / internal IP addresses |
| `SOURCE_CODE` | proprietary code (business logic, internal names) |

## Requirements

- Python 3.11+
- [Ollama](https://ollama.com/download)
- ~2 GB free disk space for the model
- A normal laptop CPU (no GPU needed)

## Setup on a fresh machine

### 1. Install

```bash
git clone https://github.com/UroojShehzadi302/zeuslock-detector.git
cd zeuslock-detector

python -m venv .venv
# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Download the model

```bash
ollama pull qwen2.5:3b
```

### 3. Start the model

```bash
ollama serve
```
(On Windows and macOS the Ollama app usually starts the server automatically.)

### 4. Run

*Coming soon: this section will be filled in as the code is written.*

```python
from submission import detect

detect("Can you check why my Visa 4838 5608 9441 5465 keeps getting declined?")
# {"decision": "alert",
#  "findings": [{"category": "PAYMENT", "start": 26, "end": 45, "value": "4838 5608 9441 5465"}]}
```

## Project structure

```
zeuslock-detector/
├── submission.py          # entry point imported by the graders (detect, Session)
├── main.py                # CLI: level1 / level2 commands
├── requirements.txt
├── data/dev_set.jsonl     # 50 example prompts
├── attacks/               # adversarial prompts (Level 2)
├── tests/
└── zeuslock/
    ├── core/              # shared: regex patterns, validators, LLM client, merge
    ├── level1/            # evaluation on the dev set
    └── level2/            # anonymisation, attacks, speed benchmarks
```

## Progress

| Step | Work | Status |
|---|---|---|
| 1 | Project setup: folders, virtual env, requirements, dev set | ✅ Done |
| 2 | Validators: Luhn, IBAN mod-97, NIR key, SSN rules, private IP (+ tests) | ✅ Done |
| 3 | Regex layer for all structured categories (+ tests) | ✅ Done |
| 4 | LLM layer (Ollama) for passwords in prose, addresses, code (+ tests) | ✅ Done |
| 5 | `detect()` + merge + `submission.py` | ⏳ Next |
| 6 | Level 1 evaluation: misses, false alarms, speed | ⬜ |
| 7 | CLI `main.py` (level1 / level2 commands) | ⬜ |
| 8 | Level 2: `Session` anonymize / restore | ⬜ |
| 9 | Level 2: attack prompts + hardening | ⬜ |
| 10 | Level 2: speed optimisation with numbers | ⬜ |
| 11 | `REPORT.md` | ⬜ |
