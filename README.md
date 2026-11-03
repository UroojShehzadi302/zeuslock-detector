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

### 4. Check it works

From the project folder, with the virtual env active and Ollama running:

```python
from submission import detect

detect("Can you check why my Visa 4838 5608 9441 5465 keeps getting declined?")
# {"decision": "alert",
#  "findings": [{"category": "PAYMENT", "start": 26, "end": 45, "value": "4838 5608 9441 5465"}]}
```

## Results (Level 1)

Measured on the 50 prompts of `data/dev_set.jsonl`, laptop CPU, model `qwen2.5:3b`:

| | Regex only | Regex + LLM |
|---|---|---|
| **Accuracy** (alert / allow) | 82 % (41/50) | **94 % (47/50)** |
| Misses | 8 | **2** |
| False alarms | 1 | 1 |
| Speed per prompt (mean) | ~1 ms | ~5.5 s |

- The LLM layer fixed **6 misses** that regex cannot see (a password inside a sentence, postal
  addresses, proprietary code) and added **no false alarms**.
- The **4 remaining differences** are deliberate disagreements with the labels, each explained in
  the report: an SSN labelled as contact info (dev-026), a public IP `1.1.1.1` (dev-031),
  a card number that fails the Luhn check (dev-037), a real email in a prompt labelled clean (dev-048).
- **Detection over speed:** the model checks every prompt. Calling it only when a keyword like
  "password" appears was 5× faster but could miss a password written without that word, so it was rejected.

Full reports: [`results/level1-regex-only.txt`](results/level1-regex-only.txt),
[`results/level1-regex-llm.txt`](results/level1-regex-llm.txt).

## Quick try (step by step)

Open a terminal in the project folder. The prompt must start with `(.venv)`; if not, activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

| # | Command | What you should see |
|---|---|---|
| 1 | `python main.py --help` | the list of commands |
| 2 | `python main.py level1 detect "My Visa 4838 5608 9441 5465 and my password is my dog's name, Biscuit2019"` | `"decision": "alert"`, the card as `PAYMENT`, `Biscuit2019` as `CREDENTIAL` (~5–10 s) |
| 3 | `python main.py level1 eval --regex-only` | accuracy **82 % (41/50)**, instant |
| 4 | `python main.py level1 eval` | accuracy **94 % (47/50)**, ~5 min |
| 5 | `python main.py all` | both reports, ~5 min |
| 6 | `python main.py level2 chat "Mail sarah@corp.com, card 4838 5608 9441 5465"` | `sent to AI : Mail [EMAIL_1], card [CARD_1]`, then the AI reply with the real values put back |
| 7 | `python -m pytest -q tests` | `75 passed` |

To test your own sentence, change the text inside the quotes in step 2.

## How to run

All commands from the project folder, with the virtual env active.
Commands marked 🔜 are planned and not available yet (see [Progress](#progress)).

```powershell
python main.py --help           # list all commands
python main.py level1 --help    # list Level 1 commands
```

### Level 1: detect

```powershell
# One prompt (needs Ollama running; without it only the regex layer runs, with a warning)
python main.py level1 detect "My card is 4838 5608 9441 5465"

# Both layers in one prompt: the card is found by regex, the password by the LLM
python main.py level1 detect "My Visa 4838 5608 9441 5465 and my password is my dog's name, Biscuit2019"
# {
#   "decision": "alert",
#   "findings": [
#     {"category": "PAYMENT", "start": 8, "end": 27, "value": "4838 5608 9441 5465"},
#     {"category": "CREDENTIAL", "start": 62, "end": 73, "value": "Biscuit2019"}
#   ]
# }

# Same thing straight from Python, the way the graders call it
python -c "from submission import detect; print(detect('My Visa 4838 5608 9441 5465 and my password is my dog''s name, Biscuit2019'))"
```

### Level 1: evaluation on the dev set

```powershell
python main.py level1 eval --regex-only   # regex layer alone, instant
python main.py level1 eval                # regex + LLM, ~5 min (needs Ollama)

# Save the reports
python main.py level1 eval --regex-only | Out-File -Encoding utf8 results\level1-regex-only.txt
python main.py level1 eval | Out-File -Encoding utf8 results\level1-regex-llm.txt
```
(`python -m zeuslock.level1.evaluate [--regex-only]` does the same.)

The report shows: accuracy, misses, false alarms, precision / recall per category,
values found (exact / overlap / missed), speed (mean, p50, p95, max) and every prompt that
differs from its label, with the reason.

### Level 2: anonymize → AI → restore (`Session`)

The AI never sees the sensitive values: they are replaced by placeholders before sending,
and put back in the AI's reply.

```powershell
# Interactive chat (empty line to quit). The "AI" is the local model, so it runs offline.
python main.py level2 chat
#   you        : my email is sarah@corp.com and my card 4838 5608 9441 5465
#   sent to AI : my email is [EMAIL_1] and my card [CARD_1]
#   AI wrote   : ...  (the AI only ever sees the placeholders)
#   you see    : ...  (the real values put back)

# Scripted chat: each quoted message is one turn
python main.py level2 chat "Please email sarah.okonkwo@brightwell-partners.co.uk: her card 4838 5608 9441 5465 was charged twice." "Also tell sarah.okonkwo@brightwell-partners.co.uk the refund takes 5 days."
#   sent to AI : Please email [EMAIL_1]: her card [CARD_1] was charged twice.
#   AI wrote   : ... the charge on her card [CARD_1] ...
#   you see    : ... the charge on her card 4838 5608 9441 5465 ...
```

From Python, the way the graders call it:

```python
from submission import Session

session = Session()
session.anonymize("Mail sarah@corp.com, card 4838 5608 9441 5465")
# 'Mail [EMAIL_1], card [CARD_1]'
session.restore("Done, I wrote to **email_1** about CARD_1.")
# 'Done, I wrote to **sarah@corp.com** about 4838 5608 9441 5465.'
```

- Same value → same placeholder in every message of the session; numbering continues.
- `restore()` survives what AIs do to placeholders: dropped brackets (`EMAIL_1`), other case
  (`[email_1]`), spaces (`[ EMAIL 1 ]`), other brackets (`{EMAIL_1}`, `<EMAIL_1>`), markdown
  (`**[EMAIL_1]**`), possessives (`[EMAIL_1]'s`). `EMAIL_10` is never read as `EMAIL_1`,
  and unknown placeholders are left as they are.

### Level 2: still to come (🔜 steps 9–10)

These print "not built yet" for now.

```powershell
python main.py level2 detect         # detection with anti-obfuscation
python main.py level2 attacks        # adversarial prompts: Level 1 vs Level 2 caught
python main.py level2 bench          # speed before / after
```

### Both levels together

```powershell
python main.py all    # Level 1 regex-only + full report (~5 min), then the Level 2 chat demo
```

### Tests

```powershell
python -m pytest -q tests                          # everything (75 tests)
python -m pytest -q tests/test_validators.py       # one file
python -m pytest -q tests -k "not test_real"       # skip the 3 tests that call the real model
```

| File | Tests |
|---|---|
| `test_validators.py` | Luhn, IBAN, NIR, SSN, private IP |
| `test_patterns.py` | regex layer, one test per category + "not sensitive" cases |
| `test_llm.py` | LLM layer with a fake model + 2 tests with the real model |
| `test_detector.py` | merge rules + `detect()` |
| `test_evaluate.py` | evaluation metrics |
| `test_main.py` | command line (`main.py`) |
| `test_session.py` | Level 2 `Session`: placeholders, multi-message conversation, every mangling style, chat turn |

```powershell
python -m pytest -q tests/test_session.py          # Level 2 only
python -m pytest -q tests --ignore=tests/test_session.py   # Level 1 only
```

- Tests that need the real model are **skipped automatically** when Ollama is not running.
- 🔜 Attack tests come with step 9.

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
| 5 | `detect()` + merge + `submission.py` (+ tests) | ✅ Done |
| 6 | Level 1 evaluation: misses, false alarms, speed | ✅ Done |
| 7 | CLI `main.py` (level1 / level2 commands) (+ tests) | ✅ Done |
| 8 | Level 2: `Session` anonymize / restore + chat demo (+ tests) | ✅ Done |
| 9 | Level 2: attack prompts + hardening | ⏳ Next |
| 10 | Level 2: speed optimisation with numbers | ⬜ |
| 11 | `REPORT.md` | ⬜ |
