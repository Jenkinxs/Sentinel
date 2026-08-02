# Sentinel

Describe a threat in plain language. Sentinel generates a YARA rule from that
description. It checks the syntax, reviews the rule against your intent, and
refines it through a generator-reviewer feedback loop. You can then scan a
directory for matches.

## Quick Start

```bash
git clone https://github.com/Jenkinxs/Sentinel.git
cd Sentinel
pip install -r requirements.txt
cp .env.example .env
# Edit .env -- add your OpenRouter API key
```

The project has no system dependencies. YARA compilation uses `yara_x` (pure
Python).

## Usage

### CLI (interactive)

```bash
python backend/LanguageProcessor.py
```

### CLI (non-interactive)

```bash
python backend/LanguageProcessor.py --cli \
    -d "Detect Cobalt Strike beacon with named pipe and registry artifacts" \
    --scan-dir /tmp/samples \
    --no-deploy
```

### Web UI

```bash
python frontend/app.py --port 8081
```

Open http://localhost:8081. Describe the threat. Optionally add a context file
and set a scan directory. Click **RUN**.

## How It Works

```
Describe threat -> Generator LLM writes YARA rule
                 -> yara_x verifies syntax (auto-fixes up to N retries)
                 -> Reviewer LLM checks semantic match against your intent
                 -> Generator + Reviewer converse (N feedback loops) to refine
                 -> Save to rules/ -> optionally scan directory
```

Two independent LLMs (generator and reviewer) run a feedback loop. The
generator writes rules. The reviewer critiques them. The loop produces more
precise rules over time.

## Configuration

| Method | File | Priority |
|---|---|---|
| Environment | `.env` (gitignored) | Highest -- overrides everything |
| Config file | `config.ini` (gitignored) | Fallback defaults |
| Example config | `config.ini.example` | Template with annotations |

Key settings in `config.ini` / `.env`:

| Setting | Default | Description |
|---|---|---|
| `SENTINEL_API_KEY` | -- | OpenRouter (or OpenAI-compatible) API key |
| `generator` | `openai/gpt-oss-120b:free` | Model for rule generation |
| `reviewer` | `openai/gpt-oss-120b:free` | Model for rule review |
| `yarac_retries` | 10 | Max LLM fix attempts on syntax errors |
| `feedback_loops` | 3 | Generator-reviewer refinement iterations |
| `stream` | True | Stream LLM output token-by-token |

### Local models (Ollama)

Modelfiles for local inference live in `modelfiles/`:

| Role | Model | File |
|---|---|---|
| Generator | Qwen3:8b | `modelfiles/Modelfile.SentinelGen` |
| Reviewer | Gemma3:4b | `modelfiles/Modelfile.SentinelRvw` |

Set `url` in config to your Ollama endpoint. Point `generator` and `reviewer`
to your local model names.

## Project Layout

```
Sentinel/
  backend/
    LanguageProcessor.py   Pipeline: generate -> verify -> review -> feedback -> deploy
    Deployer.py            File scanner using compiled YARA rules
    Verifier.py            YARA syntax validation via yara_x
  frontend/
    app.py                 NiceGUI web interface (dark theme, live logs)
  modelfiles/              Ollama Modelfiles for local inference
  rules/                   Generated YARA rules
  config.ini               Runtime configuration (gitignored)
  config.ini.example       Annotated config template
  .env                     Environment overrides (gitignored)
  .env.example             Env template
  SentinelGen              System prompt for the generator LLM
  SentinelRvw              System prompt for the reviewer LLM
```
