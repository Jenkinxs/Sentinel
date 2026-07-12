import argparse
import configparser
import datetime
import os
import sys
import time
from pathlib import Path

import requests
from openai import OpenAI

import Deployer
import Verifier


## Paths
BASE_DIR = Path(__file__).resolve().parents[1]


## ── Config loading (config.ini + .env override) ──────────────────────────────

def load_config():
    """Load config.ini, then overlay .env values."""
    config = configparser.ConfigParser()
    config.read(BASE_DIR / "config.ini")

    ## Try .env override
    env_path = BASE_DIR / ".env"
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                os.environ[key] = val

    return config


CONFIG = load_config()

MODEL_URL = (CONFIG.get("ROUTER", "url", fallback="https://openrouter.ai/api/v1")).strip('"')
GENERATOR = (CONFIG.get("ROUTER", "generator", fallback="openai/gpt-oss-120b:free")).strip('"')
REVIEWER = (CONFIG.get("ROUTER", "reviewer", fallback="openai/gpt-oss-120b:free")).strip('"')
API_KEY = os.environ.get("SENTINEL_API_KEY") or (CONFIG.get("API", "api_key", fallback="")).strip('"')
YARAC_RETRIES = int(CONFIG.get("LLM", "yarac_retries", fallback="10"))
FEEDBACK_LOOPS = int(CONFIG.get("LLM", "feedback_loops", fallback="3"))
STREAM = CONFIG.getboolean("LLM", "stream", fallback=True)

with open(BASE_DIR / "SentinelGen", encoding="utf-8") as f:
    GENERATOR_PROMPT = f.read()
with open(BASE_DIR / "SentinelRvw", encoding="utf-8") as f:
    REVIEWER_PROMPT = f.read()


## ── Core pipeline ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Sentinel — AI-powered YARA rule generation pipeline"
    )
    parser.add_argument(
        "--cli", action="store_true",
        help="Run in non-interactive CLI mode (requires --description)"
    )
    parser.add_argument(
        "-d", "--description", type=str, default=None,
        help="Natural language description of the threat to detect"
    )
    parser.add_argument(
        "--scan-dir", type=str, default=None,
        help="Directory to scan with the generated rule"
    )
    parser.add_argument(
        "--no-deploy", action="store_true",
        help="Skip the deploy/scan step in non-interactive mode"
    )
    args = parser.parse_args()

    if args.cli:
        if not args.description:
            print("[ERROR] --description is required in --cli mode")
            sys.exit(1)
        _run_pipeline(args.description, args.scan_dir, args.no_deploy, logger=None)
    else:
        _interactive_cli()


def _interactive_cli():
    """Original interactive CLI mode."""
    print("Welcome to SENTINEL.\n")
    prompt = input("Enter a description of what you want to identify. ")

    try:
        yara_rule, review = _run_pipeline(
            prompt, scan_dir=None, no_deploy=False, logger=None
        )
        if yara_rule:
            deploy(yara_rule)
    except Exception as e:
        print(f"\n\nAn error has occurred at main:\t{e}")


def _run_pipeline(description, scan_dir=None, no_deploy=False, logger=None):
    """Run the full generate-verify-review-feedback pipeline.

    Returns (final_rule, review_text) on success, (None, None) on failure.
    """
    def log(msg, **kwargs):
        if logger:
            logger(msg)
        else:
            print(msg, **kwargs)

    log("Creating rules...")
    yara_rule = call_model(description, "GENERATOR", False, logger=logger)

    log("Verifying syntax...")
    verified, corrected_rule = syntax_verification(yara_rule, logger=logger)

    if not verified:
        log(f"[ERROR] Initial syntax verification failed after {YARAC_RETRIES} retries.")
        return None, None

    log("Reviewing Rules...")
    review = call_model(corrected_rule, "REVIEWER", False, logger=logger)

    final_rule = feedback(description, corrected_rule, review, logger=logger)
    final_verified, corrected_final = syntax_verification(final_rule, logger=logger)

    if not final_verified:
        log(f"[ERROR] Final syntax verification failed after {YARAC_RETRIES} retries.")
        return None, None

    log("\n\n")
    log("=" * 93)
    log("Here's the finalized rule, along with the Reviewer's analysis.")
    time.sleep(2)

    log("\n" + corrected_final + "\n")
    time.sleep(2)
    log("\n" + review + "\n")

    if no_deploy:
        return corrected_final, review

    return corrected_final, review


def call_model(prompt, response_type, is_fix_attempt=False, logger=None):
    """Call an LLM via the OpenAI-compatible API.

    response_type: "GENERATOR" or "REVIEWER"
    is_fix_attempt: True when we're asking the generator to fix a broken rule
    """
    def log(msg, **kwargs):
        if logger:
            logger(msg)
        else:
            print(msg, **kwargs)

    if is_fix_attempt:
        log("Conversing with Model...")
    else:
        log("Calling Model...")

    if response_type == "GENERATOR":
        sys_prompt = GENERATOR_PROMPT
    else:
        sys_prompt = REVIEWER_PROMPT

    model_id = GENERATOR if response_type == "GENERATOR" else REVIEWER

    client = OpenAI(base_url=MODEL_URL, api_key=API_KEY)

    try:
        response = client.chat.completions.create(
            model=model_id,
            messages=[
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": prompt},
            ],
            stream=STREAM,
            timeout=60,
        )
    except Exception as e:
        log(f"\nError calling {response_type}: {e}")
        raise

    if STREAM:
        full_content = ""

        try:
            if logger is None:
                log("\n")
            for chunk in response:
                if chunk.choices and chunk.choices[0].delta.content is not None:
                    content = chunk.choices[0].delta.content
                    full_content += content
                    if logger is None:
                        log(content, end="", flush=True)

            if logger is None:
                log("\n")
            else:
                log("\n" + full_content + "\n", end="", flush=True)

        except Exception as e:
            log(f"\nError during streaming: {e}")
            raise

        return full_content

    return str(response.choices[0].message.content)


def syntax_verification(rule, logger=None):
    """Verify YARA syntax, retrying with LLM fixes on failure."""
    def log(msg):
        if logger:
            logger(msg)
        else:
            print(msg)

    verified, result = Verifier.verify(rule)
    if verified:
        return True, rule

    for attempt in range(YARAC_RETRIES):
        log(f"Retry #{attempt + 1}")

        prompt = (
            "The following YARA ruleset contains errors identified by the YARA compiler. "
            "Look at the error information and alter the rule accordingly.\n"
            f"COMPILER OUTPUT:\n{result}.\nRULES THAT WERE TESTED:\n{rule}"
        )

        log("\nFixing Syntax...")
        fixed_rule = call_model(prompt, "GENERATOR", True, logger=log)

        verified, result = Verifier.verify(fixed_rule)
        if verified:
            return True, fixed_rule

    return False, None


def deploy(yara_rule):
    """Save the rule and optionally scan a directory."""
    rules_dir = BASE_DIR / "rules"
    rules_dir.mkdir(exist_ok=True)

    accepted = input("\nDeploy? Y/N ").strip().upper()
    if accepted == "N":
        print("Rule rejected. Aborting deployment.")
        return

    rule_name = f"Sentinel_Rule-{datetime.datetime.now():%Y%m%d_%H%M%S}.yar"
    rule_path = rules_dir / rule_name
    rule_path.write_text(yara_rule, encoding="utf-8")
    print("Rule file written.")

    scan_directory = input(
        f"Paste a directory to scan. The current directory is {BASE_DIR}.\n"
    )
    results = Deployer.scan(rule_name, scan_directory)
    print("\nHere are the results:\n")
    print(results)


def feedback(orig_prompt, rule, analysis, logger=None):
    """Iterative generator-reviewer feedback loop to refine the rule."""
    current_rule = rule
    current_analysis = analysis

    for loop in range(FEEDBACK_LOOPS):
        feedback_prompt = (
            "Here is a reviewer's analysis of this YARA rule. Take into consideration "
            "the following:\n"
            f"1) THE RULE\n{current_rule}\n"
            f"2) THE ANALYSIS:\n{current_analysis}\n"
            f"3) THE ORIGINAL PROMPT FOR THIS RULE:\n{orig_prompt}\n\n"
            "Rewrite the rule to better fit the original prompt and address the "
            "reviewer's analysis."
        )

        new_rule = call_model(feedback_prompt, "GENERATOR", True, logger=logger)

        ## Verify syntax after each iteration — fix if broken
        verified, fixed = syntax_verification(new_rule, logger=logger)
        if verified:
            current_rule = fixed
        else:
            current_rule = new_rule

        current_analysis = call_model(current_rule, "REVIEWER", False, logger=logger)

    return current_rule


if __name__ == "__main__":
    main()
