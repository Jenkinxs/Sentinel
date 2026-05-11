import configparser
import datetime
import json
import os
import sys
import time
from pathlib import Path
import Deployer
import requests
import Verifier
from openai import OpenAI






# Resolve two levels up from this file
BASE_DIR = Path(__file__).resolve().parents[1]
CONFIG = configparser.ConfigParser()
CONFIG.read(BASE_DIR / "config.ini")



MODEL_URL = (CONFIG["ROUTER"]["url"]).strip('"')
GENERATOR = (CONFIG["ROUTER"]["generator"]).strip('"')
GENERATOR = (CONFIG["ROUTER"]["reviewer"]).strip('"')
API_KEY = (CONFIG["API"]["api_key"]).strip('"')

RETRIES = 40
STREAM = True


with open(BASE_DIR / "SentinelGen", "r", encoding="utf-8") as f:
    GENERATOR_PROMPT = f.read()
with open(BASE_DIR / "SentinelRvw", "r", encoding="utf-8") as f:
    REVIEWER_PROMPT = f.read()


def main():

    print("Welcome to SENTINEL.\n")
    prompt = input("Enter a description of what you want to identify. ")

    try:
        print("Creating rules...")
        yaraRule = call_model(prompt, "LLM1", False, logger=None)
        print("Verifying syntax...")
        verified, correctedRule = syntax_verification(yaraRule, logger=None)

        if verified == True:
            print("Reviewing Rules...")
            ruleReview = call_model(correctedRule, "LLM2", False, logger=None)

            print("\n\n")
            print(
                "============================================================================================================================="
            )
            print(
                "Here's the finalized rule, along with the Reviewer's analysis. Double check this is what you intended for before deployment.\n"
            )
            time.sleep(5)

            print(correctedRule)
            print("\n")
            time.sleep(3)

            print(ruleReview)
            deploy(correctedRule, ruleReview, prompt)

        else:
            print(
                f"Initial YARAC verification failed after {RETRIES} retries. Not proceeding."
            )

    except Exception as e:
        print(f"\n\nAn error has occurred at main:\t{e}")


def call_model(prompt, responseType, yarac, logger=None):

    def log(msg, **kwargs):
        if logger:
            logger(msg)
        else:
            print(msg, **kwargs)

    if yarac:
        log("Conversing with Model...")
    else:
        log("Calling Model...")

    if responseType == "LLM1":
        sysPrompt = GENERATOR_PROMPT
    else:
        sysPrompt = REVIEWER_PROMPT

    userPrompt = prompt

    client = OpenAI(
        base_url=MODEL_URL,
        api_key=API_KEY,
    )

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": sysPrompt},
                {"role": "user", "content": userPrompt},
            ],
            stream=STREAM,
            timeout=60,
        )

    except Exception as e:
        log(f"\nError calling model: {e}")
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
                log("\n")  # final newline for terminal
            else:
                # For frontend, log the entire string with surrounding newlines
                log("\n" + full_content + "\n", end="", flush=True)

        except Exception as e:
            log(f"\nError during streaming: {e}")
            raise
        return full_content

    else:
        return str(response.choices[0].message.content)


def syntax_verification(rule, logger=None):

    def log(msg):
        if logger:
            logger(msg)
        else:
            print(msg)

    # First attempt with the original rule
    verified, result = Verifier.yarac(rule)
    if verified == 0:
        return True, rule

    # Otherwise, iteratively ask the LLM to fix the rule and re‑verify
    for attempt in range(RETRIES):
        log(f"Retry #{attempt + 1}")

        prompt = (
            "The following YARA ruleset contains errors identified by the YARA compiler, YARAC. "
            "Look at information provided by YARAC, and alter the rule accordingly.\n"
            f"YARAC OUTPUT:\n{result}.\nRULES THAT YARAC TESTED:\n {rule}"
        )

        log("\nFixing Syntax...")
        fixed_rule = call_model(prompt, "LLM1", True, logger=log)

        
        verified, result = Verifier.yarac(fixed_rule)
        if verified == 0:
            return True, fixed_rule

    # Exhausted retries
    return False, None


def deploy(yaraRule, analysis, origPrompt):
    # redeployPrompt = (f"Here is a reviewer's analysis of this YARA rule, take into consideration the following:\n1) THE RULE\n{yaraRule}\n2)THE ANALYSIS:\n{analysis}\n3)THE ORIGINAL PROMPT FOR THIS RULE:\n{origPrompt}")

    RULES_DIR = BASE_DIR / "rules"
    RULES_DIR.mkdir(exist_ok=True)

    accepted = input("\nDeploy? Y/N ").strip().upper()
    if accepted == "N":
        print("Rule rejected. Aborting deployment.")
        return

    # while accepted == "Q":
    #     repromptedRule = call_model(redeployPrompt, "LLM1", True)
    #     reviewed_repromptedRule = call_model(repromptedRule, "LLM2", False)
    #     print(reviewed_repromptedRule)
    #     deploy(repromptedRule)

    rule_name = f"Sentinel_Rule-{datetime.datetime.now():%Y%m%d_%H%M%S}.yar"
    rule_path = RULES_DIR / rule_name
    rule_path.write_text(yaraRule, encoding="utf-8")
    print("Rule file written.")

    scan_directory = input(
        f"Paste a directory to scan. The current directory is {BASE_DIR}.\n"
    )
    results = Deployer.scan(rule_name, scan_directory)
    print("\nHere are the results:\n")
    print(results)




if __name__ == "__main__":
    main()
