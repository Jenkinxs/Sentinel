import requests
import os
#from backend import Verifier 
#from backend import Deployer

import Verifier, Deployer

import time
import datetime
import json
from openai import OpenAI
import configparser


config = configparser.ConfigParser()
config.read("config.ini")

MODEL_URL = "https://openrouter.ai/api/v1"
API_KEY = (config["API"]["api_key"]).strip('"')
with open("SentinelGen", "r") as f: LLM1_PROMPT = f.read()
with open("SentinelRvw", "r") as f: LLM2_PROMPT = f.read()

RETRIES = 40

STREAM = True


def main():
    
    print("Welcome to SENTINEL.\n")

        
    prompt = input("Enter a description of what you want to identify. ")

    try:
        print("Creating rules...")
        yaraRule = call_model(prompt, "LLM1", False)

        
        print("Verifying syntax...")
        verified, correctedRule = syntax_verification(yaraRule)


        if verified == True:
            print("Reviewing Rules...")
            ruleReview = call_model(correctedRule, "LLM2", False)
            
            print("\n\n")
            print("=============================================================================================================================")
            print("Here's the finalized rule, along with the Reviewer's analysis. Double check this is what you intended for before deployment.\n")
            time.sleep(5)


            print(correctedRule)
            print("\n")
            time.sleep(3)

            print(ruleReview)

            deploy(correctedRule)

        else:
            print(f"Initial YARAC verification failed after {RETRIES} retries. Not proceeding.")


    except Exception as e:
        print(f"\n\nAn error has occurred at main:\t{e}")



def call_model(prompt, responseType, yarac):


    if yarac == True:
        print("Conversing with Model...")

    else:
        print("Calling Model...")

    if responseType == "LLM1":
        sysPrompt = LLM1_PROMPT

    else:
        sysPrompt = LLM2_PROMPT



    userPrompt = prompt
    
    client = OpenAI(
        base_url=MODEL_URL,
        api_key=API_KEY,
        )
    
    response = client.chat.completions.create(
        model="openai/gpt-oss-120b:free",
        messages=[
            {"role": "system", "content": sysPrompt },
            {"role": "user", "content": userPrompt}
        ],
        stream = STREAM
        
    )
    

    if STREAM:
        full_content = ""
        print("\n")
        for chunk in response:
            if chunk.choices[0].delta.content is not None:
                print(chunk.choices[0].delta.content, end="")
                full_content += chunk.choices[0].delta.content

        print("\n")

        
        return full_content
    
    else:
        return response.choices[0].message.content


def syntax_verification(rule):

    verified, result = Verifier.yarac(rule) # verified is a returncode
    if verified == 0:
        return True, rule
    
    else:

        for fail in range(RETRIES):
            print(f"Retry #{fail + 1}")
            verified, result   = Verifier.yarac(rule)

            if verified == 0:
                return True, rule
                
            
            else:

                prompt = f"The following YARA ruleset contains errors identified by the YARA compiler, YARAC. Look at information provided by YARAC, and alter the rule accordingly.\n " \
                        f"YARAC OUTPUT:\n{result}.\nRULES THAT YARAC TESTED:\n {rule}"
                
                print("\nFixing Syntax...")
                

                rule = call_model(prompt, "LLM1", True)

        return False, None



def deploy(yaraRule):
    accepted = (input("\nDeploy? Y/N ")).upper()


    if accepted == "Y":

        ruleName = "Sentinel_Rule-{datetime.datetime.now():%Y%m%d_%H%M%S}.yar"

        with open(f"/rules/{ruleName}", "w") as file:
            file.write(yaraRule)
        
        print("Rule file written.")
        scanDirectory = input("Paste a directory to scan.\n")

        results = Deployer.scan(ruleName, scanDirectory)

        print("\nHere are the results:\n")
        print(results)

    else:
        print("Rule rejected. Aborting deployment.")
        




if __name__ == "__main__":
    main()