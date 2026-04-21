import requests
import os
import Verifier
import time
import datetime


MODEL_URL = "http://localhost:11434/api/generate" #Alter as needed for different providers
LLM1 = "SentinelGen"
LLM2 = "SentinelRvw"
RETRIES = 10


def main():
    
    print("Welcome to SENTINEL.\n")

        # "Detect a dropper that writes a file to the Windows temp directory and executes it via cmd.exe"
    prompt = input("Enter a description of what you want to identify. ")

    try:
        print("Creating rules...")
        yaraRule = call_model(prompt, "LLM1", False)

        #use llm1's response and send it through YARAC for initial syntax check, if fails, ship it back for correction
        print("Verifying syntax...")
        verified = syntax_verification(yaraRule)


        if verified == True:
            print("Reviewing Rules...")
            ruleReview = call_model(yaraRule, "LLM2", False)
            
            print("\n\n")
            print("=============================================================================================================================")
            print("Here's the finalized rule, along with the Reviewer's analysis. Double check this is what you intended for before deployment.\n")

            time.sleep(3)

            print(yaraRule)
            time.sleep(2)

            print(ruleReview)

            deploy(yaraRule)

        else:
            print(f"Initial YARAC verification failed after {RETRIES} retries. Not proceeding.")


    except Exception as e:
        print(f"\n\nAn error has occurred:\t{e}")



def call_model(prompt, responseType, yarac):

    if responseType == "LLM1":
        model = LLM1
    else:
        model = LLM2


    try:
        if not yarac:
            print(f"Calling {model}")

        else:
            print(f"Conversing with {model}")

        response = requests.post(MODEL_URL, json={
            "model": model,
            "prompt": prompt,
            "stream": False
        })

        return response.json()["response"].strip()
    
    except Exception as e:

        print(f"\n\nAn error occurred when calling the model:\t{e}")


def syntax_verification(rule):

    for fail in range(RETRIES):
        print(f"Retry #{fail + 1}")
        verified, result   = Verifier.yarac(rule) # verified is a returncode

        if verified == 0:
            break
        
        else:

            prompt = f"The following YARA ruleset contains errors identified by the YARA compiler, YARAC. Look at information provided by YARAC, and alter the rule accordingly. " \
                    f"YARAC OUTPUT:\n {verified} ; {result}.\nRULES:\n {rule}"
            
            print("Fixing Syntax...")
            call_model(prompt, "LLM1", True)

    return True



def deploy(yaraRule):
    accepted = (input("Deploy? Y/N ")).upper()

    if accepted == "Y":
        with open(f"Sentinel_Rule{datetime.datetime.now}.yar", "w") as file:
            file.write(yaraRule)

    else:
        print("Rule rejected. Aborting deployment.")
        




if __name__:
    main()