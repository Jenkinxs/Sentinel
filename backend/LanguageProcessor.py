import requests
import os
import Verifier
import time


MODEL_URL = "http://localhost:11434/api/generate" #Alter as needed for different providers
LLM1 = ""
LLM2 = ""

def call_model(prompt, responseType):

    if responseType == "LLM1":
        model = LLM1
    else:
        model = LLM2


    response = requests.post(OLLAMA_URL, json={
        "model": model,
        "prompt": prompt,
        "stream": False
    })
    return response.json()["response"].strip()


def generate_rule(userPrompt):

    call_provider(model, prompt)




def main():
    # print welcome message
    print("Welcome to SENTINEL.\n")

    # ask user prompt
    prompt = input("Enter a description of what you want to identify. ")

    # send the prompt to llm1 along with the system prompt
    model1Response = call_model(prompt, "LLM1")

    # use llm1's response and send it through YARAC for syntax check, if fails, ship it back for correction
    yaracFailed = 0
    while yaracFailed != 0:
        yaracFailed = Verifier.yarac(response)

    # send the response to llm2 for verification
    if yaracFailed == 0:
        model2Response = call_model(model1Response, "LLM2")
        

    # ask user if it looks good, if not, send back to llm1.
    print("\nHere's the finalized rule. Double check this is what you intended for before deployment.")
    time.sleep(5)

    # if fine, go through to the deployer
