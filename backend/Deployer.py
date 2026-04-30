import os
from pathlib import Path
import yara_x



def scan(rulesFile, scanDirectory):

    rulesPath = f"{(Path.cwd())}/rules/"

    with open(f"{rulesPath}{rulesFile}", "r", encoding="utf-8") as file:
        ruleUncompiled = file.read()


    rules = yara_x.compile(ruleUncompiled)


    results = {}
    
    for root, dirs, files in os.walk(scanDirectory):

        for filename in files:

            filepath = os.path.join(root, filename)

            try:


                with open(filepath, 'rb') as f:
                    data = f.read()
                scanner = yara_x.Scanner(rules)
                matches = scanner.scan(data)

                if matches.matching_rules:
                    results[filepath] = matches.matching_rules


            except Exception as e:

                print(f"Error scanning {filepath}: {e}")
    
    
    return results








