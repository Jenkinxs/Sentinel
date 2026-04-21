import os
import subprocess
import tempfile


def yarac(rule_text):
    try:

        with tempfile.NamedTemporaryFile(suffix=".yar", mode="w", delete=False) as f:
            f.write(rule_text)
            tmp = f.name

        result = subprocess.run(
            ["yarac", tmp, "/dev/null"],
            capture_output=True, text=True
        )
        
        os.unlink(tmp)

        print(f"YARAC RESULT: {result}")
        print(f"YARAC RETURN CODE: {result.returncode}")
              
        return result.returncode, result
   
    except Exception as e:

        print(f"\n\n{e}")


if __name__ == "main":
    yarac("Test Rule")