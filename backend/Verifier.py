import os
import subprocess
import tempfile

def yarac(rule_text):
    with tempfile.NamedTemporaryFile(suffix=".yar", mode="w", delete=False) as f:
        f.write(rule_text)
        tmp = f.name
    result = subprocess.run(
        ["yarac", tmp, "/dev/null"],
        capture_output=True, text=True
    )
    os.unlink(tmp)
    return result.returncode == 0, result.stderr.strip()



if __name__ == "main":
    yarac("Test Rule")