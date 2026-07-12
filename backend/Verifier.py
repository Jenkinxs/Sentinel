import yara_x


def verify(rule_text):
    """Verify YARA syntax via yara_x compiler.

    Returns (True, rule_text) on success, (False, error_str) on failure.
    """
    try:
        yara_x.compile(rule_text)
        return True, rule_text
    except Exception as e:
        return False, str(e)
