from flask import Flask, request, jsonify
from urllib.parse import unquote, urlparse
import re
import os

app = Flask(__name__)

ALLOWED_HOSTS = {
    "cdn-x537o79.example",
    "app-7m62zrz.example"
}

CHANNELS = {
    "html",
    "markdown",
    "url",
    "sql",
    "shell"
}


# =================================================
# RESPONSE
# =================================================

def result(safe, reason):
    response = jsonify({
        "safe": safe,
        "reason": reason
    })
    response.status_code = 200
    return response


# =================================================
# HTML ENTITY DECODING
# =================================================

def decode_html_entities(text):

    entities = {
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&apos;": "'",
        "&amp;": "&"
    }

    pattern = re.compile(
        r"&(?:lt|gt|quot|apos|amp);"
        r"|&#[0-9]+;"
        r"|&#x[0-9a-fA-F]+;"
    )

    def replace(match):

        value = match.group(0)

        if value in entities:
            return entities[value]

        if value.startswith("&#x"):
            try:
                return chr(int(value[3:-1], 16))
            except ValueError:
                return value

        if value.startswith("&#"):
            try:
                return chr(int(value[2:-1], 10))
            except ValueError:
                return value

        return value

    return pattern.sub(replace, text)


# =================================================
# UNICODE ESCAPE DECODING
# =================================================

def decode_unicode_escapes(text):

    def replace(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    return re.sub(
        r"\\u([0-9a-fA-F]{4})",
        replace,
        text
    )


# =================================================
# DECODE EXACTLY ONCE
# =================================================

def decode_once(text):

    # 1. Percent escapes
    decoded = unquote(text)

    # 2. HTML entities
    decoded = decode_html_entities(decoded)

    # 3. \uXXXX escapes
    decoded = decode_unicode_escapes(decoded)

    return decoded


# =================================================
# URL EXTRACTION
# =================================================

def extract_urls(channel, text):

    urls = []

    # -------------------------
    # HTML
    # -------------------------

    if channel == "html":

        pattern = re.compile(
            r"""(?:src|href)\s*=\s*(['"])(.*?)\1""",
            re.IGNORECASE | re.DOTALL
        )

        for match in pattern.finditer(text):
            urls.append(match.group(2))

    # -------------------------
    # MARKDOWN
    # -------------------------

    elif channel == "markdown":

        pattern = re.compile(
            r"\]\((.*?)\)",
            re.DOTALL
        )

        for match in pattern.finditer(text):

            target = match.group(1).strip()

            # <https://example.com>
            if target.startswith("<"):
                end = target.find(">")

                if end != -1:
                    target = target[1:end]

            else:
                # Remove optional markdown title
                target = target.split(None, 1)[0]

            urls.append(target)

    # -------------------------
    # URL
    # -------------------------

    elif channel == "url":

        urls.append(text.strip())

    return urls


# =================================================
# DANGEROUS SCHEME
# =================================================

def has_dangerous_scheme(channel, text):

    # javascript:
    # data:
    # vbscript:
    #
    # Optional whitespace before colon

    dangerous = re.compile(
        r"(?:javascript|data|vbscript)\s*:",
        re.IGNORECASE
    )

    if dangerous.search(text):
        return True

    urls = extract_urls(channel, text)

    for value in urls:

        value = value.strip()

        # Protocol-relative URL
        if value.startswith("//"):
            scheme = "https"

        else:
            parsed = urlparse(value)
            scheme = parsed.scheme.lower()

        # Any extracted URL with a scheme other than
        # http / https is dangerous.

        if scheme and scheme not in {
            "http",
            "https"
        }:
            return True

    return False


# =================================================
# EXTERNAL EXFILTRATION
# =================================================

def has_external_exfil(channel, text):

    urls = extract_urls(channel, text)

    for value in urls:

        value = value.strip()

        # Protocol-relative URL
        if value.startswith("//"):
            parsed = urlparse("https:" + value)

        else:
            parsed = urlparse(value)

        scheme = parsed.scheme.lower()

        # Only absolute HTTP/HTTPS URLs
        if scheme not in {
            "http",
            "https"
        }:
            continue

        hostname = parsed.hostname

        if hostname is None:
            return True

        hostname = hostname.lower()

        # EXACT hostname match
        if hostname not in ALLOWED_HOSTS:
            return True

    return False


# =================================================
# HTML
# =================================================

def check_html(text):

    # 1. SCRIPT_TAG

    script_pattern = re.compile(
        r"<\s*(script|iframe|object|embed)\b",
        re.IGNORECASE
    )

    if script_pattern.search(text):
        return "SCRIPT_TAG"

    # 2. EVENT_HANDLER

    event_pattern = re.compile(
        r"\bon[a-zA-Z0-9_-]+\s*=",
        re.IGNORECASE
    )

    if event_pattern.search(text):
        return "EVENT_HANDLER"

    # 3. DANGEROUS_SCHEME

    if has_dangerous_scheme("html", text):
        return "DANGEROUS_SCHEME"

    # 4. EXTERNAL_EXFIL

    if has_external_exfil("html", text):
        return "EXTERNAL_EXFIL"

    return None


# =================================================
# MARKDOWN
# =================================================

def check_markdown(text):

    # 1. DANGEROUS_SCHEME

    if has_dangerous_scheme("markdown", text):
        return "DANGEROUS_SCHEME"

    # 2. EXTERNAL_EXFIL

    if has_external_exfil("markdown", text):
        return "EXTERNAL_EXFIL"

    return None


# =================================================
# URL
# =================================================

def check_url(text):

    # 1. DANGEROUS_SCHEME

    if has_dangerous_scheme("url", text):
        return "DANGEROUS_SCHEME"

    # 2. EXTERNAL_EXFIL

    if has_external_exfil("url", text):
        return "EXTERNAL_EXFIL"

    return None


# =================================================
# SQL
# =================================================

def check_sql(text):

    if "'" in text:
        return "SQL_METACHAR"

    if '"' in text:
        return "SQL_METACHAR"

    if ";" in text:
        return "SQL_METACHAR"

    if "--" in text:
        return "SQL_METACHAR"

    if "/*" in text:
        return "SQL_METACHAR"

    if re.search(
        r"\bunion\b",
        text,
        re.IGNORECASE
    ):
        return "SQL_METACHAR"

    if re.search(
        r"\bor\s+1\s*=\s*1\b",
        text,
        re.IGNORECASE
    ):
        return "SQL_METACHAR"

    return None


# =================================================
# SHELL
# =================================================

def check_shell(text):

    # ; & | ` < >

    if any(
        char in text
        for char in ";&|`<>"
    ):
        return "SHELL_METACHAR"

    # $(

    if "$(" in text:
        return "SHELL_METACHAR"

    # ${

    if "${" in text:
        return "SHELL_METACHAR"

    return None


# =================================================
# CHANNEL DISPATCH
# =================================================

def check_channel(channel, text):

    if channel == "html":
        return check_html(text)

    if channel == "markdown":
        return check_markdown(text)

    if channel == "url":
        return check_url(text)

    if channel == "sql":
        return check_sql(text)

    if channel == "shell":
        return check_shell(text)

    return None


# =================================================
# SANITIZE ENDPOINT
# =================================================

@app.route(
    "/sanitize-output",
    methods=["POST"]
)
def sanitize_output():

    # =================================================
    # RULE 1: INVALID_SCHEMA
    # =================================================

    try:
        data = request.get_json(
            force=True,
            silent=False
        )
    except Exception:
        return result(
            False,
            "INVALID_SCHEMA"
        )

    if type(data) is not dict:
        return result(
            False,
            "INVALID_SCHEMA"
        )

    if "channel" not in data:
        return result(
            False,
            "INVALID_SCHEMA"
        )

    if "output" not in data:
        return result(
            False,
            "INVALID_SCHEMA"
        )

    channel = data["channel"]
    output = data["output"]

    if channel not in CHANNELS:
        return result(
            False,
            "INVALID_SCHEMA"
        )

    if type(output) is not str:
        return result(
            False,
            "INVALID_SCHEMA"
        )

    if len(output) > 20000:
        return result(
            False,
            "INVALID_SCHEMA"
        )

    # =================================================
    # RULE 2: ENCODED_PAYLOAD
    # =================================================

    decoded = decode_once(output)

    if decoded != output:

        decoded_reason = check_channel(
            channel,
            decoded
        )

        if decoded_reason is not None:
            return result(
                False,
                "ENCODED_PAYLOAD"
            )

    # =================================================
    # RULE 3: ORIGINAL OUTPUT
    # =================================================

    reason = check_channel(
        channel,
        output
    )

    if reason is not None:
        return result(
            False,
            reason
        )

    # =================================================
    # SAFE
    # =================================================

    return result(
        True,
        "SAFE"
    )


# =================================================
# HEALTH CHECK
# =================================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "status": "ok",
        "service": "llm-output-handling-gate"
    })


# =================================================
# START
# =================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port
    )
