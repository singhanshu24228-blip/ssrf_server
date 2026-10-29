
# import argparse
# import ipaddress
# import json
# import socket
# import time
# import uuid

# from collections import deque
# from dataclasses import asdict, dataclass, field
# from urllib.parse import (
#     urljoin,
#     urlparse,
#     urlunparse,
#     parse_qsl,
#     urlencode,
# )

# import requests
# from bs4 import BeautifulSoup


# # --------------------------------------------------
# # Configuration
# # --------------------------------------------------

# SSRF_PARAM_HINTS = {
#     "url", "uri", "link", "href", "src", "image", "img",
#     "photo", "avatar", "file", "path", "callback", "webhook",
#     "feed", "target", "source", "dest", "destination",
#     "redirect", "return", "next", "endpoint", "proxy",
#     "fetch", "load", "host", "domain", "site", "address",
#     "resource", "import", "download"
# }

# MAX_PAGES = 20
# REQUEST_TIMEOUT = 8
# MAX_REDIRECTS_RECORDED = 5
# USER_AGENT = "Authorized-SSRF-Scanner/1.0"


# # --------------------------------------------------
# # Result models
# # --------------------------------------------------

# @dataclass
# class Finding:
#     category: str
#     url: str
#     parameter: str = ""
#     method: str = ""
#     evidence: str = ""
#     status: str = "potential"
#     notes: str = ""


# @dataclass
# class ScanResult:
#     target: str
#     pages_crawled: list = field(default_factory=list)
#     findings: list = field(default_factory=list)
#     errors: list = field(default_factory=list)
#     requests_sent: int = 0


# # --------------------------------------------------
# # URL and scope validation
# # --------------------------------------------------

# def origin_of(url):
#     parsed = urlparse(url)

#     scheme = parsed.scheme.lower()
#     host = (parsed.hostname or "").lower()

#     try:
#         port = parsed.port
#     except ValueError:
#         return None

#     if port is None:
#         port = 443 if scheme == "https" else 80

#     return scheme, host, port


# def is_valid_http_url(url):
#     try:
#         parsed = urlparse(url)

#         return (
#             parsed.scheme in ("http", "https")
#             and bool(parsed.hostname)
#             and not parsed.username
#             and not parsed.password
#             and parsed.port != 0
#         )
#     except ValueError:
#         return False


# def hostname_is_public(hostname):
#     """
#     Best-effort DNS/IP safety check for the scanner's target.

#     Rejects hostnames resolving to non-public IP addresses.
#     This is not a complete defense against DNS rebinding.
#     """
#     try:
#         addresses = socket.getaddrinfo(
#             hostname, None, type=socket.SOCK_STREAM
#         )
#     except socket.gaierror:
#         return False, "Hostname could not be resolved."

#     if not addresses:
#         return False, "No IP addresses found."

#     for info in addresses:
#         ip_text = info[4][0]

#         try:
#             ip = ipaddress.ip_address(ip_text)
#         except ValueError:
#             return False, "Invalid IP address returned by DNS."

#         if not ip.is_global:
#             return False, (
#                 f"Target resolves to a non-public IP address: {ip}"
#             )

#     return True, ""


# def validate_target(url, expected_origin=None):
#     if not is_valid_http_url(url):
#         return False, "Invalid HTTP/HTTPS URL."

#     if expected_origin is not None:
#         if origin_of(url) != expected_origin:
#             return False, "URL is outside the permitted origin."

#     hostname = urlparse(url).hostname
#     safe, reason = hostname_is_public(hostname)

#     if not safe:
#         return False, reason

#     return True, ""


# def is_ssrf_parameter(name):
#     lowered = name.lower()

#     return any(
#         hint in lowered
#         for hint in SSRF_PARAM_HINTS
#     )


# # --------------------------------------------------
# # Safe HTTP requests
# # --------------------------------------------------

# class Scanner:
#     def __init__(
#         self,
#         target,
#         callback_url=None,
#         allow_post_forms=False,
#         max_pages=MAX_PAGES,
#     ):
#         self.target = target
#         self.origin = origin_of(target)
#         self.callback_url = callback_url
#         self.allow_post_forms = allow_post_forms
#         self.max_pages = max_pages

#         self.result = ScanResult(target=target)

#         self.session = requests.Session()
#         self.session.headers.update({
#             "User-Agent": USER_AGENT
#         })

#         # Never follow redirects automatically.
#         self.session.max_redirects = MAX_REDIRECTS_RECORDED

#         self.visited = set()
#         self.seen_tests = set()

#     def request(self, method, url, **kwargs):
#         """
#         Requests only same-origin public target URLs.
#         Redirects are returned to the caller, not followed.
#         """
#         valid, reason = validate_target(
#             url, expected_origin=self.origin
#         )

#         if not valid:
#             self.result.errors.append(
#                 f"Request blocked: {url} ({reason})"
#             )
#             return None

#         try:
#             self.result.requests_sent += 1

#             return self.session.request(
#                 method,
#                 url,
#                 timeout=REQUEST_TIMEOUT,
#                 allow_redirects=False,
#                 **kwargs
#             )

#         except requests.RequestException as exc:
#             self.result.errors.append(
#                 f"{method} {url}: {exc}"
#             )
#             return None

#     # --------------------------------------------------
#     # Crawl pages and discover links
#     # --------------------------------------------------

#     def crawl(self):
#         queue = deque([self.target])

#         while queue and len(self.visited) < self.max_pages:
#             current = queue.popleft()

#             if current in self.visited:
#                 continue

#             self.visited.add(current)

#             response = self.request("GET", current)

#             if response is None:
#                 continue

#             self.result.pages_crawled.append({
#                 "url": current,
#                 "status": response.status_code
#             })

#             # Record redirects but do not follow them.
#             if response.is_redirect:
#                 self.result.findings.append(asdict(Finding(
#                     category="redirect",
#                     url=current,
#                     evidence=(
#                         f"HTTP {response.status_code}; "
#                         "redirect observed"
#                     ),
#                     status="informational",
#                     notes=(
#                         "A redirect alone is not evidence of SSRF. "
#                         "Location header was not followed."
#                     )
#                 )))
#                 continue

#             content_type = response.headers.get(
#                 "Content-Type", ""
#             ).lower()

#             if "text/html" not in content_type:
#                 continue

#             soup = BeautifulSoup(response.text, "html.parser")

#             self.inspect_query_parameters(current)
#             self.inspect_forms(soup, current)

#             for tag in soup.find_all("a", href=True):
#                 link = urljoin(current, tag["href"])
#                 parsed = urlparse(link)

#                 # Remove fragment; preserve query string.
#                 link = urlunparse((
#                     parsed.scheme,
#                     parsed.netloc,
#                     parsed.path,
#                     parsed.params,
#                     parsed.query,
#                     ""
#                 ))

#                 if origin_of(link) != self.origin:
#                     continue

#                 if link not in self.visited:
#                     queue.append(link)

#     # --------------------------------------------------
#     # Query parameter discovery and active testing
#     # --------------------------------------------------

#     def inspect_query_parameters(self, url):
#         parsed = urlparse(url)
#         params = parse_qsl(
#             parsed.query,
#             keep_blank_values=True
#         )

#         for index, (name, value) in enumerate(params):
#             if not is_ssrf_parameter(name):
#                 continue

#             self.result.findings.append(asdict(Finding(
#                 category="query_parameter",
#                 url=url,
#                 parameter=name,
#                 method="GET",
#                 evidence=f"Potential URL-related parameter: {name}",
#                 status="potential",
#                 notes=(
#                     "Parameter name is a heuristic only; "
#                     "server-side fetching is not established."
#                 )
#             )))

#             if self.callback_url:
#                 self.test_query_parameter(
#                     url, params, index, name
#                 )

#     def test_query_parameter(
#         self, url, params, index, name
#     ):
#         if not self.callback_url:
#             return

#         token = uuid.uuid4().hex
#         callback = (
#             self.callback_url.rstrip("/") + "/" + token
#         )

#         parsed = urlparse(url)
#         changed = list(params)
#         changed[index] = (name, callback)

#         test_url = urlunparse((
#             parsed.scheme,
#             parsed.netloc,
#             parsed.path,
#             parsed.params,
#             urlencode(changed),
#             ""
#         ))

#         key = ("GET", test_url)

#         if key in self.seen_tests:
#             return

#         self.seen_tests.add(key)

#         response = self.request("GET", test_url)

#         self.result.findings.append(asdict(Finding(
#             category="active_callback_test",
#             url=test_url,
#             parameter=name,
#             method="GET",
#             evidence=(
#                 f"Unique callback token: {token}; "
#                 f"target response: "
#                 f"{response.status_code if response else 'no response'}"
#             ),
#             status="submitted",
#             notes=(
#                 "A callback URL was supplied to the application. "
#                 "Check your callback server logs for this exact token. "
#                 "This result is not confirmed SSRF by itself."
#             )
#         )))

#     # --------------------------------------------------
#     # HTML form discovery and optional testing
#     # --------------------------------------------------

#     def inspect_forms(self, soup, page_url):
#         for form in soup.find_all("form"):
#             method = form.get("method", "get").strip().upper()

#             if method not in ("GET", "POST"):
#                 continue

#             action = urljoin(
#                 page_url,
#                 form.get("action") or page_url
#             )

#             if origin_of(action) != self.origin:
#                 continue

#             inputs = []

#             for element in form.find_all(
#                 ["input", "textarea", "select"]
#             ):
#                 name = element.get("name")

#                 if not name:
#                     continue

#                 input_type = element.get(
#                     "type", "text"
#                 ).lower()

#                 if input_type in (
#                     "submit", "button", "reset",
#                     "file", "password", "hidden"
#                 ):
#                     continue

#                 if input_type in ("checkbox", "radio"):
#                     if not element.has_attr("checked"):
#                         continue

#                 value = element.get("value", "")

#                 if element.name == "textarea":
#                     value = element.get_text()

#                 inputs.append((name, value))

#             candidates = [
#                 name for name, _ in inputs
#                 if is_ssrf_parameter(name)
#             ]

#             if not candidates:
#                 continue

#             self.result.findings.append(asdict(Finding(
#                 category="html_form",
#                 url=action,
#                 parameter=", ".join(candidates),
#                 method=method,
#                 evidence="Potential URL-related form field found",
#                 status="potential",
#                 notes=(
#                     "Form discovery does not prove the backend "
#                     "fetches supplied URLs."
#                 )
#             )))

#             if not self.callback_url:
#                 continue

#             # POST forms may change application state.
#             # Do not submit them unless explicitly enabled.
#             if method == "POST" and not self.allow_post_forms:
#                 self.result.findings.append(asdict(Finding(
#                     category="form_test_skipped",
#                     url=action,
#                     parameter=", ".join(candidates),
#                     method="POST",
#                     status="informational",
#                     notes=(
#                         "POST form was not submitted. Enable "
#                         "--allow-post-forms only when you understand "
#                         "the endpoint's effects and have permission."
#                     )
#                 )))
#                 continue

#             for candidate in candidates:
#                 self.test_form(
#                     action, method, inputs, candidate
#                 )

#     def test_form(self, action, method, inputs, candidate):
#         token = uuid.uuid4().hex
#         callback = (
#             self.callback_url.rstrip("/") + "/" + token
#         )

#         data = dict(inputs)
#         data[candidate] = callback

#         key = (method, action, candidate, token)

#         if key in self.seen_tests:
#             return

#         self.seen_tests.add(key)

#         if method == "GET":
#             response = self.request(
#                 "GET", action, params=data
#             )
#         else:
#             response = self.request(
#                 "POST", action, data=data
#             )

#         self.result.findings.append(asdict(Finding(
#             category="active_form_test",
#             url=action,
#             parameter=candidate,
#             method=method,
#             evidence=(
#                 f"Unique callback token: {token}; "
#                 f"target response: "
#                 f"{response.status_code if response else 'no response'}"
#             ),
#             status="submitted",
#             notes=(
#                 "Check your controlled callback logs for this token. "
#                 "The form response alone does not confirm SSRF."
#             )
#         )))

#     # --------------------------------------------------
#     # Report
#     # --------------------------------------------------

#     def run(self):
#         valid, reason = validate_target(
#             self.target, expected_origin=self.origin
#         )

#         if not valid:
#             self.result.errors.append(
#                 f"Target rejected: {reason}"
#             )
#             return self.result

#         if self.callback_url:
#             if not is_valid_http_url(self.callback_url):
#                 self.result.errors.append(
#                     "Callback URL must be a valid HTTP/HTTPS URL."
#                 )
#                 return self.result

#         self.crawl()
#         return self.result


# def print_report(result):
#     print("\n========== SSRF SCAN REPORT ==========")
#     print("Target:", result.target)
#     print("Pages crawled:", len(result.pages_crawled))
#     print("Requests sent:", result.requests_sent)
#     print("Findings:", len(result.findings))

#     for finding in result.findings:
#         print("\n[{}] {}".format(
#             finding["status"].upper(),
#             finding["category"]
#         ))
#         print("URL:", finding["url"])

#         if finding.get("parameter"):
#             print("Parameter:", finding["parameter"])

#         if finding.get("method"):
#             print("Method:", finding["method"])

#         if finding.get("evidence"):
#             print("Evidence:", finding["evidence"])

#         if finding.get("notes"):
#             print("Notes:", finding["notes"])

#     if result.errors:
#         print("\n========== ERRORS / BLOCKED REQUESTS ==========")
#         for error in result.errors:
#             print("-", error)

#     print("\nReminder: potential matches and submitted callback tests")
#     print("are not confirmed SSRF without supporting evidence.")


# def main():
#     parser = argparse.ArgumentParser(
#         description="Authorized SSRF reconnaissance and testing"
#     )

#     parser.add_argument(
#         "target",
#         nargs="?",
#         help="Starting URL of the authorized target"
#     )

#     parser.add_argument(
#         "--callback",
#         help="Base URL of a callback endpoint you control"
#     )

#     parser.add_argument(
#         "--max-pages",
#         type=int,
#         default=MAX_PAGES,
#         help="Maximum same-origin pages to crawl"
#     )

#     parser.add_argument(
#         "--allow-post-forms",
#         action="store_true",
#         help="Allow active tests of discovered POST forms"
#     )

#     parser.add_argument(
#         "--report",
#         default="ssrf_report.json",
#         help="Output JSON report path"
#     )

#     args = parser.parse_args()

#     if args.max_pages < 1 or args.max_pages > 100:
#         parser.error("--max-pages must be between 1 and 100")

#     target = args.target
#     if target is None:
#         try:
#             target = input("Enter the authorized target URL: ").strip()
#         except EOFError:
#             parser.error("A target URL is required.")

#     if not is_valid_http_url(target):
#         parser.error("Target must be a valid HTTP/HTTPS URL")

#     scanner = Scanner(
#         target=target,
#         callback_url=args.callback,
#         allow_post_forms=args.allow_post_forms,
#         max_pages=args.max_pages
#     )

#     result = scanner.run()
#     print_report(result)

#     with open(args.report, "w", encoding="utf-8") as report_file:
#         json.dump(asdict(result), report_file, indent=2)

#     print("\nJSON report saved to:", args.report)


# if __name__ == "__main__":
#     main()



import argparse
import hmac
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests
from dotenv import load_dotenv
from flask import Flask, request, jsonify, abort


# ==================================================
# Configuration
# ==================================================

# Load values from the .env file in the current project directory.
load_dotenv()

DB_FILE = os.environ.get("DB_FILE", "ssrf_callbacks.db")
CALLBACK_API_KEY = os.environ.get("CALLBACK_API_KEY", "")
CALLBACK_BASE = os.environ.get(
    "CALLBACK_BASE",
    "https://ssrf-server-u23s.onrender.com"
).rstrip("/")
CALLBACK_API = os.environ.get(
    "CALLBACK_API",
    "https://ssrf-server-u23s.onrender.com/api/events"
).rstrip("/")

SSRF_PARAM_HINTS = {
    "url", "uri", "link", "href", "src", "image", "img",
    "photo", "avatar", "file", "path", "callback", "webhook",
    "feed", "target", "source", "dest", "destination",
    "redirect", "return", "next", "endpoint", "proxy",
    "fetch", "load", "host", "domain", "site", "address",
    "resource", "image_url"
}

TIMEOUT = 8
CALLBACK_WAIT_SECONDS = 15
POLL_INTERVAL_SECONDS = 2


# ==================================================
# Callback database
# ==================================================

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS callbacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL,
                received_at TEXT NOT NULL,
                remote_addr TEXT,
                user_agent TEXT
            )
        """)


def record_callback(token, remote_addr, user_agent):
    received_at = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """
            INSERT INTO callbacks
                (token, received_at, remote_addr, user_agent)
            VALUES (?, ?, ?, ?)
            """,
            (token, received_at, remote_addr, user_agent)
        )


def get_callbacks(token):
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT token, received_at, remote_addr, user_agent
            FROM callbacks
            WHERE token = ?
            ORDER BY id DESC
            """,
            (token,)
        ).fetchall()

    return [dict(row) for row in rows]


# ==================================================
# Callback receiver
# ==================================================

app = Flask(__name__)


@app.route("/c/<token>", methods=["GET", "POST"])
def receive_callback(token):
    # Tokens generated by this scanner are UUID hex strings.
    if len(token) != 32 or any(
        c not in "0123456789abcdef" for c in token
    ):
        abort(404)

    record_callback(
        token=token,
        remote_addr=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")
    )

    # Return no internal data to the requesting application.
    return "", 204


@app.route("/api/events/<token>", methods=["GET"])
def callback_events(token):
    if not CALLBACK_API_KEY:
        abort(503, description="Callback API key is not configured")

    supplied_key = request.headers.get("X-API-Key", "")

    if not hmac.compare_digest(supplied_key, CALLBACK_API_KEY):
        abort(403)

    return jsonify(get_callbacks(token))


@app.route("/health", methods=["GET"])
def health():
    # Optional health endpoint; the root path "/" remains undefined.
    return jsonify({"status": "ok"}), 200


def run_callback_server(host, port):
    if not CALLBACK_API_KEY:
        raise SystemExit(
            "Set CALLBACK_API_KEY in your environment or .env file."
        )

    init_db()

    print("Starting callback receiver.")
    print("Configure HTTPS through a trusted reverse proxy.")
    app.run(host=host, port=port, debug=False)


# ==================================================
# SSRF scanner
# ==================================================

def is_ssrf_parameter(name):
    name = name.lower()
    return any(hint in name for hint in SSRF_PARAM_HINTS)


def valid_http_url(url):
    try:
        parsed = urlparse(url)
        return (
            parsed.scheme in ("http", "https")
            and bool(parsed.hostname)
            and not parsed.username
            and not parsed.password
            and parsed.port != 0
        )
    except ValueError:
        return False


def poll_callback(api_url, token, api_key):
    """
    Check the callback receiver for the unique test token.
    Returns matching events, or an empty list on timeout.
    """
    deadline = time.monotonic() + CALLBACK_WAIT_SECONDS

    while time.monotonic() < deadline:
        try:
            response = requests.get(
                api_url.rstrip("/") + "/" + token,
                headers={"X-API-Key": api_key},
                timeout=TIMEOUT,
                allow_redirects=False
            )
            response.raise_for_status()
            events = response.json()

            if events:
                return events

        except (requests.RequestException, ValueError) as error:
            print(f"[!] Callback polling error: {error}")
            return []

        time.sleep(POLL_INTERVAL_SECONDS)

    return []


def test_parameter(
    target_url,
    parameter_index,
    callback_base,
    callback_api,
    api_key
):
    parsed = urlparse(target_url)
    original_params = parse_qsl(
        parsed.query, keep_blank_values=True
    )

    if parameter_index >= len(original_params):
        return []

    name, old_value = original_params[parameter_index]

    if not is_ssrf_parameter(name):
        return []

    token = uuid.uuid4().hex
    callback_url = callback_base.rstrip("/") + "/c/" + token

    modified_params = list(original_params)
    modified_params[parameter_index] = (name, callback_url)

    test_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        urlencode(modified_params),
        ""
    ))

    print(f"\n[*] Testing parameter: {name}")
    print(f"[*] Unique token: {token}")

    try:
        # Do not follow target redirects automatically.
        response = requests.get(
            test_url,
            timeout=TIMEOUT,
            allow_redirects=False
        )
        print(f"[*] Target HTTP status: {response.status_code}")

    except requests.RequestException as error:
        print(f"[!] Target request failed: {error}")
        return [{
            "parameter": name,
            "status": "INCONCLUSIVE",
            "reason": str(error)
        }]

    print("[*] Waiting for callback evidence...")
    events = poll_callback(callback_api, token, api_key)

    if events:
        print("[+] MATCHING CALLBACK OBSERVED")
        for event in events:
            print("    Received at:", event.get("received_at"))
            print("    Source IP:", event.get("remote_addr"))
            print("    User-Agent:", event.get("user_agent"))

        print(
            "[!] Investigate whether the callback originated "
            "from the target application's backend."
        )
        status = "CALLBACK_OBSERVED"
    else:
        print("[-] No matching callback observed.")
        print(
            "[!] This does not rule out SSRF. The request may have "
            "been blocked, delayed, or failed."
        )
        status = "INCONCLUSIVE"

    return [{
        "parameter": name,
        "token": token,
        "target_url": target_url,
        "status": status,
        "callback_events": events
    }]


def run_scan(target, callback_base, callback_api, api_key):
    if not valid_http_url(target):
        raise SystemExit("Target must be a valid HTTP/HTTPS URL.")

    if not valid_http_url(callback_base):
        raise SystemExit("Invalid callback base URL.")

    if not valid_http_url(callback_api):
        raise SystemExit("Invalid callback API URL.")

    parsed_target = urlparse(target)
    parsed_callback = urlparse(callback_base)

    # Avoid accidentally using the target itself as callback.
    if (
        parsed_target.scheme,
        parsed_target.netloc
    ) == (
        parsed_callback.scheme,
        parsed_callback.netloc
    ):
        raise SystemExit(
            "Target and callback must be separate origins."
        )

    params = parse_qsl(
        parsed_target.query, keep_blank_values=True
    )

    candidates = [
        index for index, (name, value) in enumerate(params)
        if is_ssrf_parameter(name)
    ]

    if not candidates:
        print(
            "[!] No recognized SSRF-related query parameters "
            "found in the supplied URL."
        )
        print(
            "[!] This scanner does not yet discover HTML forms "
            "or JSON API request bodies."
        )
        return

    results = []
    for parameter_index in candidates:
        results.extend(test_parameter(
            target,
            parameter_index,
            callback_base,
            callback_api,
            api_key
        ))

    print("\n========== SUMMARY ==========")
    for result in results:
        print(result["parameter"], "=>", result["status"])

    print(
        "\nA callback is evidence of server-side fetching only "
        "after its source is attributed. Confirmed SSRF requires "
        "additional validation of the security impact."
    )


# ==================================================
# Command-line interface
# ==================================================

def main():
    parser = argparse.ArgumentParser(
        description="Authorized SSRF callback verification"
    )
    subparsers = parser.add_subparsers(
        dest="mode", required=True
    )

    server_parser = subparsers.add_parser("server")
    server_parser.add_argument("--host", default="127.0.0.1")
    server_parser.add_argument("--port", type=int, default=5000)

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("target")
    scan_parser.add_argument(
        "--callback-base",
        default=CALLBACK_BASE
    )
    scan_parser.add_argument(
        "--callback-api",
        default=CALLBACK_API
    )

    args = parser.parse_args()

    if args.mode == "server":
        run_callback_server(args.host, args.port)

    elif args.mode == "scan":
        if not CALLBACK_API_KEY:
            raise SystemExit(
                "Set CALLBACK_API_KEY in your .env file or environment."
            )

        run_scan(
            args.target,
            args.callback_base,
            args.callback_api,
            CALLBACK_API_KEY
        )


if __name__ == "__main__":
    main()
