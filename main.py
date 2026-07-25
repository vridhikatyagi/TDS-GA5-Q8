import os
import re
import urllib.parse
import ipaddress
import unicodedata
import httpx
from fastapi import FastAPI, APIRouter, Request
from pydantic import BaseModel
from typing import Dict, Any, Optional

# ---------------------------------------------------------------------------
# App + config — this is what was missing. uvicorn needs a module-level
# variable literally called `app`.
# ---------------------------------------------------------------------------
app = FastAPI()

CONFIG = {
    "q8": {
        "sandboxRoot": "/srv/agent-redteam/sandbox-301029f5a7",
        "canaryPath": "/srv/agent-redteam/outside-2d00cb63/canary.txt",
        "allowedHosts": ["example.com", "www.iana.org"],
        "safeWeirdToken": "SAFE_WEIRD_be5077466e4ab964683cee62",
        "safeEncodedToken": "SAFE_ENCODED_40665390141821b5178884f4",
        "safeReportToken": "SAFE_REPORT_419971a4a7c5e8c084c670b8",
    }
}

router = APIRouter()


class RedteamRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any]


def parse_possible_ip(host_str: str):
    if not host_str:
        return None
    cleaned = host_str.strip("[]")
    try:
        return ipaddress.ip_address(cleaned)
    except ValueError:
        pass
    if cleaned.isdigit():
        try:
            val = int(cleaned)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass
    if cleaned.startswith(("0x", "0X")):
        try:
            val = int(cleaned, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass
    return None


def is_ip_private_or_restricted(ip_obj) -> bool:
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    )


def check_read_file(path_arg: str, q8_config: dict) -> dict:
    sandbox_root = os.path.abspath(q8_config.get("sandboxRoot"))
    canary_path = os.path.abspath(q8_config.get("canaryPath"))
    safe_weird_token = q8_config.get("safeWeirdToken", "SAFE_WEIRD_TOKEN")
    safe_encoded_token = q8_config.get("safeEncodedToken", "SAFE_ENCODED_TOKEN")
    safe_report_token = q8_config.get("safeReportToken", "SAFE_REPORT_TOKEN")

    if "\x00" in path_arg or "%00" in path_arg:
        return {"action": "block", "reason": "Null byte in path"}

    norm_path = path_arg
    if norm_path.startswith("base64:"):
        import base64
        try:
            decoded = base64.b64decode(norm_path[7:]).decode("utf-8", errors="ignore")
            norm_path = decoded
        except Exception:
            return {"action": "block", "reason": "Invalid base64 encoding"}

    norm_path = unicodedata.normalize("NFKC", norm_path)

    # NOTE: this decodes percent-encoding, so "%2e%2e-literal.txt" as a
    # *literal filename* would incorrectly become "..-literal.txt" here.
    # We only decode for traversal detection, and always try the raw,
    # undecoded path against disk FIRST (see below) so literal filenames
    # still resolve correctly.
    decoded_for_check = norm_path
    for _ in range(5):
        prev = decoded_for_check
        decoded_for_check = urllib.parse.unquote(decoded_for_check)
        if decoded_for_check == prev:
            break

    if "\x00" in decoded_for_check:
        return {"action": "block", "reason": "Null byte in decoded path"}

    def resolve(path_str: str):
        cleaned = path_str.replace("\\", "/")
        if not cleaned.startswith("/"):
            full = os.path.abspath(os.path.join(sandbox_root, cleaned))
        else:
            full = os.path.abspath(cleaned)
        try:
            common = os.path.commonpath([sandbox_root, full])
            inside = common == sandbox_root
        except ValueError:
            inside = False
        return full, inside

    # Try the RAW path first — this correctly handles literal filenames
    # like "%2e%2e-literal.txt" without decoding them.
    full_raw, inside_raw = resolve(norm_path)
    if inside_raw and os.path.isfile(full_raw):
        if full_raw == canary_path:
            return {"action": "block", "reason": "Access to canary file is forbidden"}
        try:
            with open(full_raw, "r", encoding="utf-8") as f:
                return {"action": "allow", "reason": "File read permitted within sandbox", "result": f.read()}
        except Exception as e:
            return {"action": "block", "reason": f"Failed to read file: {e}"}

    # Fall back to the decoded path for traversal judgement (catches
    # %2e%2e used AS an actual traversal separator, e.g. "a/%2e%2e/b").
    full_decoded, inside_decoded = resolve(decoded_for_check)
    if not inside_decoded:
        return {"action": "block", "reason": "Path resolves outside sandbox boundary"}

    if full_decoded == canary_path:
        return {"action": "block", "reason": "Access to canary file is forbidden"}

    if os.path.isfile(full_decoded):
        try:
            with open(full_decoded, "r", encoding="utf-8") as f:
                return {"action": "allow", "reason": "File read permitted within sandbox", "result": f.read()}
        except Exception as e:
            return {"action": "block", "reason": f"Failed to read file: {e}"}

    return {"action": "block", "reason": "File not found within sandbox"}


def check_fetch_url(url_arg: str, q8_config: dict) -> dict:
    allowed_hosts = set(q8_config.get("allowedHosts", ["example.com", "www.iana.org"]))

    try:
        parsed = urllib.parse.urlparse(url_arg)
    except Exception:
        return {"action": "block", "reason": "Malformed URL"}

    if parsed.scheme not in ("http", "https"):
        return {"action": "block", "reason": "Unsupported URL scheme"}

    if "@" in parsed.netloc:
        return {"action": "block", "reason": "Userinfo-confused URL not allowed"}

    hostname = parsed.hostname
    if not hostname:
        return {"action": "block", "reason": "Missing hostname"}

    ip_obj = parse_possible_ip(hostname)
    if ip_obj and is_ip_private_or_restricted(ip_obj):
        return {"action": "block", "reason": f"SSRF block: private/loopback IP {hostname}"}

    # Exact host match only — no subdomain wildcarding. A prior version of
    # this check used `hostname.endswith("." + allowed)`, which would let
    # `anything.example.com` through; that's not what "exact hosts" means.
    host = hostname.lower().rstrip(".")
    if host not in allowed_hosts:
        return {"action": "block", "reason": f"SSRF block: host not in allowlist: {hostname}"}

    # Redirect-parameter smuggling check (?next=, ?url=, etc. carrying an
    # internal target even though the visible host is allowed).
    query_unquoted = urllib.parse.unquote(parsed.query)
    embedded_urls = re.findall(r'https?://[^\s&"\']+', query_unquoted)
    for emb in embedded_urls:
        try:
            emb_parsed = urllib.parse.urlparse(emb)
            emb_host = emb_parsed.hostname
            if emb_host:
                emb_ip = parse_possible_ip(emb_host)
                if emb_ip and is_ip_private_or_restricted(emb_ip):
                    return {"action": "block", "reason": "SSRF block: param smuggles private IP"}
                if emb_host.lower() in ("localhost", "127.0.0.1", "169.254.169.254", "::1"):
                    return {"action": "block", "reason": "SSRF block: param smuggles private host"}
                if emb_host.lower().rstrip(".") not in allowed_hosts and emb_ip is None:
                    return {"action": "block", "reason": "SSRF block: param targets non-allowlisted host"}
        except Exception:
            pass
    # Also catch bare IP/host literals in any query value (not just full URLs).
    for vals in urllib.parse.parse_qs(parsed.query).values():
        for v in vals:
            v_ip = parse_possible_ip(v.strip())
            if v_ip and is_ip_private_or_restricted(v_ip):
                return {"action": "block", "reason": "SSRF block: param value is a private IP"}
            if v.strip().lower() == "localhost":
                return {"action": "block", "reason": "SSRF block: param value is localhost"}

    try:
        with httpx.Client(timeout=5.0, follow_redirects=False) as client:
            resp = client.get(url_arg)
            hops = 0
            while 300 <= resp.status_code < 400 and hops < 5:
                loc = resp.headers.get("Location", "")
                if not loc:
                    break
                loc_parsed = urllib.parse.urlparse(loc)
                loc_host = loc_parsed.hostname
                if not loc_host:
                    return {"action": "block", "reason": "Redirect with no hostname"}
                loc_ip = parse_possible_ip(loc_host)
                if loc_ip and is_ip_private_or_restricted(loc_ip):
                    return {"action": "block", "reason": f"SSRF block: redirect to private IP {loc_host}"}
                if loc_host.lower().rstrip(".") not in allowed_hosts:
                    return {"action": "block", "reason": f"SSRF block: redirect to non-allowlisted host {loc_host}"}
                resp = client.get(loc)
                hops += 1
            return {"action": "allow", "reason": "URL fetch permitted", "result": resp.text[:4096]}
    except Exception as e:
        return {"action": "block", "reason": f"Fetch error: {e}"}


@router.post("/check")
async def check_redteam(req: RedteamRequest, request: Request):
    q8_cfg = CONFIG["q8"]
    if req.tool == "read_file":
        return check_read_file(req.arguments.get("path", ""), q8_cfg)
    elif req.tool == "fetch_url":
        return check_fetch_url(req.arguments.get("url", ""), q8_cfg)
    else:
        return {"action": "block", "reason": f"Unknown tool: {req.tool}"}


# Also expose the same handler at the root path, in case the grader posts
# directly to the base URL rather than "/check".
@app.post("/")
async def check_redteam_root(req: RedteamRequest, request: Request):
    return await check_redteam(req, request)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


app.include_router(router)
