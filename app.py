import html
import os
from pathlib import Path

import resend
import logging

from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from collections import defaultdict, deque
from threading import Lock
from time import monotonic

import requests

BASE_DIR = Path(__file__).resolve().parent

logger = logging.getLogger(
    "uvicorn.error"
)

load_dotenv(
    BASE_DIR / ".env"
)

RESEND_API_KEY = os.getenv(
    "RESEND_API_KEY",
    "",
)

CONTACT_FROM_EMAIL = os.getenv(
    "CONTACT_FROM_EMAIL",
    "",
)

CONTACT_TO_EMAIL = os.getenv(
    "CONTACT_TO_EMAIL",
    "",
)

TURNSTILE_SITE_KEY = os.getenv(
    "TURNSTILE_SITE_KEY",
    "",
)

TURNSTILE_SECRET_KEY = os.getenv(
    "TURNSTILE_SECRET_KEY",
    "",
)

TURNSTILE_ALLOWED_HOSTNAMES = {
    hostname.strip().lower()
    for hostname in os.getenv(
        "TURNSTILE_ALLOWED_HOSTNAMES",
        "preclearsecurity.com,www.preclearsecurity.com",
    ).split(",")
    if hostname.strip()
}


if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY

CONTACT_RATE_LIMIT = 3
CONTACT_RATE_WINDOW_SECONDS = 600

_submission_times = defaultdict(deque)
_submission_lock = Lock()


def get_request_ip(
    request: Request,
) -> str:
    forwarded_for = request.headers.get(
        "x-forwarded-for",
        "",
    )

    if forwarded_for:
        return (
            forwarded_for
            .split(",")[0]
            .strip()
        )

    if request.client:
        return request.client.host

    return "unknown"


def contact_rate_limit_exceeded(
    request: Request,
) -> bool:
    client_ip = get_request_ip(
        request
    )

    now = monotonic()

    cutoff = (
        now
        - CONTACT_RATE_WINDOW_SECONDS
    )

    with _submission_lock:
        timestamps = _submission_times[
            client_ip
        ]

        while (
            timestamps
            and timestamps[0] < cutoff
        ):
            timestamps.popleft()

        if (
            len(timestamps)
            >= CONTACT_RATE_LIMIT
        ):
            return True

        timestamps.append(now)

    return False


def verify_turnstile(
    token: str,
    secret_key: str,
    remote_ip: str | None = None,
    expected_action: str | None = None,
    allowed_hostnames: set[str] | None = None,
) -> bool:
    if not secret_key:
        return True

    if not token:
        return False

    payload = {
        "secret": secret_key,
        "response": token,
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        response = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=payload,
            timeout=5,
        )

        response.raise_for_status()

        result = response.json()

        if not result.get("success"):
            return False

        action = (
            str(result.get("action") or "")
            .strip()
        )

        hostname = (
            str(result.get("hostname") or "")
            .strip()
            .lower()
        )

        using_test_key = (
            secret_key.startswith("1x")
            or secret_key.startswith("2x")
            or secret_key.startswith("3x")
        )

        if (
            expected_action
            and not using_test_key
            and action != expected_action
        ):
            return False

        if (
            allowed_hostnames
            and not using_test_key
            and hostname not in allowed_hostnames
        ):
            return False

        return True

    except (
        requests.RequestException,
        ValueError,
    ):
        return False

app = FastAPI(
    title="PreClear Cybersecurity",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


app.mount(
    "/css",
    StaticFiles(
        directory=BASE_DIR / "css",
    ),
    name="css",
)

app.mount(
    "/js",
    StaticFiles(
        directory=BASE_DIR / "js",
    ),
    name="js",
)

app.mount(
    "/static",
    StaticFiles(
        directory=BASE_DIR / "static",
    ),
    name="static",
)


PAGES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/platform.html": "platform.html",
    "/vision.html": "vision.html",
    "/products.html": "products.html",
    "/mission.html": "mission.html",
    "/company.html": "company.html",
    "/investors.html": "investors.html",
    "/contact.html": "contact.html",
}


for route_path, filename in PAGES.items():

    def make_page_handler(
        page_filename: str,
    ):
        def page():
            return FileResponse(
                BASE_DIR / page_filename
            )

        return page

    app.add_api_route(
        route_path,
        make_page_handler(filename),
        methods=["GET"],
        include_in_schema=False,
    )

def log_contact_security_event(
    request: Request,
    event: str,
    *,
    blocked: bool = True,
) -> None:
    client_ip = get_request_ip(
        request
    )

    user_agent = (
        request.headers.get(
            "user-agent",
            "unknown",
        )
        .strip()
    )

    if len(user_agent) > 180:
        user_agent = (
            user_agent[:180]
            + "..."
        )

    log_method = (
        logger.warning
        if blocked
        else logger.info
    )

    log_method(
        "CONTACT_SECURITY event=%s ip=%s user_agent=%r",
        event,
        client_ip,
        user_agent,
    )


@app.post("/contact")
def submit_contact(
    request: Request,
    inquiry_type: str = Form(...),
    name: str = Form(...),
    company: str = Form(""),
    email: str = Form(...),
    message: str = Form(...),
    website: str = Form(""),
    turnstile_token: str = Form(
        "",
        alias="cf-turnstile-response",
    ),
):
    # Honeypot field for basic bot filtering.
    if website:
        log_contact_security_event(
            request,
            "contact_blocked_honeypot",
        )

        return RedirectResponse(
            url="/contact.html?sent=1",
            status_code=303,
        )

    client_ip = get_request_ip(
        request
    )

    if not verify_turnstile(
        token=turnstile_token,
        secret_key=TURNSTILE_SECRET_KEY,
        remote_ip=client_ip,
        expected_action="corporate_contact",
        allowed_hostnames=(
            TURNSTILE_ALLOWED_HOSTNAMES
        ),
    ):
        log_contact_security_event(
            request,
            "contact_blocked_turnstile",
        )

        return RedirectResponse(
            url="/contact.html?sent=1",
            status_code=303,
        )

    if contact_rate_limit_exceeded(
        request
    ):
        log_contact_security_event(
            request,
            "contact_blocked_rate_limit",
        )

        return RedirectResponse(
            url="/contact.html?sent=1",
            status_code=303,
        )

    allowed_inquiry_types = {
        "Enterprise / Security",
        "Investor / Funding",
        "Strategic Partnership",
        "Analyst / Media",
        "General Inquiry",
    }

    if inquiry_type not in allowed_inquiry_types:
        return RedirectResponse(
            url="/contact.html?error=1",
            status_code=303,
        )

    name = name.strip()
    company = company.strip()
    email = email.strip()
    message = message.strip()

    if (
        len(name) < 2
        or len(name) > 120
        or len(email) > 254
        or len(company) > 200
        or len(message) < 10
        or len(message) > 5000
    ):
        return RedirectResponse(
            url="/contact.html?error=1",
            status_code=303,
        )

    if (
        not RESEND_API_KEY
        or not CONTACT_FROM_EMAIL
        or not CONTACT_TO_EMAIL
    ):
        return RedirectResponse(
            url="/contact.html?error=1",
            status_code=303,
        )

    safe_type = html.escape(
        inquiry_type
    )

    safe_name = html.escape(
        name
    )

    safe_company = html.escape(
        company or "Not provided"
    )

    safe_email = html.escape(
        email
    )

    safe_message = html.escape(
        message
    ).replace(
        "\n",
        "<br>",
    )

    subject = (
        f"PreClear Website Inquiry: "
        f"{inquiry_type}"
    )

    email_html = f"""
    <h2>New PreClear Website Inquiry</h2>

    <p>
        <strong>Inquiry Type:</strong>
        {safe_type}
    </p>

    <p>
        <strong>Name:</strong>
        {safe_name}
    </p>

    <p>
        <strong>Company:</strong>
        {safe_company}
    </p>

    <p>
        <strong>Email:</strong>
        {safe_email}
    </p>

    <p>
        <strong>Message:</strong>
    </p>

    <p>
        {safe_message}
    </p>
    """

    try:
        response = resend.Emails.send(
            {
                "from": CONTACT_FROM_EMAIL,
                "to": [
                    CONTACT_TO_EMAIL,
                ],
                "reply_to": email,
                "subject": subject,
                "html": email_html,
            }
        )

        logger.info(
            "Contact inquiry accepted by Resend. "
            "Inquiry type=%s message_id=%s",
            inquiry_type,
            response.get("id"),
        )

        log_contact_security_event(
            request,
            "contact_accepted",
            blocked=False,
        )

    except Exception:
        logger.exception(
            "Contact inquiry email failed."
        )

        return RedirectResponse(
            url="/contact.html?error=1",
            status_code=303,
        )

    return RedirectResponse(
        url="/contact.html?sent=1",
        status_code=303,
    )

@app.get(
    "/favicon.ico",
    include_in_schema=False,
)
def favicon():
    return FileResponse(
        BASE_DIR
        / "static"
        / "preclear-shield.png"
    )

@app.get(
    "/robots.txt",
    include_in_schema=False,
)
def robots():
    return FileResponse(
        BASE_DIR / "robots.txt",
        media_type="text/plain",
    )


@app.get(
    "/sitemap.xml",
    include_in_schema=False,
)
def sitemap():
    return FileResponse(
        BASE_DIR / "sitemap.xml",
        media_type="application/xml",
    )