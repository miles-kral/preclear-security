import html
import os
from pathlib import Path

import resend
import logging

from dotenv import load_dotenv
from fastapi import FastAPI, Form
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles


BASE_DIR = Path(__file__).resolve().parent

logger = logging.getLogger(
    "preclear_security"
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


if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY


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

app.mount(
    "/assets",
    StaticFiles(
        directory=BASE_DIR / "assets",
    ),
    name="assets",
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


@app.post("/contact")
def submit_contact(
    inquiry_type: str = Form(...),
    name: str = Form(...),
    company: str = Form(""),
    email: str = Form(...),
    message: str = Form(...),
    website: str = Form(""),
):
    # Honeypot field for basic bot filtering.
    if website:
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