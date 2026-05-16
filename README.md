# AI Phishing Risk Assistant

A Chrome Manifest V3 extension and local FastAPI backend for detecting phishing indicators in opened Gmail messages.

This first version is rule-based only. It does not use any paid external API.

Privacy note: This prototype analyses only the visible email content in the browser and sends it to a local backend for demonstration purposes.

## Structure

```text
gmail-phishing-detector/
  extension/
    manifest.json
    content.js
    style.css
  backend/
    app/
      main.py
      api/
        routes.py
      services/
        phishing_detector.py
        domain_checks.py
        banking_detector.py
      models/
        schemas.py
      utils/
        scoring.py
    main.py
    requirements.txt
  samples/
    safe_email.txt
    medium_risk_email.txt
    high_risk_phishing_email.txt
  README.md
```

## How It Works

1. The Chrome extension runs on `https://mail.google.com/*`.
2. When a Gmail message is opened, `content.js` extracts the visible email text and links.
3. The extension sends this JSON to the local backend at `http://localhost:8000/analyse`:

```json
{
  "email_text": "Visible Gmail message text...",
  "links": ["https://example.com/path"],
  "sender_email": "sender@example.com"
}
```

If Gmail does not expose the sender email address in the visible message view, the extension sends `"sender_email": null` and the normal text/link analysis still runs.

4. The FastAPI backend returns a phishing risk level, score, and reasons.
5. The extension shows a compact warning banner near the top-right of Gmail.

## Run the Backend

From the project root:

```bash
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

From the `backend` folder, this shorter command also works with Uvicorn's default host and port:

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Check that the backend is running:

```bash
Invoke-RestMethod http://127.0.0.1:8000/health
```

Expected response:

```json
{"status":"ok"}
```

You can also open `http://127.0.0.1:8000/docs` to view the FastAPI docs.

## Load the Chrome Extension

1. Open Chrome.
2. Go to `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked**.
5. Select the `gmail-ai-phishing-detector/extension` folder.
6. Confirm that **AI Phishing Risk Assistant** appears in the extensions list.

If you change files in `extension/`, click the extension's reload button in `chrome://extensions` and refresh Gmail.

## Test With Gmail

1. Start the backend first.
2. Load or reload the Chrome extension.
3. Open Gmail at `https://mail.google.com/`.
4. Send the sample emails to yourself, or paste each sample into a Gmail draft and send it to your own address.
5. Open each received email in Gmail.
6. Watch for the floating phishing banner near the top-right of the Gmail page.

Sample messages are in:

- `samples/safe_email.txt`
- `samples/medium_risk_email.txt`
- `samples/high_risk_phishing_email.txt`

For the best link extraction test, make sure Gmail turns the sample URLs into clickable links before sending.

You can also paste this fake banking phishing example into a Gmail draft and send it to yourself:

```text
Subject: Maybank security alert: account locked

Dear customer,

Maybank has detected an unauthorised transaction on your online banking profile. Your account locked status will remain active unless you verify your banking account immediately.

Confirm your account, update your banking details, and enter your OTP or TAC here:
http://192.168.1.44/login/verify-account

Failure to act within 24 hours will result in account closure.

Security Department
```

## What the Demo Should Show

The safe sample should show a **Low** risk label with a low score and no major warning reasons.

The medium-risk sample should show a **Medium** risk label because it uses a generic greeting, billing language, and a shortened link.

The high-risk phishing sample should show a **High** risk label because it uses urgent language, account verification wording, password and banking-detail requests, Malaysian banking impersonation wording, an insecure IP-address link, and a suspicious domain.

The banner should:

- appear near the top-right of Gmail
- show the risk level and risk score
- show the sender domain, SPF status, and DMARC status when available
- show a banking impersonation warning when detected
- show the top 3 reasons by default
- expand all reasons when **View details** is clicked
- close when the close button is clicked
- show a backend warning if FastAPI is not running

## New Security Checks

The extension now tries to extract the visible sender email address from Gmail and sends it to the local backend. The backend extracts the sender domain, such as `example.com`, and performs basic DNS checks.

**SPF** is a DNS TXT record that lists which mail servers are allowed to send email for a domain. If SPF is missing, the backend adds a small risk score because the sender domain has weaker sender authentication.

**DMARC** is a DNS TXT record under `_dmarc.<domain>`. It tells receiving mail systems how to handle messages that fail authentication checks. If DMARC is missing, the backend adds a slightly higher risk score than SPF because DMARC is important for reducing spoofed email.

These SPF and DMARC checks are basic existence checks only. They do not fully prove whether an individual email is legitimate. If DNS lookup fails, the result is marked as inconclusive and only a small score is added.

The backend also checks for banking impersonation language. It looks for phrases such as `online banking`, `account locked`, `unauthorised transaction`, `OTP`, and `TAC`, plus Malaysian financial brands such as Maybank, CIMB, Public Bank, RHB, Hong Leong Bank, AmBank, Bank Islam, BSN, Touch 'n Go, TNG, DuitNow, and FPX.

If a message mentions one of those brands and also asks for urgent account verification, credentials, payment, or banking details, the backend raises the risk and returns a reason such as:

```text
Possible banking impersonation detected: mentions Maybank with urgent account verification language.
```

## Purpose

Banks and financial services teams spend significant effort reducing phishing, credential theft, and online banking fraud. While Phishing emails remain one of the most common attack vectors for credential theft, financial fraud, and account compromise.

This project was developed as a lightweight browser-side assistant that helps users identify suspicious emails directly inside Gmail before interacting with links or sharing sensitive information.

The prototype combines:
- phishing content analysis
- suspicious link detection
- sender-domain checks
- SPF/DMARC awareness
- banking impersonation detection
- explainable risk feedback

The goal is to improve user awareness and support safer decision-making during email interactions.

## Rule-Based Checks

The backend currently looks for:

- urgent or threatening wording
- password, sign-in, account verification, or payment update requests
- banking impersonation phrases and Malaysian financial brand names
- missing or inconclusive SPF and DMARC records for the sender domain
- generic greetings
- insecure `http://` links
- URL shorteners
- IP-address links
- suspicious domain endings
- visible link text that points to a different destination domain
- URLs with redirect parameters

## Next Steps
- Add backend unit tests for the rule-based checks.
- Add trusted-domain allowlists.
- Add extension options for configuring the backend URL.
- Later, add an optional AI analysis layer after the rule-based baseline is stable.
