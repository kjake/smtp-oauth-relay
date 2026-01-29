import base64
import logging
from email import policy
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

import requests

from config import HTTP_TIMEOUT_SECONDS

GRAPH_MIME_CONTENT_TYPE = "text/plain"


def send_email(
    access_token: str,
    body: bytes,
    from_email: str
) -> tuple[bool, str | None, int | None]:
    url = f"https://graph.microsoft.com/v1.0/users/{from_email}/sendMail"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": GRAPH_MIME_CONTENT_TYPE
    }

    try:
        data = base64.b64encode(body)
        logging.debug(f"Sending email from {from_email}")

        response = requests.post(url, data=data, headers=headers, timeout=HTTP_TIMEOUT_SECONDS)
        if response.status_code == 202:
            logging.info("Email sent successfully!")
            return True, None, response.status_code
        error_detail = f"Status code {response.status_code}; response body: {response.text}"
        logging.error(f"Failed to send email: {error_detail}")
        return False, error_detail, response.status_code
    except Exception as e:
        logging.exception(f"Exception while sending email: {str(e)}")
        return False, str(e), None


def send_failure_notification(
    access_token: str,
    from_email: str,
    notification_address: str,
    parsed_message,
    envelope,
    error_detail: str | None
) -> None:
    subject_value = parsed_message.get("Subject")
    subject = "SMTP relay failure"
    if subject_value:
        subject = f"{subject}: {subject_value}"

    body_lines = [
        "SMTP OAuth Relay failed to send a message.",
        f"Error: {error_detail or 'Unknown error'}",
    ]

    from_header = parsed_message.get("From")
    to_header = parsed_message.get("To")
    message_id = parsed_message.get("Message-ID")
    envelope_from = envelope.mail_from
    recipients = ", ".join(envelope.rcpt_tos or [])

    if from_header:
        body_lines.append(f"Original From: {from_header}")
    if envelope_from:
        body_lines.append(f"Envelope From: {envelope_from}")
    if to_header:
        body_lines.append(f"To: {to_header}")
    if recipients:
        body_lines.append(f"Recipients: {recipients}")
    if subject_value:
        body_lines.append(f"Subject: {subject_value}")
    if message_id:
        body_lines.append(f"Message-ID: {message_id}")

    message = EmailMessage()
    message["From"] = from_email
    message["To"] = notification_address
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(
        domain=from_email.split("@")[-1] if "@" in from_email else None
    )
    message.set_content("\n".join(body_lines))

    success, notification_error, _ = send_email(
        access_token=access_token,
        body=message.as_bytes(policy=policy.SMTP),
        from_email=from_email
    )
    if not success:
        logging.error(
            "Failed to send failure notification to %s: %s",
            notification_address,
            notification_error or "Unknown error"
        )
