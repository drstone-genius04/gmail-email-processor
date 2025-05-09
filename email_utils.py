"""
Utility functions for authenticating Gmail API and retrieving email metadata.

Import as:

    import utils.email_utils as eutemutls
"""

import os
import base64
import logging
import re
from typing import List, Set, Dict, Optional

import pandas as pd
from bs4 import BeautifulSoup
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
_TOKEN_PATH = "token.json"
_CREDENTIALS_PATH = "credentials.json"


def authenticate_gmail() -> object:
    """
    Authenticate user and return Gmail API service.

    :return: authenticated Gmail API service
    """
    creds = None
    if os.path.exists(_TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(_TOKEN_PATH, _SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(_CREDENTIALS_PATH, _SCOPES)
            creds = flow.run_local_server(port=0)
        with open(_TOKEN_PATH, "w") as token_file:
            token_file.write(creds.to_json())
    return build("gmail", "v1", credentials=creds)


def fetch_emails(
    service: object,
    query: str,
    max_results: int = 100,
    total_limit: Optional[int] = None,
) -> pd.DataFrame:
    """
    Fetch emails matching the query and return a DataFrame.

    :param service: Gmail API service
    :param query: Gmail search query
    :param max_results: maximum results per API call
    :param total_limit: overall result limit
    :return: DataFrame with email metadata
    """
    messages = []
    next_page_token = None

    while True:
        response = service.users().messages().list(
            userId="me",
            q=query,
            maxResults=max_results,
            pageToken=next_page_token,
        ).execute()

        messages.extend(response.get("messages", []))

        if total_limit and len(messages) >= total_limit:
            messages = messages[:total_limit]
            break

        next_page_token = response.get("nextPageToken")
        if not next_page_token:
            break

    data = []
    for msg in messages:
        email_data = get_email_details(service, msg["id"])
        if email_data:
            data.append(email_data)

    return pd.DataFrame(data)


def get_email_details(service: object, msg_id: str) -> Optional[Dict[str, str]]:
    """
    Retrieve sender, subject, date, and body for a given message.

    :param service: Gmail API service
    :param msg_id: Gmail message ID
    :return: dictionary with email metadata
    """
    try:
        msg_data = service.users().messages().get(
            userId="me", id=msg_id, format="full"
        ).execute()
        headers = msg_data["payload"].get("headers", [])

        email_data = {
            "Sender": "",
            "Subject": "",
            "Date": "",
            "Body": "",
        }

        for header in headers:
            name = header.get("name", "").lower()
            if name == "from":
                email_data["Sender"] = header.get("value", "")
            elif name == "subject":
                email_data["Subject"] = header.get("value", "")
            elif name == "date":
                email_data["Date"] = header.get("value", "")

        # Extract the email body
        email_data["Body"] = _extract_email_body(msg_data["payload"])

        return email_data

    except HttpError as e:
        _LOG.warning("Failed to retrieve message %s: %s", msg_id, str(e))
        return None


def _extract_email_body(payload: Dict) -> str:
    """
    Extract text/plain or text/html email body from payload.

    :param payload: Gmail message payload
    :return: decoded email body text
    """
    if "parts" in payload:
        for part in payload["parts"]:
            mime_type = part.get("mimeType", "")
            data = part.get("body", {}).get("data")
            if data:
                content = base64.urlsafe_b64decode(data).decode(errors="ignore")
                if mime_type == "text/plain":
                    return content
                elif mime_type == "text/html":
                    return BeautifulSoup(content, "html.parser").get_text()
    elif payload.get("body", {}).get("data"):
        return base64.urlsafe_b64decode(payload["body"]["data"]).decode(errors="ignore")
    return ""


def extract_email_addresses(df: pd.DataFrame) -> Set[str]:
    """
    Extract unique email addresses from the Sender and Body columns.

    :param df: DataFrame with Sender and Body columns
    :return: set of email addresses
    """
    addresses = set()
    for _, row in df.iterrows():
        sender_match = re.findall(r"[\w\.-]+@[\w\.-]+", row.get("Sender", ""))
        body_match = re.findall(r"[\w\.-]+@[\w\.-]+", row.get("Body", ""))
        addresses.update(sender_match)
        addresses.update(body_match)
    return addresses
