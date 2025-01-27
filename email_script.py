import os
import time
import json
import base64
import email
from email.mime.text import MIMEText
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from email.header import decode_header
from tabulate import tabulate

# Gmail API Scopes
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# Busy status flag (Set to True when busy)
BUSY_STATUS = True  

# Email Priority Rules
HIGH_PRIORITY = ["urgent", "asap", "important"]
MEDIUM_PRIORITY = ["follow-up", "reminder"]

# Gmail labels to exclude from auto-replies
EXCLUDE_LABELS = ["CATEGORY_PROMOTIONS", "CATEGORY_SOCIAL"]

# File to store replied email IDs
REPLIED_EMAILS_FILE = "replied_emails.json"

# Load OAuth credentials
def get_credentials():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds

# Authenticate and connect to Gmail API
def connect_email():
    creds = get_credentials()
    service = build("gmail", "v1", credentials=creds)
    return service

# Load replied email IDs
def load_replied_emails():
    if os.path.exists(REPLIED_EMAILS_FILE):
        with open(REPLIED_EMAILS_FILE, "r") as file:
            return json.load(file)
    return []

# Save replied email IDs
def save_replied_emails(replied_emails):
    with open(REPLIED_EMAILS_FILE, "w") as file:
        json.dump(replied_emails, file)

# Classify Emails
def classify_email(subject):
    subject_lower = subject.lower()
    if any(word in subject_lower for word in HIGH_PRIORITY):
        return "High"
    elif any(word in subject_lower for word in MEDIUM_PRIORITY):
        return "Medium"
    return "Low"

# Fetch unread emails and classify them
def check_emails():
    service = connect_email()
    results = service.users().messages().list(userId="me", labelIds=["INBOX"], q="is:unread").execute()
    messages = results.get("messages", [])
    
    email_data = []
    replied_emails = load_replied_emails()  # Load previously replied emails

    for msg in messages:
        msg_id = msg["id"]
        msg_data = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
        headers = msg_data["payload"]["headers"]

        subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
        sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown Sender")

        # Check the labels of the email
        labels = msg_data.get("labelIds", [])

        # Skip auto-reply for promotions or social emails
        if any(label in labels for label in EXCLUDE_LABELS):
            print(f"Skipping email from {sender} due to label {labels}")
            continue  

        # Classify email priority
        priority = classify_email(subject)
        
        # Add email details to the table data list
        email_data.append([sender, subject, priority])

        # Check if we have already replied to this email
        if msg_id not in replied_emails:
            # Send auto-reply if busy and the email is low priority
            if BUSY_STATUS and priority == "Low":
                send_auto_reply(sender)
                replied_emails.append(msg_id)  # Mark this email as replied

    # Save updated replied emails
    save_replied_emails(replied_emails)

    # Display the email data in a table
    if email_data:
        print("\nUnread Emails:")
        headers = ["Sender", "Subject", "Priority"]
        print(tabulate(email_data, headers, tablefmt="grid"))
    else:
        print("No unread emails.")

# Send an auto-reply when busy
def send_auto_reply(to_email):
    service = connect_email()
    message = MIMEText("Thank you for your email. I am currently busy and will respond as soon as possible.")
    message["to"] = to_email
    message["subject"] = "Re: Auto Response"
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

    try:
        service.users().messages().send(userId="me", body={"raw": raw_message}).execute()
        print(f"Auto-reply sent to {to_email}")
    except Exception as e:
        print(f"Error sending auto-reply: {e}")

# Run the email checker in an infinite loop
def run_continuously():
    try:
        while True:
            print("Checking for new emails...")
            check_emails()
            print("Waiting for 1 minute before checking again...\n")
            time.sleep(60)  # Wait for 1 minute before checking again
    except KeyboardInterrupt:
        print("\nEmail checker stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
        run_continuously()  # Retry if error occurs

# Run the email checker
if __name__ == "__main__":
    run_continuously()
