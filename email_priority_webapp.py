from flask import Flask, render_template, request, jsonify
import os
import time
import json
import base64
import threading
from email.mime.text import MIMEText
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import re
import nltk
from nltk.tokenize import sent_tokenize
from nltk.corpus import stopwords
from collections import Counter

# Download necessary NLTK data
nltk.download("punkt")
nltk.download('punkt_tab')
nltk.download("stopwords")

app = Flask(__name__)

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
EXCLUDE_LABELS = ["CATEGORY_PROMOTIONS", "CATEGORY_SOCIAL"]
REPLIED_EMAILS_FILE = "replied_emails.json"
BUSY_STATUS = True  # Default: Not busy

def get_credentials():
    creds = None
    if not os.path.exists("credentials.json"):
        print("ERROR: 'credentials.json' file is missing!")
        return None

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

def connect_email():
    creds = get_credentials()
    if not creds:
        print("ERROR: Failed to authenticate with Google API.")
        return None
    return build("gmail", "v1", credentials=creds)

def load_replied_emails():
    if os.path.exists(REPLIED_EMAILS_FILE):
        with open(REPLIED_EMAILS_FILE, "r") as file:
            return json.load(file)
    return []

def save_replied_emails(replied_emails):
    with open(REPLIED_EMAILS_FILE, "w") as file:
        json.dump(replied_emails, file)

def classify_email(subject):
    high_priority = ["urgent", "asap", "important"]
    medium_priority = ["follow-up", "reminder"]
    subject_lower = subject.lower()
    if any(word in subject_lower for word in high_priority):
        return "High"
    elif any(word in subject_lower for word in medium_priority):
        return "Medium"
    return "Low"


def extract_key_points(email_body):
    """Extracts important points from an email. Uses keyword extraction and summarization."""
    important_sentences = []
    
    # Keywords indicating important info
    keywords = ["important", "urgent", "deadline", "please note", "action required", "asap"]
    
    # Split body into sentences
    sentences = sent_tokenize(email_body)

    # Step 1: Check for keyword-based extraction
    for sentence in sentences:
        if any(keyword in sentence.lower() for keyword in keywords):
            important_sentences.append(sentence.strip())

    # Step 2: If no important sentences found, summarize the email
    if not important_sentences:
        important_sentences = summarize_text(sentences)

    return " ".join(important_sentences)[:100]  # Limit to 100 characters


def summarize_text(sentences):
    """Summarizes the email content by selecting the most informative sentences."""
    if not sentences:
        return ["No content available"]

    stop_words = set(stopwords.words("english"))

    # Tokenize words and remove stopwords
    words = [word.lower() for sent in sentences for word in sent.split() if word.lower() not in stop_words]
    
    # Frequency distribution of words
    word_freq = Counter(words)

    # Score sentences based on word importance
    sentence_scores = {}
    for sent in sentences:
        for word in sent.split():
            if word.lower() in word_freq:
                if sent not in sentence_scores:
                    sentence_scores[sent] = word_freq[word.lower()]
                else:
                    sentence_scores[sent] += word_freq[word.lower()]
    
    # Sort sentences by importance and select top 2
    top_sentences = sorted(sentence_scores, key=sentence_scores.get, reverse=True)[:2]
    
    return top_sentences

def check_emails():
    global BUSY_STATUS
    service = connect_email()
    if not service:
        print("ERROR: Email service not connected.")
        return []

    try:
        results = service.users().messages().list(userId="me", labelIds=["INBOX"], q="is:unread").execute()
        messages = results.get("messages", [])
    except Exception as e:
        print(f"ERROR: Failed to fetch emails - {e}")
        return []

    email_data = []
    replied_emails = load_replied_emails()

    for msg in messages:
        try:
            msg_id = msg["id"]
            msg_data = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
            headers = msg_data["payload"]["headers"]

            subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
            sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown Sender")

            # Extract snippet (email body preview)
            email_body = msg_data.get("snippet", "")
            key_points = extract_key_points(email_body)  # Extract key points or summary

            labels = msg_data.get("labelIds", [])
            if any(label in labels for label in EXCLUDE_LABELS):
                continue  

            priority = classify_email(subject)
            email_data.append({
                "sender": sender,
                "subject": subject,
                "priority": priority,
                "preview": key_points  # Show meaningful summary
            })

            if msg_id not in replied_emails and BUSY_STATUS and priority == "Low":
                send_auto_reply(sender)
                replied_emails.append(msg_id)

        except Exception as e:
            print(f"ERROR: Failed to process email {msg_id} - {e}")

    save_replied_emails(replied_emails)
    return email_data


def send_auto_reply(to_email):
    service = connect_email()
    if not service:
        print("ERROR: Cannot send auto-reply, email service not connected.")
        return

    try:
        message = MIMEText("Thank you for your email. I am currently busy and will respond as soon as possible.")
        message["to"] = to_email
        message["subject"] = "Re: Auto Response"
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        service.users().messages().send(userId="me", body={"raw": raw_message}).execute()
    except Exception as e:
        print(f"ERROR: Failed to send auto-reply to {to_email} - {e}")

def run_email_checker():
    while True:
        check_emails()
        time.sleep(60)

@app.route('/')
def index():
    emails = check_emails()
    return render_template('index.html', emails=emails, busy=BUSY_STATUS)

@app.route('/toggle-busy', methods=['POST'])
def toggle_busy():
    global BUSY_STATUS
    BUSY_STATUS = not BUSY_STATUS
    return jsonify({"status": "success", "busy": BUSY_STATUS})

if __name__ == '__main__':
    threading.Thread(target=run_email_checker, daemon=True).start()
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
