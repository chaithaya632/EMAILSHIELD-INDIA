import os.path
import base64
from typing import List, Dict, Any, Optional
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CREDENTIALS_PATH = 'credentials.json'
TOKEN_PATH = 'token.json'

def get_gmail_service():
    """Authenticates the user and returns the Gmail service object."""
    creds = None
    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(CREDENTIALS_PATH):
                raise FileNotFoundError(f"Missing '{CREDENTIALS_PATH}'. Please download it from Google Cloud Console.")
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_PATH, SCOPES)
            creds = flow.run_local_server(port=0)
        
        with open(TOKEN_PATH, 'w') as token:
            token.write(creds.to_json())
            
    return build('gmail', 'v1', credentials=creds)

def fetch_recent_emails(max_results: int = 100, query: str = None) -> List[Dict[str, str]]:
    """Fetches a list of recent emails with basic metadata."""
    try:
        service = get_gmail_service()
        limit = 500 if (not max_results or max_results <= 0) else min(max_results, 500)
        kwargs = {'userId': 'me', 'labelIds': ['INBOX'], 'maxResults': limit}
        if query:
            kwargs['q'] = query
        results = service.users().messages().list(**kwargs).execute()
        messages = results.get('messages', [])
        
        email_list = []
        for msg in messages:
            msg_id = msg['id']
            msg_obj = service.users().messages().get(userId='me', id=msg_id, format='metadata', metadataHeaders=['Subject', 'From', 'Date']).execute()
            
            headers = msg_obj.get('payload', {}).get('headers', [])
            subject = "No Subject"
            sender = "Unknown Sender"
            date = "Unknown Date"
            
            for h in headers:
                if h['name'].lower() == 'subject':
                    subject = h['value']
                elif h['name'].lower() == 'from':
                    sender = h['value']
                elif h['name'].lower() == 'date':
                    date = h['value']
            
            email_list.append({
                "id": msg_id,
                "snippet": msg_obj.get('snippet', ''),
                "subject": subject,
                "sender": sender,
                "date": date
            })
        return email_list
    except Exception as e:
        raise Exception(f"Failed to fetch emails: {str(e)}")

def fetch_raw_email(msg_id: str) -> bytes:
    """Fetches the raw .eml bytes of a specific email by ID."""
    try:
        service = get_gmail_service()
        message = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
        msg_raw = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))
        return msg_raw
    except Exception as e:
        raise Exception(f"Failed to fetch raw email: {str(e)}")
