from core.gmail_integration import get_gmail_service

print("Starting Gmail OAuth flow...")
try:
    service = get_gmail_service()
    print("Successfully authenticated! You can now close this window and use the Streamlit app.")
except Exception as e:
    print(f"Error during authentication: {e}")
