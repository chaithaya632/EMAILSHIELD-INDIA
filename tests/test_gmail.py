import pytest
from unittest.mock import patch, MagicMock
from core.gmail_integration import fetch_recent_emails

@patch('core.gmail_integration.get_gmail_service')
def test_fetch_recent_emails(mock_get_service):
    # Setup mock
    mock_service = MagicMock()
    mock_get_service.return_value = mock_service
    
    # Mock list messages response
    mock_service.users().messages().list().execute.return_value = {
        'messages': [{'id': '123'}]
    }
    
    # Mock get message metadata response
    mock_service.users().messages().get().execute.return_value = {
        'id': '123',
        'snippet': 'Test snippet',
        'payload': {
            'headers': [
                {'name': 'Subject', 'value': 'Test Subject'},
                {'name': 'From', 'value': 'test@example.com'},
                {'name': 'Date', 'value': '2026-09-10'}
            ]
        }
    }
    
    emails = fetch_recent_emails(1)
    assert len(emails) == 1
    assert emails[0]['id'] == '123'
    assert emails[0]['subject'] == 'Test Subject'
    assert emails[0]['sender'] == 'test@example.com'
    assert emails[0]['date'] == '2026-09-10'
