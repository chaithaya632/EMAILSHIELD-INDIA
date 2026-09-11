from core.parser import SecureEmailParser
import pytest

def test_parser_clean():
    eml = b"""From: test@test.com
Subject: Hello
Content-Type: text/plain

World"""
    parser = SecureEmailParser(eml)
    data = parser.parse()
    
    assert data["headers"].get("subject") == "Hello"
    assert "World" in data["body"]
    assert len(data["attachments"]) == 0
    assert "sha256" in data

def test_parser_attachment():
    eml = b"""From: a@a.com
Subject: File
Content-Type: multipart/mixed; boundary="sep"

--sep
Content-Type: text/plain

Hi
--sep
Content-Type: text/plain
Content-Disposition: attachment; filename="test.txt"

data
--sep--"""
    parser = SecureEmailParser(eml)
    data = parser.parse()
    
    assert len(data["attachments"]) == 1
    assert data["attachments"][0]["filename"] == "test.txt"
