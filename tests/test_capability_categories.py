from bastionsupply import capability_categories
from bastionsupply.models import Tool


def test_categories_are_the_matched_sensitive_kinds():
    t = Tool("fetch_url", "Fetch a URL over https and return the body.")
    assert capability_categories(t) == frozenset({"network"})


def test_email_send_is_email_egress_not_read():
    assert "email-egress" in capability_categories(Tool("send_email", "Send an email."))
    assert "email-egress" not in capability_categories(Tool("list_emails", "List emails."))


def test_benign_tool_has_no_categories():
    assert capability_categories(Tool("add", "Add two numbers.")) == frozenset()


def test_malformed_tool_text_never_crashes():
    assert capability_categories(Tool("", "")) == frozenset()
