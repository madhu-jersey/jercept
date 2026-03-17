"""
Tests for the 6 new fast_extractor patterns added in v0.4.0.

Covers: pull-up billing, account balance/summary/statement,
        file upload, script execution, file write, API call.
"""
from __future__ import annotations

import pytest
from jercept.core.fast_extractor import try_fast_extract


class TestPullUpBillingPatterns:
    """Natural-language billing reads that missed the original pattern."""

    def test_pull_up_billing(self):
        scope = try_fast_extract("pull up billing for account 999")
        assert scope is not None
        assert "db.read" in scope.allowed_actions

    def test_what_is_the_balance(self):
        scope = try_fast_extract("what is the balance for customer abc")
        assert scope is not None
        assert "db.read" in scope.allowed_actions

    def test_give_me_the_billing(self):
        scope = try_fast_extract("give me the billing details")
        assert scope is not None
        assert "db.read" in scope.allowed_actions

    def test_billing_history(self):
        scope = try_fast_extract("show billing history for this account")
        assert scope is not None
        assert "db.read" in scope.allowed_actions

    def test_payment_history(self):
        scope = try_fast_extract("show me the payment history")
        assert scope is not None
        assert "db.read" in scope.allowed_actions


class TestAccountSummaryStatementPatterns:
    """Standalone account/billing summary phrases."""

    def test_account_statement(self):
        scope = try_fast_extract("account statement for user 42")
        assert scope is not None
        assert "db.read" in scope.allowed_actions

    def test_account_balance(self):
        scope = try_fast_extract("account balance please")
        assert scope is not None
        assert "db.read" in scope.allowed_actions

    def test_billing_summary(self):
        scope = try_fast_extract("billing summary for this month")
        assert scope is not None
        assert "db.read" in scope.allowed_actions

    def test_subscription_status(self):
        scope = try_fast_extract("subscription status for customer 7")
        assert scope is not None
        assert "db.read" in scope.allowed_actions

    def test_account_history(self):
        scope = try_fast_extract("account history for the past 3 months")
        assert scope is not None
        assert "db.read" in scope.allowed_actions

    def test_new_billing_patterns_deny_export(self):
        """All new billing patterns must deny export and delete."""
        for req in [
            "account balance",
            "billing summary",
            "account statement",
            "payment summary",
        ]:
            scope = try_fast_extract(req)
            assert scope is not None, f"Expected match for: {req!r}"
            assert "db.export" in scope.denied_actions, f"Missing db.export deny for: {req!r}"
            assert "db.delete" in scope.denied_actions, f"Missing db.delete deny for: {req!r}"


class TestFileUploadPattern:
    """File upload requests."""

    def test_upload_file(self):
        scope = try_fast_extract("upload the CSV file to the system")
        assert scope is not None
        assert "file.upload" in scope.allowed_actions

    def test_attach_document(self):
        scope = try_fast_extract("attach this document to the ticket")
        assert scope is not None
        assert "file.upload" in scope.allowed_actions

    def test_import_spreadsheet(self):
        scope = try_fast_extract("import the spreadsheet from my desktop")
        assert scope is not None
        assert "file.upload" in scope.allowed_actions

    def test_submit_pdf(self):
        scope = try_fast_extract("submit the PDF form")
        assert scope is not None
        assert "file.upload" in scope.allowed_actions

    def test_upload_denies_download(self):
        scope = try_fast_extract("upload the csv file")
        assert scope is not None
        assert "file.download" in scope.denied_actions


class TestScriptExecutionPattern:
    """Script / job execution requests."""

    def test_run_script(self):
        scope = try_fast_extract("run the migration script")
        assert scope is not None
        assert "code.execute" in scope.allowed_actions

    def test_execute_command(self):
        scope = try_fast_extract("execute the cleanup command")
        assert scope is not None
        assert "code.execute" in scope.allowed_actions

    def test_trigger_pipeline(self):
        scope = try_fast_extract("trigger the deployment pipeline")
        assert scope is not None
        assert "code.execute" in scope.allowed_actions

    def test_launch_job(self):
        scope = try_fast_extract("launch the nightly batch job")
        assert scope is not None
        assert "code.execute" in scope.allowed_actions

    def test_script_denies_export(self):
        scope = try_fast_extract("run the backup script")
        assert scope is not None
        assert "db.export" in scope.denied_actions


class TestFileWritePattern:
    """File write / creation requests."""

    def test_write_file(self):
        scope = try_fast_extract("write the output to a file")
        assert scope is not None
        assert "file.write" in scope.allowed_actions

    def test_save_report(self):
        scope = try_fast_extract("save the analysis report")
        assert scope is not None
        assert "file.write" in scope.allowed_actions

    def test_create_csv(self):
        scope = try_fast_extract("create a CSV file with the results")
        assert scope is not None
        assert "file.write" in scope.allowed_actions

    def test_generate_pdf(self):
        scope = try_fast_extract("generate a PDF document from the data")
        assert scope is not None
        assert "file.write" in scope.allowed_actions


class TestApiCallPattern:
    """External API / service call requests."""

    def test_call_api(self):
        scope = try_fast_extract("call the payment API with this order")
        assert scope is not None
        assert "api.call" in scope.allowed_actions

    def test_invoke_endpoint(self):
        scope = try_fast_extract("invoke the webhook endpoint")
        assert scope is not None
        assert "api.call" in scope.allowed_actions

    def test_query_service(self):
        scope = try_fast_extract("query the external service for status")
        assert scope is not None
        assert "api.call" in scope.allowed_actions

    def test_hit_rest_endpoint(self):
        scope = try_fast_extract("hit the REST endpoint with these params")
        assert scope is not None
        assert "api.call" in scope.allowed_actions

    def test_api_denies_db_delete(self):
        scope = try_fast_extract("call the graphql api")
        assert scope is not None
        assert "db.delete" in scope.denied_actions


class TestAmbiguousStillReturnsNone:
    """Ambiguous requests must still return None even after new patterns."""

    def test_help_me(self):
        assert try_fast_extract("help me") is None

    def test_do_the_thing(self):
        assert try_fast_extract("do the thing") is None

    def test_fix_it(self):
        assert try_fast_extract("fix it") is None

    def test_check_it(self):
        assert try_fast_extract("check it") is None
