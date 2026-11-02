import importlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient


class ClearanceSmokeTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "clearance-test.db")

        os.environ["DB_PATH"] = self.db_path
        os.environ["JWT_SECRET_KEY"] = "test-secret-not-for-production-0123456789"
        os.environ["BOT_COMM_PASSWORD"] = "test-bot-comm-password"
        os.environ.pop("TRAFFIC_BOARD_PASSWORD", None)
        os.environ.pop("TRAFFIC_KNOWN_USERS", None)
        os.environ.pop("AGENT_OUTREACH_TARGETS", None)
        os.environ["LEDGER_TOOLS_ENABLED"] = "true"
        os.environ["LEDGER_USERS_JSON"] = json.dumps([
            {
                "username": "ada_operator",
                "display_name": "Ada Operator",
                "passcode": "test-pass-ada",
                "role": "operator",
            },
            {
                "username": "ben_operator",
                "display_name": "Ben Operator",
                "passcode": "test-pass-ben",
                "role": "operator",
            },
        ])
        os.environ.pop("FAMILY_HOUSEHOLD_NAME", None)
        os.environ.pop("FAMILY_JUSTIN_PASSCODE", None)
        os.environ.pop("FAMILY_NICOLE_PASSCODE", None)
        os.environ["BASE_URL"] = "http://localhost:8000"
        os.environ["TOKEN_ISSUER"] = "http://localhost:8000"
        os.environ.pop("PUBLIC_BASE_URL", None)
        os.environ.pop("TEST_PRICE_USD", None)
        os.environ.pop("CDP_API_KEY_ID", None)
        os.environ.pop("CDP_API_KEY_SECRET", None)
        os.environ.pop("X402_FACILITATOR_URL", None)
        os.environ.pop("ADMIN_TOKEN", None)
        os.environ.pop("AGENT_INCOME_OPERATOR_ENABLED", None)
        os.environ.pop("AGENT_INCOME_PUBLIC_LEAD_DISCOVERY_ENABLED", None)
        os.environ.pop("AGENT_INCOME_AUTO_DEAL_LEADS", None)
        os.environ["BRAND_URL"] = "https://nauti-labs.com"
        os.environ["PAYMENT_WALLET"] = "0x0000000000000000000000000000000000000001"
        os.environ["PAYMENT_ENS"] = "example.base.eth"
        os.environ["USDC_CONTRACT"] = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
        os.environ["PAYMENT_SUPPORT_EMAIL"] = "consulting@nauti-labs.com"
        os.environ["ADMIN_EMAIL"] = "consulting@nauti-labs.com"
        os.environ["SIGNUP_NOTIFY_EMAIL"] = ""
        os.environ["WELCOME_EMAILS_ENABLED"] = "false"
        os.environ.pop("BOT_BUILD_REQUEST_URL", None)
        for mail_env in (
            "EMAIL_FROM",
            "SMTP_HOST",
            "SMTP_PORT",
            "SMTP_USER",
            "SMTP_PASSWORD",
            "SMTP_USE_TLS",
            "SMTP_USE_SSL",
        ):
            os.environ.pop(mail_env, None)
        os.environ["MIN_CONFIRMATIONS"] = "12"
        os.environ.pop("STRIPE_SECRET_KEY", None)
        os.environ.pop("STRIPE_WEBHOOK_SECRET", None)
        os.environ["TELEGRAM_BOT_TOKEN"] = ""
        os.environ["TELEGRAM_CHAT_ID"] = ""
        os.environ["TELEGRAM_WEBHOOK_SECRET"] = ""
        os.environ["FAMILY_SYNC_TOKEN"] = "sync-secret"
        os.environ["NAUTI_TRAFFIC_ADMIN_PIN"] = "123456"
        os.environ["NAUTI_TRAFFIC_ADMIN_PATH_TOKEN"] = "test_admin_secret_123456"

        self.database = importlib.import_module("database")
        self.database = importlib.reload(self.database)
        self.app_module = importlib.import_module("app")
        self.app_module = importlib.reload(self.app_module)

    def tearDown(self):
        self.temp_dir.cleanup()

    def login_family(self, client: TestClient, username: str = "ada_operator", passcode: str = "test-pass-ada"):
        response = client.post(
            "/family/api/login",
            json={"username": username, "passcode": passcode},
        )
        self.assertEqual(response.status_code, 200)
        return response

    def test_payment_info_uses_runtime_config(self):
        with TestClient(self.app_module.app) as client:
            response = client.get("/v1/payments/info")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["wallet"]["address"], os.environ["PAYMENT_WALLET"])
        self.assertEqual(payload["wallet"]["ens"], os.environ["PAYMENT_ENS"])
        self.assertEqual(payload["verification"]["min_confirmations"], 12)
        self.assertEqual(payload["verification"]["manual_release_required"], False)
        self.assertEqual(payload["verification"]["checkout_mode"], "stripe_checkout_or_self_serve_usdc_on_base")
        self.assertEqual(payload["checkout_policy"]["card_checkout"], "not_configured")
        self.assertIn("consulting@nauti-labs.com", payload["refunds"])

    def test_stripe_checkout_requires_configuration(self):
        with TestClient(self.app_module.app) as client:
            response = client.post(
                "/v1/payments/stripe/checkout",
                json={"email": "buyer@example.com", "tier": "pro"},
            )

        self.assertEqual(response.status_code, 503)
        self.assertIn("Stripe card checkout is not connected", response.json()["detail"])

    def test_nauti_traffic_titlecase_route_serves_dashboard(self):
        with TestClient(self.app_module.app) as client:
            response = client.get("/Nauti-Traffic")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Nauti-Traffic", response.text)
        self.assertIn("Ambassador Leaderboard", response.text)

    def test_landing_page_links_to_tutorial_and_bot_build_request(self):
        with TestClient(self.app_module.app) as client:
            response = client.get("/", headers={"host": "localhost:8000"})
            scram = client.get("/scram")
            market = client.get("/bot-comm/market")

        self.assertEqual(response.status_code, 200)
        self.assertIn('href="/tutorial"', response.text)
        self.assertNotIn("scam_check.html", response.text)
        self.assertEqual(scram.status_code, 200)
        self.assertIn("SCRAM scam check", scram.text)
        self.assertEqual(market.status_code, 200)
        self.assertIn("Bot-Comm market", market.text)
        self.assertIn("Request a trading bot build", response.text)
        self.assertIn("$125/hr", response.text)
        self.assertIn("10-hour minimum", response.text)

    def test_tutorial_page_serves_bot_integration_guide(self):
        with TestClient(self.app_module.app) as client:
            response = client.get("/tutorial")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Add Clearance to your bot", response.text)
        self.assertIn("/static/tutorial/01-create-clearance.png", response.text)
        self.assertIn("/static/tutorial/02-human-approval.png", response.text)
        self.assertIn("/static/tutorial/03-verify-token.png", response.text)
        self.assertIn("$125/hr", response.text)
        self.assertIn("10-hour minimum", response.text)
        self.assertIn("/v1/docs", response.text)

    def test_nauti_traffic_admin_updates_display_config(self):
        admin_path = "/nauti-traffic/admin/test_admin_secret_123456"
        with TestClient(self.app_module.app) as client:
            locked = client.get("/nauti-traffic/admin")
            old_login = client.post(
                "/nauti-traffic/admin/login",
                data={"pin": "123456"},
                follow_redirects=False,
            )
            wrong_secret = client.get("/nauti-traffic/admin/wrong_secret_12345")
            wrong_secret_post = client.post(
                "/nauti-traffic/admin/wrong_secret_12345/affiliate",
                data={"ref": "north_pier"},
                follow_redirects=False,
            )
            secret_locked = client.get(admin_path)
            bad_login = client.post(
                f"{admin_path}/login",
                data={"pin": "000000"},
                follow_redirects=False,
            )
            login = client.post(
                f"{admin_path}/login",
                data={"pin": "123456"},
                follow_redirects=False,
            )
            unlocked = client.get(admin_path)
            saved = client.post(
                f"{admin_path}/affiliate",
                data={"ref": "north_pier", "badge": "none", "avatar_url": "", "x_handle": "north_pier"},
                follow_redirects=False,
            )
            captain_saved = client.post(
                f"{admin_path}/affiliate",
                data={"ref": "second_captain", "badge": "captain", "avatar_url": "", "x_handle": ""},
                follow_redirects=False,
            )
            alias = client.post(
                f"{admin_path}/alias",
                data={"alias": "northpier", "target": "north_pier"},
                follow_redirects=False,
            )
            hidden = client.post(
                f"{admin_path}/hide",
                data={"ref": "telegram", "action": "hide"},
                follow_redirects=False,
            )
            pretty_alias = client.get("/r/northpier", follow_redirects=False)
            vanity_alias = client.get("/northpier", follow_redirects=False)
            captain_vanity = client.get("/second_captain", follow_redirects=False)
            unknown_vanity = client.get("/not_configured", follow_redirects=False)
            health = client.get("/health")
            config = client.get("/v1/traffic/config")

        self.assertEqual(locked.status_code, 404)
        self.assertEqual(old_login.status_code, 404)
        self.assertEqual(wrong_secret.status_code, 404)
        self.assertEqual(wrong_secret_post.status_code, 404)
        self.assertEqual(secret_locked.status_code, 200)
        self.assertIn("PIN Required", secret_locked.text)
        self.assertEqual(bad_login.status_code, 303)
        self.assertEqual(login.status_code, 303)
        self.assertIn("nauti_traffic_admin_v2", login.headers.get("set-cookie", ""))
        self.assertIn("nauti_traffic_admin=", login.headers.get("set-cookie", ""))
        self.assertIn("Path=/nauti-traffic/admin/", login.headers.get("set-cookie", ""))
        self.assertEqual(secret_locked.headers.get("cache-control"), "no-store, no-cache, must-revalidate, max-age=0")
        self.assertEqual(login.headers.get("location"), admin_path)
        self.assertEqual(unlocked.status_code, 200)
        self.assertIn("Affiliate Control", unlocked.text)
        self.assertIn(f'action="{admin_path}/affiliate"', unlocked.text)
        self.assertEqual(saved.status_code, 303)
        self.assertEqual(captain_saved.status_code, 303)
        self.assertEqual(alias.status_code, 303)
        self.assertEqual(hidden.status_code, 303)
        self.assertEqual(pretty_alias.status_code, 302)
        self.assertIn("clearance_ref=north_pier", pretty_alias.headers.get("set-cookie", ""))
        self.assertEqual(vanity_alias.status_code, 302)
        self.assertIn("clearance_ref=north_pier", vanity_alias.headers.get("set-cookie", ""))
        self.assertEqual(captain_vanity.status_code, 302)
        self.assertIn("clearance_ref=second_captain", captain_vanity.headers.get("set-cookie", ""))
        self.assertEqual(unknown_vanity.status_code, 404)
        self.assertEqual(health.status_code, 200)
        payload = config.json()
        self.assertEqual(payload["captain"], "harbor_captain")
        self.assertIn("harbor_captain", payload["captains"])
        self.assertIn("cove_mate", payload["captains"])
        self.assertIn("second_captain", payload["captains"])
        self.assertEqual(payload["avatar_urls"]["cove_mate"], "/static/logos/stamp.svg")
        self.assertNotIn("north_pier", payload["first_mates"])
        self.assertLessEqual(len(payload["first_mates"]), 10)
        self.assertEqual(payload["ref_aliases"]["northpier"], "north_pier")
        self.assertIn("telegram", payload["hidden_refs"])
        self.assertEqual(payload["avatar_overrides"]["north_pier"], "north_pier")

    def test_paid_tier_fulfillment_issues_key_and_is_idempotent(self):
        import asyncio

        async def fulfill_twice():
            with TestClient(self.app_module.app):
                first = await self.app_module.fulfill_paid_tier(
                    email="paid@example.com",
                    tier="pro",
                    amount=19.0,
                    currency="USD",
                    provider="stripe",
                    provider_ref="cs_test_123",
                    metadata={"test": True},
                )
                second = await self.app_module.fulfill_paid_tier(
                    email="paid@example.com",
                    tier="pro",
                    amount=19.0,
                    currency="USD",
                    provider="stripe",
                    provider_ref="cs_test_123",
                    metadata={"test": True},
                )
            return first, second

        first, second = asyncio.run(fulfill_twice())

        self.assertEqual(first["status"], "verified")
        self.assertTrue(first["api_key"].startswith("clr_live_"))
        self.assertEqual(first["tier"], "pro")
        self.assertEqual(second["status"], "already_fulfilled")

    def test_init_db_migrates_payments_metadata_column(self):
        with TestClient(self.app_module.app):
            pass

        async def fetch_columns():
            db = await self.database.get_db()
            try:
                cursor = await db.execute("PRAGMA table_info(payments)")
                return [row[1] for row in await cursor.fetchall()]
            finally:
                await db.close()

        import asyncio

        columns = asyncio.run(fetch_columns())
        self.assertIn("metadata", columns)

    def test_duplicate_free_key_email_is_rejected(self):
        with TestClient(self.app_module.app) as client:
            first = client.post("/v1/keys", json={"email": "builder@example.com"})
            second = client.post("/v1/keys", json={"email": "builder@example.com"})

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 409)
        self.assertIn("already exists", second.json()["detail"])

    def test_free_key_signup_sends_admin_and_optional_welcome_email(self):
        self.app_module.SIGNUP_NOTIFY_EMAIL = "consulting@nauti-labs.com"
        self.app_module.WELCOME_EMAILS_ENABLED = True

        with patch.object(self.app_module, "send_email", new_callable=AsyncMock) as send_email:
            send_email.return_value = True
            with TestClient(self.app_module.app) as client:
                response = client.post(
                    "/v1/keys",
                    json={"email": "Builder@Example.com", "name": "Casey"},
                )

        self.assertEqual(response.status_code, 200)
        raw_key = response.json()["api_key"]
        self.assertEqual(send_email.await_count, 2)

        admin_call = send_email.await_args_list[0].args
        self.assertEqual(admin_call[0], "consulting@nauti-labs.com")
        self.assertIn("New Clearance free signup", admin_call[1])
        self.assertIn("builder@example.com", admin_call[2])
        self.assertIn("Casey", admin_call[2])
        self.assertNotIn(raw_key, admin_call[2])

        welcome_call = send_email.await_args_list[1].args
        self.assertEqual(welcome_call[0], "builder@example.com")
        self.assertIn("starter key is live", welcome_call[1])
        self.assertIn("human approval layer", welcome_call[2])
        self.assertIn("we do not email API keys", welcome_call[2])
        self.assertIn("your clearance layer is live", welcome_call[3])
        self.assertIn("&gt;&gt;&gt;", welcome_call[3])
        self.assertNotIn(raw_key, welcome_call[2])
        self.assertNotIn(raw_key, welcome_call[3])

    def test_free_key_signup_rejects_invalid_email(self):
        with TestClient(self.app_module.app) as client:
            response = client.post("/v1/keys", json={"email": "not-an-email"})

        self.assertEqual(response.status_code, 400)
        self.assertIn("valid email", response.json()["detail"])

    def test_free_key_signup_rate_limit_applies_per_ip(self):
        with TestClient(self.app_module.app) as client:
            for idx in range(5):
                response = client.post(
                    "/v1/keys",
                    json={"email": f"builder{idx}@example.com"},
                    headers={"x-forwarded-for": "203.0.113.55"},
                )
                self.assertEqual(response.status_code, 200)

            blocked = client.post(
                "/v1/keys",
                json={"email": "builder-final@example.com"},
                headers={"x-forwarded-for": "203.0.113.55"},
            )

        self.assertEqual(blocked.status_code, 429)
        self.assertIn("Too many free key signups", blocked.json()["detail"])

    def test_clearance_approval_page_uses_same_origin_decision_post(self):
        with TestClient(self.app_module.app) as client:
            key_response = client.post("/v1/keys", json={"email": "approval@example.com"})
            headers = {"X-API-Key": key_response.json()["api_key"]}
            clearance = client.post(
                "/v1/clearances",
                headers=headers,
                json={
                    "title": "Approve XRP test trade",
                    "description": "Browser approval should post to the current Clearance host.",
                    "scope": "crypto:buy:XRP",
                    "budget_amount": 20,
                    "budget_currency": "USD",
                },
            )
            approval = client.get(f"/approve/{clearance.json()['id']}")

        self.assertEqual(clearance.status_code, 201)
        self.assertEqual(approval.status_code, 200)
        self.assertIn("fetch('/v1/clearances/", approval.text)

    def test_telegram_webhook_can_approve_pending_clearance(self):
        with TestClient(self.app_module.app) as client:
            key_response = client.post("/v1/keys", json={"email": "telegram@example.com"})
            headers = {"X-API-Key": key_response.json()["api_key"]}
            clearance = client.post(
                "/v1/clearances",
                headers=headers,
                json={
                    "title": "Approve Telegram test trade",
                    "scope": "telegram:test",
                    "budget_amount": 1,
                    "budget_currency": "USD",
                },
            )
            clearance_id = clearance.json()["id"]
            callback = client.post(
                "/v1/telegram/webhook",
                json={
                    "callback_query": {
                        "id": "callback-test",
                        "data": f"clr_approve:{clearance_id}",
                        "from": {"username": "tester"},
                        "message": {
                            "chat": {"id": 123},
                            "message_id": 456,
                            "text": "Clearance Request",
                        },
                    }
                },
            )
            updated = client.get(f"/v1/clearances/{clearance_id}", headers=headers)

        self.assertEqual(callback.status_code, 200)
        self.assertEqual(callback.json(), {"ok": True})
        self.assertEqual(updated.json()["status"], "approved")
        self.assertTrue(updated.json()["token"])

    def test_browser_decision_sends_telegram_update_when_configured(self):
        self.app_module.TELEGRAM_BOT_TOKEN = "test-token"
        self.app_module.TELEGRAM_CHAT_ID = "123"

        with patch.object(self.app_module, "telegram_call", new=AsyncMock(return_value={"ok": True})) as call:
            with TestClient(self.app_module.app) as client:
                key_response = client.post("/v1/keys", json={"email": "browser-telegram@example.com"})
                headers = {"X-API-Key": key_response.json()["api_key"]}
                clearance = client.post(
                    "/v1/clearances",
                    headers=headers,
                    json={
                        "title": "Approve browser decision test",
                        "scope": "browser:telegram:test",
                        "budget_amount": 1,
                        "budget_currency": "USD",
                    },
                )
                decision = client.post(
                    f"/v1/clearances/{clearance.json()['id']}/decide",
                    json={"approved": False, "note": "Declined in browser"},
                )

        self.assertEqual(decision.status_code, 200)
        self.assertEqual(decision.json()["status"], "denied")
        send_message_calls = [
            args for args, _kwargs in call.await_args_list
            if args and args[0] == "sendMessage"
        ]
        self.assertEqual(len(send_message_calls), 2)
        self.assertIn("DENIED", send_message_calls[-1][1]["text"])

    def test_family_sync_populates_dashboard_metrics(self):
        future_due = (datetime.now(timezone.utc) + timedelta(days=3)).date().isoformat()

        with TestClient(self.app_module.app) as client:
            self.login_family(client)
            sync = client.post(
                "/family/api/sync",
                headers={"X-Family-Sync-Token": "sync-secret"},
                json={
                    "actor": "bank-agent",
                    "sources": [
                        {
                            "source_key": "capital_one",
                            "name": "Capital One",
                            "kind": "bank_api",
                            "status": "connected",
                        }
                    ],
                    "accounts": [
                        {
                            "source_key": "capital_one",
                            "external_id": "chk1",
                            "institution": "Capital One",
                            "name": "Northwind Checking",
                            "account_type": "checking",
                            "balance": 4825.42,
                            "available": 4560.11,
                            "currency": "USD",
                            "status": "active",
                            "is_live": True,
                        }
                    ],
                    "bills": [
                        {
                            "source_key": "capital_one",
                            "external_id": "bill1",
                            "payee": "Capital One",
                            "category": "credit_card",
                            "amount": 320.44,
                            "minimum_due": 75.00,
                            "due_date": future_due,
                            "autopay_enabled": False,
                            "status": "pending",
                        }
                    ],
                    "debts": [
                        {
                            "source_key": "capital_one",
                            "external_id": "debt1",
                            "creditor": "Capital One",
                            "balance": 2480.70,
                            "apr": 22.4,
                            "minimum_payment": 75.00,
                            "due_date": future_due,
                            "status": "open",
                        }
                    ],
                    "subscriptions": [
                        {
                            "source_key": "capital_one",
                            "external_id": "sub1",
                            "merchant": "AI Super Plan",
                            "amount": 29.00,
                            "billing_cycle": "monthly",
                            "status": "active",
                        }
                    ],
                    "goals": [
                        {
                            "name": "Emergency Buffer",
                            "target_amount": 10000,
                            "current_amount": 2500,
                            "status": "active",
                        }
                    ],
                    "credit_scores": [
                        {
                            "person_name": "Casey Rivera",
                            "bureau": "Experian",
                            "score": 702,
                            "source_key": "capital_one",
                        }
                    ],
                    "alerts": [
                        {
                            "source_key": "capital_one",
                            "alert_type": "identity",
                            "severity": "medium",
                            "title": "New account inquiry",
                            "detail": "Review recent inquiry activity.",
                            "status": "open",
                        }
                    ],
                },
            )
            self.assertEqual(sync.status_code, 200)

            dashboard = client.get("/family/api/dashboard")

        self.assertEqual(dashboard.status_code, 200)
        payload = dashboard.json()
        self.assertEqual(payload["metrics"]["total_balance"], 4825.42)
        self.assertEqual(payload["metrics"]["upcoming_bills_total"], 320.44)
        self.assertEqual(payload["metrics"]["open_debt_balance"], 2480.7)
        self.assertEqual(payload["metrics"]["monthly_subscriptions"], 29.0)
        self.assertEqual(payload["credit_scores"][0]["label"], "good")
        self.assertTrue(payload["health"]["is_live"])

    def test_family_queue_blocks_unknown_payees(self):
        with TestClient(self.app_module.app) as client:
            self.login_family(client, username="ben_operator", passcode="test-pass-ben")

            blocked = client.post(
                "/family/api/actions",
                json={
                    "action_type": "bill_payment",
                    "title": "Pay Mystery Creditor",
                    "payee": "Unknown Creditor",
                    "amount": 55.25,
                },
            )
            self.assertEqual(blocked.status_code, 400)
            self.assertIn("approved allowlist", blocked.json()["detail"])

            payee = client.post(
                "/family/api/payees",
                json={"name": "Trusted Creditor", "category": "loan"},
            )
            self.assertEqual(payee.status_code, 200)

            queued = client.post(
                "/family/api/actions",
                json={
                    "action_type": "bill_payment",
                    "title": "Pay Trusted Creditor",
                    "payee": "Trusted Creditor",
                    "amount": 155.25,
                    "human_note": "Personal loan minimum due",
                },
            )
            self.assertEqual(queued.status_code, 200)
            action_id = queued.json()["action_id"]

            decided = client.post(
                f"/family/api/actions/{action_id}/decision",
                json={"approved": True, "note": "Looks right"},
            )

        self.assertEqual(decided.status_code, 200)
        self.assertEqual(decided.json()["status"], "approved_for_release")

    def test_health(self):
        with TestClient(self.app_module.app) as client:
            response = client.get("/health")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "operational")
        self.assertEqual(payload["service"], "clearance")

    def test_startup_rejects_missing_required_secrets(self):
        os.environ["JWT_SECRET_KEY"] = ""
        os.environ["BOT_COMM_PASSWORD"] = ""
        reloaded = importlib.reload(self.app_module)
        with self.assertRaises(RuntimeError) as caught:
            with TestClient(reloaded.app):
                pass
        message = str(caught.exception)
        self.assertIn("JWT_SECRET_KEY", message)
        self.assertIn("BOT_COMM_PASSWORD", message)
        self.assertIn("Refusing to start", message)

    def test_private_ledger_hidden_unless_enabled(self):
        os.environ["LEDGER_TOOLS_ENABLED"] = "false"
        reloaded = importlib.reload(self.app_module)
        with TestClient(reloaded.app) as client:
            hidden = client.get("/family/login")
            health = client.get("/health")
        self.assertEqual(hidden.status_code, 404)
        self.assertEqual(health.status_code, 200)

    def test_outreach_flags_default_off(self):
        self.assertFalse(self.app_module.AGENT_INCOME_OPERATOR_ENABLED)
        self.assertFalse(self.app_module.AGENT_INCOME_PUBLIC_LEAD_DISCOVERY_ENABLED)
        self.assertFalse(self.app_module.AGENT_INCOME_AUTO_DEAL_LEADS)

    def test_production_allows_missing_payment_ens_and_https_resources(self):
        os.environ["BASE_URL"] = "https://clearance.example.com"
        os.environ["PUBLIC_BASE_URL"] = "http://pay.example.com"
        os.environ["PAYMENT_ENS"] = ""
        os.environ["PAYMENT_WALLET"] = "0xaC73A1dC4FEc75b61478Fb34186C6a379EA01CC2"
        os.environ["USDC_CONTRACT"] = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
        reloaded = importlib.reload(self.app_module)
        with TestClient(reloaded.app) as client:
            unpaid = client.post(
                "/agent-income/audit",
                json={"project_url": "https://example.com"},
                headers={"Accept": "application/json"},
            )
            discovery = client.get("/.well-known/x402.json")
            probe = client.get(
                "/bot-comm/api/services/directory_lookup?x402=1",
                headers={"Accept": "application/json"},
            )
        self.assertEqual(unpaid.status_code, 402)
        resource = unpaid.json()["payment"]["resource"]["url"]
        self.assertTrue(resource.startswith("https://pay.example.com/agent-income/audit"))
        self.assertIn("quote_id=", resource)
        accept = unpaid.json()["payment"]["accepts"][0]
        self.assertEqual(accept["facilitator"], "https://api.cdp.coinbase.com/platform/v2/x402")
        self.assertEqual(discovery.status_code, 200)
        self.assertEqual(discovery.json()["baseUrl"], "https://pay.example.com")
        self.assertTrue(discovery.json()["services"][0]["endpoint"].startswith("https://pay.example.com/"))
        self.assertEqual(probe.status_code, 402)
        self.assertTrue(probe.headers.get("payment-required"))
        self.assertTrue(probe.json()["payment"]["resource"]["url"].startswith("https://pay.example.com/"))

    def test_production_still_requires_wallet_and_usdc(self):
        os.environ["BASE_URL"] = "https://clearance.example.com"
        os.environ["PUBLIC_BASE_URL"] = "https://pay.example.com"
        os.environ["PAYMENT_ENS"] = ""
        os.environ["PAYMENT_WALLET"] = ""
        reloaded = importlib.reload(self.app_module)
        with self.assertRaises(RuntimeError) as missing_wallet:
            with TestClient(reloaded.app):
                pass
        self.assertIn("PAYMENT_WALLET", str(missing_wallet.exception))

        os.environ["PAYMENT_WALLET"] = "0xaC73A1dC4FEc75b61478Fb34186C6a379EA01CC2"
        os.environ["USDC_CONTRACT"] = ""
        reloaded = importlib.reload(self.app_module)
        with self.assertRaises(RuntimeError) as missing_usdc:
            with TestClient(reloaded.app):
                pass
        self.assertIn("USDC_CONTRACT", str(missing_usdc.exception))

    def test_direct_payment_is_bound_to_quote_and_rejects_replay(self):
        tx_hash = "0x" + "ab" * 32
        payer = "0x" + "11" * 20
        seen = {}

        async def fake_verify(tx, amount, recipient=None, not_before=None):
            seen["not_before"] = not_before
            seen["recipient"] = recipient
            seen["amount"] = amount
            return {
                "verified": True,
                "error": None,
                "amount_usdc": amount,
                "confirmations": 20,
                "from_address": payer,
                "block_number": 10,
                "block_timestamp": int(datetime.now(timezone.utc).timestamp()),
            }

        with TestClient(self.app_module.app) as client:
            unpaid = client.post("/agent-income/audit", json={"project_url": "https://example.com"})
            self.assertEqual(unpaid.status_code, 402)
            quote_id = unpaid.json()["quote_id"]
            self.assertTrue(quote_id)
            missing_quote = client.post(
                "/agent-income/audit",
                json={"project_url": "https://example.com", "payment_tx": tx_hash},
            )
            self.assertEqual(missing_quote.status_code, 402)
            self.assertIn("quote_id", missing_quote.json()["error"])

            with patch.object(self.app_module, "verify_usdc_payment", fake_verify):
                paid = client.post(
                    "/agent-income/audit",
                    json={"project_url": "https://example.com", "payment_tx": tx_hash, "quote_id": quote_id},
                )
                replay = client.post(
                    "/agent-income/audit",
                    json={"project_url": "https://example.com", "payment_tx": tx_hash, "quote_id": quote_id},
                )
        self.assertEqual(paid.status_code, 200, paid.text)
        self.assertEqual(paid.json()["status"], "paid")
        self.assertEqual(paid.json()["receipt"]["tx"], tx_hash)
        self.assertIsNotNone(seen["not_before"])
        self.assertEqual(seen["recipient"], os.environ["PAYMENT_WALLET"].lower())
        self.assertEqual(seen["amount"], 49.0)
        self.assertEqual(replay.status_code, 409)

    def test_standard_x402_header_uses_facilitator_and_402_without_credentials(self):
        payload = {
            "x402Version": 2,
            "accepted": {"scheme": "exact", "network": "eip155:8453"},
            "payload": {
                "signature": "0x" + "12" * 65,
                "authorization": {
                    "from": "0x" + "22" * 20,
                    "to": os.environ["PAYMENT_WALLET"],
                    "value": "49000000",
                    "validAfter": "0",
                    "validBefore": "9999999999",
                    "nonce": "0x" + "33" * 32,
                },
            },
            "extensions": {"bazaar": {"info": {"input": {"type": "http", "method": "POST"}}}},
        }
        header = json.dumps(payload).encode("utf-8")
        encoded = __import__("base64").b64encode(header).decode("ascii")

        with TestClient(self.app_module.app) as client:
            unconfigured = client.post(
                "/agent-income/audit",
                json={"project_url": "https://example.com"},
                headers={"PAYMENT-SIGNATURE": encoded, "Accept": "application/json"},
            )
        self.assertEqual(unconfigured.status_code, 402)
        self.assertIn("CDP_API_KEY_ID", unconfigured.json()["error"])
        self.assertNotIn("Traceback", unconfigured.text)

        captured = {}

        async def fake_settle(payment_header, requirements):
            import x402_facilitator

            captured["body"] = x402_facilitator.prepare_facilitator_body(
                x402_facilitator.decode_payment_header(payment_header),
                requirements,
            )
            return {"ok": True, "error": None, "tx_hash": "0x" + "cd" * 32, "payer": "0x" + "22" * 20}

        os.environ["CDP_API_KEY_ID"] = "test-key-id"
        os.environ["CDP_API_KEY_SECRET"] = "test-key-secret"
        try:
            with patch.object(self.app_module, "verify_and_settle", fake_settle):
                with TestClient(self.app_module.app) as client:
                    settled = client.post(
                        "/agent-income/audit",
                        json={"project_url": "https://example.com"},
                        headers={"X-PAYMENT": encoded, "Accept": "application/json"},
                    )
        finally:
            os.environ.pop("CDP_API_KEY_ID", None)
            os.environ.pop("CDP_API_KEY_SECRET", None)

        self.assertEqual(settled.status_code, 200, settled.text)
        self.assertEqual(settled.json()["receipt"]["tx"], "0x" + "cd" * 32)
        forwarded = captured["body"]["paymentPayload"]
        self.assertTrue(forwarded["resource"]["url"])
        self.assertIn("bazaar", forwarded["extensions"])
        self.assertEqual(forwarded["extensions"]["bazaar"]["info"]["input"]["method"], "POST")

    def test_revenue_log_requires_admin_and_groups_paid_calls(self):
        tx_hash = "0x" + "ef" * 32
        payer = "0x" + "44" * 20

        async def fake_verify(tx, amount, recipient=None, not_before=None):
            return {
                "verified": True,
                "error": None,
                "amount_usdc": amount,
                "confirmations": 20,
                "from_address": payer,
                "block_number": 12,
                "block_timestamp": int(datetime.now(timezone.utc).timestamp()),
            }

        with TestClient(self.app_module.app) as client:
            unpaid = client.post("/agent-income/test-ping", json={"ping": "1"})
            self.assertEqual(unpaid.status_code, 404)
            os.environ["TEST_PRICE_USD"] = "0.05"
            hidden = client.get("/agent-income/agents.json")
            discovery = client.get("/.well-known/x402.json")
            probe = client.post("/agent-income/test-ping", json={"ping": "1"}, headers={"Accept": "application/json"})
            self.assertNotIn("test-ping", hidden.text)
            self.assertNotIn("test_ping", discovery.text)
            self.assertEqual(probe.status_code, 402)
            self.assertAlmostEqual(probe.json()["service"]["price_usd"], 0.05)
            quote_id = probe.json()["quote_id"]

            locked = client.get("/v1/revenue/payments")
            wrong = client.get("/v1/revenue/payments", headers={"Authorization": "Bearer nope"})
            with patch.object(self.app_module, "verify_usdc_payment", fake_verify):
                paid = client.post(
                    "/agent-income/test-ping",
                    json={"ping": "1", "payment_tx": tx_hash, "quote_id": quote_id},
                )
                quoted = client.post(
                    "/bot-comm/api/services/directory_lookup",
                    json={"input": {"task": "classify inbound payment messages", "required_capability": "message scoring"}},
                )
                bot_quote = quoted.json()["quote_id"]
                bot_paid = client.post(
                    "/bot-comm/api/services/directory_lookup",
                    json={
                        "input": {"task": "classify inbound payment messages", "required_capability": "message scoring"},
                        "payment_tx": "0x" + "12" * 32,
                        "quote_id": bot_quote,
                    },
                )
            os.environ["ADMIN_TOKEN"] = "revenue-admin-token"
            by_password = client.get(
                "/v1/revenue/payments",
                headers={"Authorization": f"Bearer {os.environ['BOT_COMM_PASSWORD']}"},
            )
            by_admin = client.get(
                "/v1/revenue/payments",
                headers={"X-Admin-Token": "revenue-admin-token"},
            )
        self.assertEqual(paid.status_code, 200, paid.text)
        self.assertTrue(paid.json()["result"]["pong"])
        self.assertIn(bot_paid.status_code, {200, 409})
        self.assertEqual(locked.status_code, 401)
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(by_password.status_code, 200)
        body = by_password.json()
        services = {item["service_id"] for item in body["payments"]}
        self.assertIn("test_ping", services)
        self.assertIn("directory_lookup", services)
        test_row = next(item for item in body["payments"] if item["service_id"] == "test_ping")
        self.assertEqual(test_row["tx_hash"], tx_hash)
        self.assertEqual(test_row["payer"], payer)
        self.assertAlmostEqual(test_row["amount"], 0.05)
        self.assertAlmostEqual(body["totals"]["all_time"]["by_service"]["test_ping"], 0.05)
        self.assertAlmostEqual(body["totals"]["24h"]["by_service"]["directory_lookup"], 0.02)
        self.assertAlmostEqual(body["totals"]["7d"]["total"], body["totals"]["all_time"]["total"])
        self.assertEqual(by_admin.status_code, 200)
        self.assertEqual(len(by_admin.json()["payments"]), len(body["payments"]))

    def test_bot_comm_json_probe_returns_402(self):
        with TestClient(self.app_module.app) as client:
            catalog = client.get("/bot-comm/api/services/directory_lookup")
            probe = client.get(
                "/bot-comm/api/services/directory_lookup?x402=1",
                headers={"Accept": "application/json"},
            )
            ignored = client.get("/bot-comm/api/services/directory_lookup?x402=1")
        self.assertEqual(catalog.status_code, 200)
        self.assertEqual(catalog.json()["id"], "directory_lookup")
        self.assertEqual(probe.status_code, 402)
        self.assertTrue(probe.headers.get("payment-required"))
        self.assertEqual(probe.json()["payment"]["accepts"][0]["scheme"], "exact")
        self.assertTrue(probe.json()["payment"]["accepts"][0]["facilitator"])
        self.assertEqual(ignored.status_code, 200)


class UsdcVerificationTests(unittest.TestCase):
    def setUp(self):
        self.crypto = importlib.import_module("crypto_verify")
        os.environ["USDC_CONTRACT"] = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
        os.environ["PAYMENT_WALLET"] = "0x0000000000000000000000000000000000000001"
        os.environ["MIN_CONFIRMATIONS"] = "12"
        self.contract = os.environ["USDC_CONTRACT"].lower()
        self.recipient = os.environ["PAYMENT_WALLET"].lower()
        self.other = "0x0000000000000000000000000000000000000002"
        self.payer = "0x00000000000000000000000000000000000000aa"
        self.tx_hash = "0x" + "ab" * 32

    def _topic(self, address: str) -> str:
        return "0x" + address.lower().replace("0x", "").rjust(64, "0")

    def _log(self, to_address: str, atomic: int, contract: str | None = None, payer: str | None = None) -> dict:
        return {
            "address": contract or self.contract,
            "topics": [
                self.crypto.TRANSFER_TOPIC,
                self._topic(payer or self.payer),
                self._topic(to_address),
            ],
            "data": hex(atomic),
        }

    def _rpc(self, receipt: dict, timestamp: int):
        async def rpc(method, params):
            if method == "eth_getTransactionReceipt":
                return receipt
            if method == "eth_blockNumber":
                return "0x20"
            if method == "eth_getBlockByNumber":
                return {"timestamp": hex(timestamp)}
            raise AssertionError(method)

        return rpc

    def test_matches_recipient_across_every_usdc_log(self):
        now = int(datetime.now(timezone.utc).timestamp())
        receipt = {
            "status": "0x1",
            "blockNumber": "0x10",
            "logs": [
                self._log(self.other, 49_000_000),
                self._log(self.recipient, 20_000_000),
                self._log(self.recipient, 29_000_000),
                self._log(self.recipient, 1, contract="0x" + "99" * 20),
            ],
        }
        with patch.object(self.crypto, "_rpc_call", self._rpc(receipt, now)):
            result = self._run(self.crypto.verify_usdc_payment(self.tx_hash, 49, self.recipient))
        self.assertTrue(result["verified"], result)
        self.assertAlmostEqual(result["amount_usdc"], 49.0)
        self.assertEqual(result["from_address"], self.payer)
        self.assertGreaterEqual(result["confirmations"], 12)

    def test_rejects_payment_older_than_quote_and_wrong_recipient(self):
        now = int(datetime.now(timezone.utc).timestamp())
        receipt = {
            "status": "0x1",
            "blockNumber": "0x10",
            "logs": [self._log(self.recipient, 49_000_000)],
        }
        with patch.object(self.crypto, "_rpc_call", self._rpc(receipt, now - 3600)):
            stale = self._run(
                self.crypto.verify_usdc_payment(
                    self.tx_hash,
                    49,
                    self.recipient,
                    not_before=datetime.now(timezone.utc),
                )
            )
        self.assertFalse(stale["verified"])
        self.assertIn("older than the quote", stale["error"])

        wrong = {
            "status": "0x1",
            "blockNumber": "0x10",
            "logs": [self._log(self.other, 49_000_000)],
        }
        with patch.object(self.crypto, "_rpc_call", self._rpc(wrong, now)):
            mismatched = self._run(self.crypto.verify_usdc_payment(self.tx_hash, 49, self.recipient))
        self.assertFalse(mismatched["verified"])
        self.assertIn("different address", mismatched["error"])

    def test_facilitator_request_keeps_resource_and_bazaar(self):
        import x402_facilitator

        requirements = {
            "x402Version": 2,
            "resource": {"url": "https://pay.example.com/agent-income/audit", "description": "Audit", "mimeType": "application/json"},
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "49000000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": self.recipient,
                "facilitator": "https://facilitator.example/x402",
            }],
            "extensions": {"bazaar": {"info": {"input": {"type": "http"}}}},
        }
        payload = {"x402Version": 2, "accepted": {"scheme": "exact", "network": "eip155:8453"}, "payload": {"signature": "0xabc"}}
        body = x402_facilitator.prepare_facilitator_body(payload, requirements)
        self.assertEqual(body["paymentPayload"]["resource"]["url"], requirements["resource"]["url"])
        self.assertEqual(body["paymentPayload"]["extensions"]["bazaar"]["info"]["input"]["type"], "http")
        self.assertEqual(body["paymentRequirements"]["scheme"], "exact")

        captured = {}

        async def fake_post(url, payload_body):
            captured.setdefault("urls", []).append(url)
            captured["body"] = payload_body
            if url.endswith("/verify"):
                return {"isValid": True, "payer": self.payer}
            return {"success": True, "transaction": self.tx_hash, "payer": self.payer}

        os.environ["CDP_API_KEY_ID"] = "organizations/test/apiKeys/test"
        os.environ["CDP_API_KEY_SECRET"] = __import__("base64").b64encode(os.urandom(32)).decode("ascii")
        os.environ["X402_FACILITATOR_URL"] = "https://facilitator.example/x402"
        try:
            with patch.object(x402_facilitator, "_post_json", fake_post):
                settled = self._run(x402_facilitator.verify_and_settle(json.dumps(payload), requirements))
        finally:
            os.environ.pop("CDP_API_KEY_ID", None)
            os.environ.pop("CDP_API_KEY_SECRET", None)
            os.environ.pop("X402_FACILITATOR_URL", None)
        self.assertTrue(settled["ok"], settled)
        self.assertEqual(settled["tx_hash"], self.tx_hash)
        self.assertEqual(captured["urls"], [
            "https://facilitator.example/x402/verify",
            "https://facilitator.example/x402/settle",
        ])
        self.assertIn("bazaar", captured["body"]["paymentPayload"]["extensions"])
        self.assertTrue(captured["body"]["paymentPayload"]["resource"]["url"].startswith("https://"))

        os.environ.pop("CDP_API_KEY_ID", None)
        os.environ.pop("CDP_API_KEY_SECRET", None)
        missing = self._run(x402_facilitator.verify_and_settle(json.dumps(payload), requirements))
        self.assertFalse(missing["ok"])
        self.assertIn("CDP_API_KEY_ID", missing["error"])

    def _run(self, awaitable):
        import asyncio

        return asyncio.run(awaitable)


if __name__ == "__main__":
    unittest.main()
