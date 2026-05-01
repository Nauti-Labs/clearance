import importlib
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient


class ClearanceSmokeTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "clearance-test.db")

        os.environ["DB_PATH"] = self.db_path
        os.environ["JWT_SECRET_KEY"] = "test-secret-not-for-production"
        os.environ["BASE_URL"] = "http://localhost:8000"
        os.environ["TOKEN_ISSUER"] = "http://localhost:8000"
        os.environ["BRAND_URL"] = "https://nauti-labs.com"
        os.environ["PAYMENT_WALLET"] = "0x369301753a2372304ba4e159bab852339d760989"
        os.environ["PAYMENT_ENS"] = "spacegravy.base.eth"
        os.environ["USDC_CONTRACT"] = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
        os.environ["PAYMENT_SUPPORT_EMAIL"] = "consulting@nauti-labs.com"
        os.environ["MIN_CONFIRMATIONS"] = "12"
        os.environ.pop("STRIPE_SECRET_KEY", None)
        os.environ.pop("STRIPE_WEBHOOK_SECRET", None)
        os.environ["FAMILY_JUSTIN_PASSCODE"] = "nauti-justin"
        os.environ["FAMILY_NICOLE_PASSCODE"] = "nauti-nicole"
        os.environ["FAMILY_SYNC_TOKEN"] = "sync-secret"
        os.environ["NAUTI_TRAFFIC_ADMIN_PIN"] = "123456"
        os.environ["NAUTI_TRAFFIC_ADMIN_PATH_TOKEN"] = "test_admin_secret_123456"

        self.database = importlib.import_module("database")
        self.database = importlib.reload(self.database)
        self.app_module = importlib.import_module("app")
        self.app_module = importlib.reload(self.app_module)

    def tearDown(self):
        self.temp_dir.cleanup()

    def login_family(self, client: TestClient, username: str = "justin", passcode: str = "nauti-justin"):
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
        self.assertIn("Stripe checkout is not configured", response.json()["detail"])

    def test_nauti_traffic_titlecase_route_serves_dashboard(self):
        with TestClient(self.app_module.app) as client:
            response = client.get("/Nauti-Traffic")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Nauti-Traffic", response.text)
        self.assertIn("Ambassador Leaderboard", response.text)

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
                data={"ref": "bhamzy"},
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
                data={"ref": "bhamzy", "badge": "first_mate", "avatar_url": "", "x_handle": "bhamzy"},
                follow_redirects=False,
            )
            alias = client.post(
                f"{admin_path}/alias",
                data={"alias": "bhamzi", "target": "bhamzy"},
                follow_redirects=False,
            )
            hidden = client.post(
                f"{admin_path}/hide",
                data={"ref": "telegram", "action": "hide"},
                follow_redirects=False,
            )
            pretty_alias = client.get("/r/bhamzi", follow_redirects=False)
            vanity_alias = client.get("/bhamzi", follow_redirects=False)
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
        self.assertIn("nauti_traffic_admin", login.headers.get("set-cookie", ""))
        self.assertEqual(unlocked.status_code, 200)
        self.assertIn("Affiliate Control", unlocked.text)
        self.assertIn(f'action="{admin_path}/affiliate"', unlocked.text)
        self.assertEqual(saved.status_code, 303)
        self.assertEqual(alias.status_code, 303)
        self.assertEqual(hidden.status_code, 303)
        self.assertEqual(pretty_alias.status_code, 302)
        self.assertIn("clearance_ref=bhamzy", pretty_alias.headers.get("set-cookie", ""))
        self.assertEqual(vanity_alias.status_code, 302)
        self.assertIn("clearance_ref=bhamzy", vanity_alias.headers.get("set-cookie", ""))
        self.assertEqual(unknown_vanity.status_code, 404)
        self.assertEqual(health.status_code, 200)
        payload = config.json()
        self.assertIn("bhamzy", payload["first_mates"])
        self.assertEqual(payload["ref_aliases"]["bhamzi"], "bhamzy")
        self.assertIn("telegram", payload["hidden_refs"])
        self.assertEqual(payload["avatar_overrides"]["bhamzy"], "bhamzy")

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
                            "name": "LeBlanc Checking",
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
                            "person_name": "Nicole",
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
            self.login_family(client, username="nicole", passcode="nauti-nicole")

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


if __name__ == "__main__":
    unittest.main()
