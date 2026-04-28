from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum
from datetime import datetime


class Tier(str, Enum):
    starter = "starter"
    pro = "pro"
    scale = "scale"


class ClearanceStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    denied = "denied"
    expired = "expired"
    revoked = "revoked"


# --- Request Models ---

class CreateClearance(BaseModel):
    title: str = Field(..., max_length=200, description="Short description of what the agent wants to do")
    description: Optional[str] = Field(None, max_length=2000, description="Detailed explanation for the human approver")
    scope: str = Field(..., max_length=500, description="Machine-readable scope (e.g. 'purchase:flight', 'send:email')")
    budget_amount: Optional[float] = Field(None, ge=0, description="Maximum spend authorized")
    budget_currency: Optional[str] = Field("USD", max_length=10)
    callback_url: Optional[str] = Field(None, description="Webhook URL for status updates")
    metadata: Optional[dict] = Field(None, description="Arbitrary key-value data attached to clearance")
    expires_in: Optional[int] = Field(3600, ge=60, le=604800, description="Seconds until expiry (default 1 hour, max 7 days)")


class ApproveAction(BaseModel):
    approved: bool
    note: Optional[str] = Field(None, max_length=500)


class CreateAPIKey(BaseModel):
    email: str
    name: Optional[str] = Field(None, max_length=100)


class RegisterWebhook(BaseModel):
    url: str
    events: list[str] = Field(default_factory=lambda: ["clearance.approved", "clearance.denied"])


class FamilyLogin(BaseModel):
    username: str = Field(..., max_length=50)
    passcode: str = Field(..., min_length=4, max_length=128)


class FamilySourceSync(BaseModel):
    source_key: str = Field(..., max_length=100)
    name: str = Field(..., max_length=120)
    kind: str = Field(..., max_length=50)
    status: str = Field("connected", max_length=50)
    metadata: Optional[dict] = None


class FamilyAccountSync(BaseModel):
    source_key: str = Field(..., max_length=100)
    external_id: str = Field(..., max_length=120)
    institution: str = Field(..., max_length=120)
    name: str = Field(..., max_length=120)
    account_type: str = Field(..., max_length=50)
    subtype: Optional[str] = Field(None, max_length=50)
    last4: Optional[str] = Field(None, max_length=4)
    balance: float
    available: Optional[float] = None
    currency: str = Field("USD", max_length=10)
    status: str = Field("active", max_length=50)
    is_live: bool = True
    metadata: Optional[dict] = None


class FamilyBillSync(BaseModel):
    source_key: str = Field(..., max_length=100)
    external_id: str = Field(..., max_length=120)
    payee: str = Field(..., max_length=120)
    category: Optional[str] = Field(None, max_length=50)
    amount: float = Field(..., ge=0)
    minimum_due: Optional[float] = Field(None, ge=0)
    due_date: str
    autopay_enabled: bool = False
    status: str = Field("pending", max_length=50)
    debtor_account: Optional[str] = Field(None, max_length=120)
    notes: Optional[str] = Field(None, max_length=500)
    metadata: Optional[dict] = None


class FamilyDebtSync(BaseModel):
    source_key: str = Field(..., max_length=100)
    external_id: str = Field(..., max_length=120)
    creditor: str = Field(..., max_length=120)
    balance: float = Field(..., ge=0)
    apr: Optional[float] = Field(None, ge=0)
    minimum_payment: float = Field(..., ge=0)
    due_date: Optional[str] = None
    status: str = Field("open", max_length=50)
    metadata: Optional[dict] = None


class FamilySubscriptionSync(BaseModel):
    source_key: str = Field(..., max_length=100)
    external_id: str = Field(..., max_length=120)
    merchant: str = Field(..., max_length=120)
    amount: float = Field(..., ge=0)
    billing_cycle: str = Field("monthly", max_length=20)
    next_charge_date: Optional[str] = None
    status: str = Field("active", max_length=50)
    recommendation: Optional[str] = Field(None, max_length=200)
    metadata: Optional[dict] = None


class FamilyGoalSync(BaseModel):
    name: str = Field(..., max_length=120)
    target_amount: float = Field(..., ge=0)
    current_amount: float = Field(0, ge=0)
    target_date: Optional[str] = None
    status: str = Field("active", max_length=50)
    metadata: Optional[dict] = None


class FamilyCreditScoreSync(BaseModel):
    person_name: str = Field(..., max_length=120)
    bureau: str = Field(..., max_length=50)
    score: int = Field(..., ge=300, le=850)
    source_key: str = Field(..., max_length=100)
    metadata: Optional[dict] = None


class FamilyAlertSync(BaseModel):
    source_key: str = Field(..., max_length=100)
    alert_type: str = Field(..., max_length=80)
    severity: str = Field("info", max_length=20)
    title: str = Field(..., max_length=140)
    detail: Optional[str] = Field(None, max_length=600)
    status: str = Field("open", max_length=50)
    metadata: Optional[dict] = None


class FamilySyncPayload(BaseModel):
    actor: Optional[str] = Field(None, max_length=120)
    sources: list[FamilySourceSync] = Field(default_factory=list)
    accounts: list[FamilyAccountSync] = Field(default_factory=list)
    bills: list[FamilyBillSync] = Field(default_factory=list)
    debts: list[FamilyDebtSync] = Field(default_factory=list)
    subscriptions: list[FamilySubscriptionSync] = Field(default_factory=list)
    goals: list[FamilyGoalSync] = Field(default_factory=list)
    credit_scores: list[FamilyCreditScoreSync] = Field(default_factory=list)
    alerts: list[FamilyAlertSync] = Field(default_factory=list)


class FamilyPayeeCreate(BaseModel):
    name: str = Field(..., max_length=120)
    category: Optional[str] = Field(None, max_length=50)
    method: str = Field("manual_review", max_length=50)
    risk_level: str = Field("verified", max_length=30)


class FamilyActionCreate(BaseModel):
    action_type: str = Field(..., max_length=50)
    title: str = Field(..., max_length=140)
    payee: str = Field(..., max_length=120)
    amount: float = Field(..., gt=0)
    currency: str = Field("USD", max_length=10)
    source_account: Optional[str] = Field(None, max_length=120)
    destination_hint: Optional[str] = Field(None, max_length=120)
    human_note: Optional[str] = Field(None, max_length=500)
    recommended_execution_date: Optional[str] = None
    metadata: Optional[dict] = None


class FamilyActionDecision(BaseModel):
    approved: bool
    note: Optional[str] = Field(None, max_length=500)


# --- Response Models ---

class ClearanceResponse(BaseModel):
    id: str
    status: ClearanceStatus
    title: str
    description: Optional[str]
    scope: str
    budget_amount: Optional[float]
    budget_currency: Optional[str]
    approval_url: str
    token: Optional[str] = None  # Only present when approved
    callback_url: Optional[str]
    metadata: Optional[dict]
    created_at: str
    expires_at: str
    decided_at: Optional[str]


class VerifyResponse(BaseModel):
    valid: bool
    clearance_id: Optional[str]
    scope: Optional[str]
    budget_amount: Optional[float]
    budget_currency: Optional[str]
    approved_at: Optional[str]
    expires_at: Optional[str]
    error: Optional[str] = None


class APIKeyResponse(BaseModel):
    api_key: str
    tier: Tier
    credits_remaining: int
    message: str


class UsageResponse(BaseModel):
    tier: Tier
    credits_used: int
    credits_remaining: int
    clearances_this_month: int
    period_start: str
    period_end: str


class ErrorResponse(BaseModel):
    error: str
    code: str
    detail: Optional[str] = None
