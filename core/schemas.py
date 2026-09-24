from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field
from datetime import datetime

class Indicator(BaseModel):
    type: str  # IP, Domain, URL, Email, Hash
    value: str
    source: str
    confidence: Optional[str] = None

class GeolocationInfo(BaseModel):
    ip: str
    country: str
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    db_provider: str
    db_version: str
    status: Optional[str] = None
    accuracy_radius_km: Optional[int] = None
    accuracy_radius: Optional[int] = None
    network_type: Optional[str] = "Unknown"
    vpn_indicator: Optional[str] = "UNKNOWN"
    proxy_indicator: Optional[str] = "UNKNOWN"
    tor_indicator: Optional[str] = "UNKNOWN"

class AuthEvidence(BaseModel):
    mechanism: str  # SPF, DKIM, DMARC
    result: str
    evidence_source: str

class RuleFinding(BaseModel):
    rule_id: str
    finding: str
    evidence: str
    severity: str
    explanation: str

class MLAssessment(BaseModel):
    model_version: str
    probability: float
    assessment: str
    features_used: List[str]
    confidence_level: Optional[str] = "HIGH CONFIDENCE"
    confidence_score: Optional[float] = 0.0
    is_borderline: Optional[bool] = False

class EventTimeline(BaseModel):
    timestamp: Optional[datetime]
    source: str
    ip: Optional[str]
    hostname: Optional[str]
    country: Optional[str]
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    evidence_ref: str

class AgentStep(BaseModel):
    step_num: int
    thought: str
    action: str
    observation: str
    tool_used: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().strftime("%H:%M:%S"))

class DomainReputation(BaseModel):
    domain: str
    registrar: Optional[str] = "Unknown"
    creation_date: Optional[str] = "Unknown"
    domain_age_days: Optional[int] = None
    is_nrd: bool = False
    has_mx_record: bool = True
    dns_resolved_ips: List[str] = []
    risk_level: str = "LOW"
    notes: List[str] = []

class URLAnalysisResult(BaseModel):
    url: str
    defanged_url: str
    domain: str
    is_shortener: bool = False
    final_destination: Optional[str] = None
    redirect_count: int = 0
    threat_category: str = "Clean / Low Risk"
    risk_level: str = "LOW"  # CRITICAL, HIGH, MEDIUM, LOW, CLEAN
    potential_impact: str = "No severe impact detected."
    recommended_action: str = "Standard vigilance."
    reasons: List[str] = []
    suspicious_indicators: List[str] = []

class AttachmentAnalysisResult(BaseModel):
    filename: str
    sha256: str
    size_bytes: int
    content_type: str
    extension: str
    risk_level: str = "LOW"
    verdict_label: str = "CLEAN / BENIGN"
    is_double_ext: bool = False
    is_dangerous_executable: bool = False
    has_macros: bool = False
    is_disk_image: bool = False
    risk_flags: List[str] = []

class LookalikeAnalysis(BaseModel):
    domain: str
    base_name: str
    is_lookalike: bool = False
    impersonated_brand: Optional[str] = None
    technique: str = "None"
    similarity_score: float = 0.0
    risk_level: str = "LOW"
    reasons: List[str] = []

class BECTelemetry(BaseModel):
    verdict: str = "Standard / Legitimate"
    confidence_pct: int = 80
    bec_risk_score: int = 0
    is_display_name_spoof: bool = False
    is_executive_lure: bool = False
    is_financial_lure: bool = False
    display_name: str = ""
    sender_email: str = ""
    sender_domain: str = ""
    flags: List[str] = []

class AuthAlignmentResult(BaseModel):
    header_from_domain: str = ""
    envelope_from_domain: str = ""
    dkim_signing_domain: str = ""
    spf_result: str = "NONE"
    dkim_result: str = "NONE"
    dmarc_recorded: str = "NONE"
    spf_aligned: bool = False
    dkim_aligned: bool = False
    spf_alignment_status: str = "NOT_DETERMINABLE"
    dkim_alignment_status: str = "NOT_DETERMINABLE"
    effective_dmarc: str = "NONE / UNCONFIGURED"
    dmarc_reason: str = ""
    threat_detected: bool = False
    advisories: List[str] = []

class CaseReport(BaseModel):
    case_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    original_sha256: str
    subject: str = "Unknown"
    sender: str = "Unknown"
    parser_version: str = "1.0"
    
    # SOC Case Management
    status: str = "Open"
    assigned_investigator: str = "Unassigned"
    analyst_notes: str = ""
    case_severity: str = "MEDIUM"
    
    # Forensic Classification & Verdict
    threat_verdict: str = "Legitimate"
    verdict_confidence: int = 80
    content_type: str = "Personal / Direct Mail"
    
    forwarded_by: Optional[str] = None
    ingestion_source: str = "Direct Analysis"  # Direct Analysis, Gmail API, Forward-to-Verify
    
    indicators: List[Indicator] = []
    geolocation: List[GeolocationInfo] = []
    auth_results: List[AuthEvidence] = []
    auth_alignment: Optional[AuthAlignmentResult] = None
    rule_findings: List[RuleFinding] = []
    ml_assessment: Optional[MLAssessment] = None
    domain_reputation: Optional[DomainReputation] = None
    lookalike_analysis: Optional[LookalikeAnalysis] = None
    attachment_analyses: List[AttachmentAnalysisResult] = []
    bec_telemetry: Optional[BECTelemetry] = None
    url_analyses: List[URLAnalysisResult] = []
    ai_reasoning: Optional[str] = None
    agent_trace: List[AgentStep] = []
    timeline: List[EventTimeline] = []
    
    sender_location: Optional[Dict[str, Any]] = None
    infrastructure_intel: Optional[Any] = None
    risk_score: str = "UNKNOWN"
    risk_reasons: List[str] = []

class DomainRole(str, Enum):
    SENDER_IDENTITY = "SENDER_IDENTITY"
    REPLY_TO = "REPLY_TO"
    RETURN_PATH = "RETURN_PATH"
    DKIM = "DKIM"
    URL_DESTINATION = "URL_DESTINATION"
    VISIBLE_ANCHOR = "VISIBLE_ANCHOR"
    QR_DESTINATION = "QR_DESTINATION"
    ATTACHMENT_METADATA = "ATTACHMENT_METADATA"
    THIRD_PARTY_INFRASTRUCTURE = "THIRD_PARTY_INFRASTRUCTURE"
    UNKNOWN = "UNKNOWN"

class DomainVerdict(str, Enum):
    LIKELY_LEGITIMATE = "LIKELY LEGITIMATE"
    THIRD_PARTY_INFRASTRUCTURE = "THIRD-PARTY INFRASTRUCTURE"
    LOOKALIKE_IMPERSONATION = "LOOKALIKE / IMPERSONATION"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH RISK"
    UNKNOWN = "UNKNOWN"

class InspectedDomain(BaseModel):
    domain: str
    registrable_domain: str
    roles: List[DomainRole] = Field(default_factory=list)
    occurrence_count: int = 1

    # Registration intelligence
    rdap_available: bool = False
    registration_date: Optional[str] = "Unknown"
    domain_age_days: Optional[int] = None
    registrar: Optional[str] = "Unknown"
    is_nrd: bool = False

    # DNS
    dns_resolved: bool = False
    resolved_ips: List[str] = Field(default_factory=list)

    # Alignment
    is_sender_aligned: bool = False
    is_auth_aligned: bool = False
    is_claimed_brand_aligned: bool = False

    # Lookalike
    is_lookalike: bool = False
    lookalike_technique: Optional[str] = None
    impersonated_brand: Optional[str] = None
    similarity_score: float = 0.0

    # Risk/evidence
    risk_signals: List[str] = Field(default_factory=list)
    verdict: DomainVerdict = DomainVerdict.UNKNOWN
    evidence_references: List[str] = Field(default_factory=list)

