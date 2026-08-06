"""Domain models — organized by responsibility.

- auth/    : users, organizations, teams, api keys, audit logs, webhooks
- scan/    : scans, scan jobs, per-source tasks, progress, raw results
- worker/  : worker fleet, jobs, queues, logs
- atlas/   : normalized knowledge base (knowledge model, not CRUD)
- source.py: connector registry (website, github, wayback, …)
"""
from app.models.auth import (
    User,
    Organization,
    Team,
    team_members,
    APIKey,
    APIKeyUsage,
    AuditLog,
    Webhook,
    Notification,
)
from app.models.scan import Scan, ScanType, ScanStatus, ScanJob, ScanTask, ScanProgress, ScanResult
from app.models.worker import Worker, WorkerJob, WorkerQueue, WorkerLog
from app.models.source import Source
from app.models.atlas import (
    AtlasDomain,
    AtlasEmail,
    AtlasDnsRecord,
    AtlasCertificate,
    AtlasSubdomain,
    AtlasDocument,
    AtlasPerson,
    AtlasUsername,
    AtlasSource,
    AtlasRelationship,
    AtlasTechnology,
    AtlasHistory,
)

__all__ = [
    # auth
    "User", "Organization", "Team", "team_members", "APIKey", "APIKeyUsage",
    "AuditLog", "Webhook", "Notification",
    # scan
    "Scan", "ScanType", "ScanStatus", "ScanJob", "ScanTask", "ScanProgress", "ScanResult",
    # worker
    "Worker", "WorkerJob", "WorkerQueue", "WorkerLog",
    # source registry
    "Source",
    # atlas
    "AtlasDomain", "AtlasEmail", "AtlasDnsRecord", "AtlasCertificate",
    "AtlasSubdomain", "AtlasDocument", "AtlasPerson", "AtlasUsername",
    "AtlasSource", "AtlasRelationship", "AtlasTechnology", "AtlasHistory",
]
