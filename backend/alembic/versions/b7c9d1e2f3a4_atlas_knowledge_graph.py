"""Atlas knowledge graph — full model restructure

Revision ID: b7c9d1e2f3a4
Revises: a1b2c3d4e5f6
Create Date: 2026-08-06 10:00:00.000000

Creates the atlas knowledge-model tables (atlas_domains, atlas_emails,
atlas_sources, atlas_relationships, atlas_subdomains, atlas_dns_records,
atlas_documents, atlas_persons, atlas_usernames, atlas_certificates,
atlas_technologies, atlas_histories) plus the supporting scan/worker/
auth/registry tables. Migrates existing `vire_atlas` cache rows into the
atlas (domain node + history snapshot) and drops the old scaffold tables
(domains, emails, usernames, dns_records, certificates, technologies) and
the vire_atlas table itself.

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "b7c9d1e2f3a4"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Connector registry seed — every data source the engine knows about.
SOURCE_SEED = [
    ("website", "crawl", "Website crawl (BFS depth-2)"),
    ("mailto", "crawl", "mailto: links"),
    ("careers", "crawl", "Career / job pages on the domain"),
    ("jobportal", "search", "HRD emails from public job portals (polite)"),
    ("document", "crawl", "Public documents (PDF/DOCX/XLSX/TXT…)"),
    ("security_txt", "crawl", "security.txt contact"),
    ("search", "search", "Public search engines (DDG + Bing)"),
    ("wayback", "search", "Wayback Machine archive"),
    ("github", "api", "Public git commit histories"),
    ("mailing_list", "search", "Public mailing-list archives"),
    ("ocr", "crawl", "Local OCR (Tesseract)"),
    ("bbot", "subprocess", "BBOT email-enum (deep mode)"),
    ("holehe", "subprocess", "Holehe account footprint (deep mode)"),
    ("subdomain", "dns", "Subdomain enumeration + crawl"),
    ("whois", "dns", "WHOIS lookup"),
    ("pattern_verified", "smtp", "Pattern candidates (SMTP-verified)"),
    ("smtp", "smtp", "SMTP RCPT-TO verification"),
]


def upgrade() -> None:
    bind = op.get_bind()

    # ------------------------------------------------------------------
    # 1) auth additions: organizations / teams
    # ------------------------------------------------------------------
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("slug", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("name"),
        sa.UniqueConstraint("slug"),
    )
    op.create_index(op.f("ix_organizations_id"), "organizations", ["id"], unique=False)
    op.create_index(op.f("ix_organizations_name"), "organizations", ["name"], unique=True)
    op.create_index(op.f("ix_organizations_slug"), "organizations", ["slug"], unique=True)

    op.create_table(
        "teams",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(op.f("ix_teams_id"), "teams", ["id"], unique=False)

    op.create_table(
        "team_members",
        sa.Column("team_id", sa.Integer(), sa.ForeignKey("teams.id"), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), primary_key=True),
        sa.Column("role", sa.String(), nullable=True),
        sa.Column("joined_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.UniqueConstraint("team_id", "user_id", name="uq_team_members"),
    )

    # ------------------------------------------------------------------
    # 2) source registry
    # ------------------------------------------------------------------
    op.create_table(
        "sources",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("name"),
    )
    op.create_index(op.f("ix_sources_id"), "sources", ["id"], unique=False)
    op.create_index(op.f("ix_sources_name"), "sources", ["name"], unique=True)
    op.bulk_insert(
        sa.table(
            "sources",
            sa.column("name", sa.String),
            sa.column("type", sa.String),
            sa.column("description", sa.String),
        ),
        [{"name": n, "type": t, "description": d} for n, t, d in SOURCE_SEED],
    )

    # ------------------------------------------------------------------
    # 3) scan lifecycle tables
    # ------------------------------------------------------------------
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("mode", sa.String(), nullable=True),
        sa.Column("celery_task_id", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.UniqueConstraint("celery_task_id"),
    )
    op.create_index(op.f("ix_scan_jobs_celery_task_id"), "scan_jobs", ["celery_task_id"], unique=True)
    op.create_index(op.f("ix_scan_jobs_id"), "scan_jobs", ["id"], unique=False)

    op.create_table(
        "scan_tasks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("source_name", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
    )
    op.create_index(op.f("ix_scan_tasks_id"), "scan_tasks", ["id"], unique=False)

    op.create_table(
        "scan_progress",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("stage", sa.String(), nullable=True),
        sa.Column("percent", sa.Integer(), nullable=True),
        sa.Column("message", sa.String(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
    )
    op.create_index(op.f("ix_scan_progress_id"), "scan_progress", ["id"], unique=False)

    op.create_table(
        "scan_results",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("entity_type", sa.String(), nullable=False),
        sa.Column("entity_value", sa.String(), nullable=False),
        sa.Column("source_name", sa.String(), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=True),
        sa.Column("meta", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
    )
    op.create_index(op.f("ix_scan_results_id"), "scan_results", ["id"], unique=False)

    # ------------------------------------------------------------------
    # 4) worker tables
    # ------------------------------------------------------------------
    op.create_table(
        "worker_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("worker_id", sa.Integer(), sa.ForeignKey("workers.id"), nullable=True),
        sa.Column("task_name", sa.String(), nullable=False),
        sa.Column("task_id", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.UniqueConstraint("task_id"),
    )
    op.create_index(op.f("ix_worker_jobs_id"), "worker_jobs", ["id"], unique=False)
    op.create_index(op.f("ix_worker_jobs_task_id"), "worker_jobs", ["task_id"], unique=True)

    op.create_table(
        "worker_queues",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("length", sa.Integer(), nullable=True),
        sa.Column("processed", sa.Integer(), nullable=True),
        sa.Column("failed", sa.Integer(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.UniqueConstraint("name"),
    )
    op.create_index(op.f("ix_worker_queues_id"), "worker_queues", ["id"], unique=False)
    op.create_index(op.f("ix_worker_queues_name"), "worker_queues", ["name"], unique=True)

    op.create_table(
        "worker_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("worker_id", sa.Integer(), sa.ForeignKey("workers.id"), nullable=True),
        sa.Column("level", sa.String(), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
    )
    op.create_index(op.f("ix_worker_logs_id"), "worker_logs", ["id"], unique=False)

    # ------------------------------------------------------------------
    # 5) ATLAS — the knowledge model
    # ------------------------------------------------------------------
    op.create_table(
        "atlas_domains",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("scan_mode", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("confidence_score", sa.Integer(), nullable=True),
        sa.Column("emails_found", sa.Integer(), nullable=True),
        sa.Column("subdomains_found", sa.Integer(), nullable=True),
        sa.Column("security_posture", sa.JSON(), nullable=True),
        sa.Column("dns_summary", sa.JSON(), nullable=True),
        sa.Column("hits", sa.Integer(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("domain", "scan_mode", name="uq_atlas_domains_domain_mode"),
    )
    op.create_index(op.f("ix_atlas_domains_domain"), "atlas_domains", ["domain"], unique=False)
    op.create_index(op.f("ix_atlas_domains_id"), "atlas_domains", ["id"], unique=False)

    op.create_table(
        "atlas_sources",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=True),
        sa.Column("kind", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.UniqueConstraint("name"),
    )
    op.create_index(op.f("ix_atlas_sources_id"), "atlas_sources", ["id"], unique=False)
    op.create_index(op.f("ix_atlas_sources_name"), "atlas_sources", ["name"], unique=True)
    op.bulk_insert(
        sa.table(
            "atlas_sources",
            sa.column("name", sa.String),
            sa.column("label", sa.String),
            sa.column("kind", sa.String),
        ),
        [
            {"name": n, "label": n.capitalize(),
             "kind": "tool" if t == "subprocess" else ("pattern" if n == "pattern_verified" else "observed")}
            for n, t, _ in SOURCE_SEED
        ],
    )

    op.create_table(
        "atlas_emails",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain_id", sa.Integer(), sa.ForeignKey("atlas_domains.id"), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("local_part", sa.String(), nullable=True),
        sa.Column("smtp_status", sa.String(), nullable=True),
        sa.Column("is_hrd", sa.Boolean(), nullable=True),
        sa.Column("confidence_score", sa.Integer(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("domain_id", "email", name="uq_atlas_emails_domain_email"),
    )
    op.create_index(op.f("ix_atlas_emails_email"), "atlas_emails", ["email"], unique=False)
    op.create_index(op.f("ix_atlas_emails_id"), "atlas_emails", ["id"], unique=False)

    op.create_table(
        "atlas_dns_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain_id", sa.Integer(), sa.ForeignKey("atlas_domains.id"), nullable=False),
        sa.Column("record_type", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.UniqueConstraint("domain_id", "record_type", "name", "value",
                            name="uq_atlas_dns_domain_type_name_value"),
    )
    op.create_index(op.f("ix_atlas_dns_records_id"), "atlas_dns_records", ["id"], unique=False)

    op.create_table(
        "atlas_subdomains",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain_id", sa.Integer(), sa.ForeignKey("atlas_domains.id"), nullable=False),
        sa.Column("subdomain", sa.String(), nullable=False),
        sa.Column("resolved_ip", sa.String(), nullable=True),
        sa.Column("crawled", sa.Boolean(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.UniqueConstraint("domain_id", "subdomain", name="uq_atlas_subdomains_domain_sub"),
    )
    op.create_index(op.f("ix_atlas_subdomains_id"), "atlas_subdomains", ["id"], unique=False)
    op.create_index(op.f("ix_atlas_subdomains_subdomain"), "atlas_subdomains", ["subdomain"], unique=False)

    op.create_table(
        "atlas_documents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain_id", sa.Integer(), sa.ForeignKey("atlas_domains.id"), nullable=False),
        sa.Column("url", sa.String(), nullable=False),
        sa.Column("file_type", sa.String(), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("emails_found", sa.Integer(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
    )
    op.create_index(op.f("ix_atlas_documents_id"), "atlas_documents", ["id"], unique=False)

    op.create_table(
        "atlas_persons",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain_id", sa.Integer(), sa.ForeignKey("atlas_domains.id"), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=True),
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("atlas_emails.id"), nullable=True),
        sa.Column("source_name", sa.String(), nullable=True),
        sa.Column("context", sa.String(), nullable=True),
        sa.Column("url", sa.String(), nullable=True),
        sa.Column("is_hrd", sa.Boolean(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
    )
    op.create_index(op.f("ix_atlas_persons_id"), "atlas_persons", ["id"], unique=False)

    op.create_table(
        "atlas_usernames",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain_id", sa.Integer(), sa.ForeignKey("atlas_domains.id"), nullable=False),
        sa.Column("platform", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("profile_url", sa.String(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.UniqueConstraint("platform", "username", name="uq_atlas_usernames_platform_name"),
    )
    op.create_index(op.f("ix_atlas_usernames_id"), "atlas_usernames", ["id"], unique=False)
    op.create_index(op.f("ix_atlas_usernames_username"), "atlas_usernames", ["username"], unique=False)

    op.create_table(
        "atlas_certificates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain_id", sa.Integer(), sa.ForeignKey("atlas_domains.id"), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=True),
        sa.Column("issuer", sa.Text(), nullable=True),
        sa.Column("subject", sa.Text(), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("serial_number", sa.String(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.UniqueConstraint("fingerprint"),
    )
    op.create_index(op.f("ix_atlas_certificates_fingerprint"), "atlas_certificates", ["fingerprint"], unique=True)
    op.create_index(op.f("ix_atlas_certificates_id"), "atlas_certificates", ["id"], unique=False)

    op.create_table(
        "atlas_technologies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain_id", sa.Integer(), sa.ForeignKey("atlas_domains.id"), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=True),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.UniqueConstraint("domain_id", "name", "version",
                            name="uq_atlas_technologies_domain_name_version"),
    )
    op.create_index(op.f("ix_atlas_technologies_id"), "atlas_technologies", ["id"], unique=False)

    op.create_table(
        "atlas_relationships",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("atlas_emails.id"), nullable=False),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("atlas_sources.id"), nullable=False),
        sa.Column("url", sa.String(), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.UniqueConstraint("email_id", "source_id", "url",
                            name="uq_atlas_relationships_email_source_url"),
    )
    op.create_index(op.f("ix_atlas_relationships_id"), "atlas_relationships", ["id"], unique=False)

    op.create_table(
        "atlas_histories",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain_id", sa.Integer(), sa.ForeignKey("atlas_domains.id"), nullable=False),
        sa.Column("scan_mode", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("emails_found", sa.Integer(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
    )
    op.create_index(op.f("ix_atlas_histories_id"), "atlas_histories", ["id"], unique=False)

    # ------------------------------------------------------------------
    # 6) migrate vire_atlas cache rows -> atlas_domains + atlas_histories
    # ------------------------------------------------------------------
    vire = sa.table(
        "vire_atlas",
        sa.column("id", sa.Integer),
        sa.column("domain", sa.String),
        sa.column("scan_mode", sa.String),
        sa.column("result", sa.JSON),
        sa.column("emails_found", sa.Integer),
        sa.column("status", sa.String),
        sa.column("hits", sa.Integer),
        sa.column("scanned_at", sa.DateTime(timezone=True)),
    )
    rows = bind.execute(sa.select(vire)).mappings().all()

    atlas_domains = sa.table(
        "atlas_domains",
        sa.column("domain", sa.String),
        sa.column("scan_mode", sa.String),
        sa.column("status", sa.String),
        sa.column("emails_found", sa.Integer),
        sa.column("hits", sa.Integer),
        sa.column("last_scanned_at", sa.DateTime(timezone=True)),
    )
    atlas_histories = sa.table(
        "atlas_histories",
        sa.column("domain_id", sa.Integer),
        sa.column("scan_mode", sa.String),
        sa.column("status", sa.String),
        sa.column("result", sa.JSON),
        sa.column("emails_found", sa.Integer),
        sa.column("duration_ms", sa.Integer),
    )

    for row in rows:
        node_id = bind.execute(
            atlas_domains.insert().values(
                domain=row["domain"],
                scan_mode=row["scan_mode"],
                status="completed",
                emails_found=row["emails_found"] or 0,
                hits=row["hits"] or 0,
                last_scanned_at=row["scanned_at"],
            ).returning(sa.column("id"))
        ).scalar()
        duration_ms = None
        try:
            duration_ms = (row["result"] or {}).get("duration_ms")
        except Exception:
            pass
        bind.execute(
            atlas_histories.insert().values(
                domain_id=node_id,
                scan_mode=row["scan_mode"],
                status="completed",
                result=row["result"],
                emails_found=row["emails_found"] or 0,
                duration_ms=duration_ms,
            )
        )

    # ------------------------------------------------------------------
    # 7) drop the old scaffold tables + vire_atlas
    # ------------------------------------------------------------------
    op.drop_table("vire_atlas")
    op.drop_index(op.f("ix_technologies_id"), table_name="technologies")
    op.drop_table("technologies")
    op.drop_index(op.f("ix_dns_records_id"), table_name="dns_records")
    op.drop_table("dns_records")
    op.drop_index(op.f("ix_certificates_fingerprint"), table_name="certificates")
    op.drop_index(op.f("ix_certificates_id"), table_name="certificates")
    op.drop_table("certificates")
    op.drop_index(op.f("ix_usernames_username"), table_name="usernames")
    op.drop_index(op.f("ix_usernames_id"), table_name="usernames")
    op.drop_table("usernames")
    op.drop_index(op.f("ix_emails_id"), table_name="emails")
    op.drop_index(op.f("ix_emails_email"), table_name="emails")
    op.drop_index(op.f("ix_emails_domain"), table_name="emails")
    op.drop_table("emails")
    op.drop_index(op.f("ix_domains_id"), table_name="domains")
    op.drop_index(op.f("ix_domains_domain"), table_name="domains")
    op.drop_table("domains")


def downgrade() -> None:
    # Reverse: recreate the old scaffold tables (empty), then drop atlas.
    op.create_table(
        "domains",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("dns_records", sa.JSON(), nullable=True),
        sa.Column("mx_records", sa.JSON(), nullable=True),
        sa.Column("spf", sa.Text(), nullable=True),
        sa.Column("dmarc", sa.Text(), nullable=True),
        sa.Column("dkim", sa.Text(), nullable=True),
        sa.Column("certificate_transparency", sa.JSON(), nullable=True),
        sa.Column("tls_certificate", sa.JSON(), nullable=True),
        sa.Column("asn", sa.String(), nullable=True),
        sa.Column("ip_addresses", sa.JSON(), nullable=True),
        sa.Column("security_txt", sa.Text(), nullable=True),
        sa.Column("robots_txt", sa.Text(), nullable=True),
        sa.Column("sitemap_xml", sa.Text(), nullable=True),
        sa.Column("technologies", sa.JSON(), nullable=True),
        sa.Column("public_emails", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_domains_id"), "domains", ["id"], unique=False)
    op.create_index(op.f("ix_domains_domain"), "domains", ["domain"], unique=True)
    op.create_table(
        "emails",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("is_valid_format", sa.Boolean(), nullable=True),
        sa.Column("mx_record", sa.JSON(), nullable=True),
        sa.Column("spf", sa.Text(), nullable=True),
        sa.Column("dmarc", sa.Text(), nullable=True),
        sa.Column("dkim", sa.Text(), nullable=True),
        sa.Column("gravatar", sa.JSON(), nullable=True),
        sa.Column("domain_info", sa.JSON(), nullable=True),
        sa.Column("public_references", sa.JSON(), nullable=True),
        sa.Column("confidence_score", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_emails_id"), "emails", ["id"], unique=False)
    op.create_index(op.f("ix_emails_email"), "emails", ["email"], unique=True)
    op.create_index(op.f("ix_emails_domain"), "emails", ["domain"], unique=False)
    op.create_table(
        "usernames",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("github", sa.JSON(), nullable=True),
        sa.Column("gitlab", sa.JSON(), nullable=True),
        sa.Column("reddit", sa.JSON(), nullable=True),
        sa.Column("stackoverflow", sa.JSON(), nullable=True),
        sa.Column("docker_hub", sa.JSON(), nullable=True),
        sa.Column("pypi", sa.JSON(), nullable=True),
        sa.Column("npm", sa.JSON(), nullable=True),
        sa.Column("medium", sa.JSON(), nullable=True),
        sa.Column("gravatar", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_usernames_id"), "usernames", ["id"], unique=False)
    op.create_index(op.f("ix_usernames_username"), "usernames", ["username"], unique=True)
    op.create_table(
        "certificates",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain_id", sa.Integer(), sa.ForeignKey("domains.id"), nullable=True),
        sa.Column("fingerprint", sa.String(), nullable=True),
        sa.Column("issuer", sa.JSON(), nullable=True),
        sa.Column("subject", sa.JSON(), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("serial_number", sa.String(), nullable=True),
        sa.Column("signature_algorithm", sa.String(), nullable=True),
        sa.Column("pem", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_certificates_id"), "certificates", ["id"], unique=False)
    op.create_index(op.f("ix_certificates_fingerprint"), "certificates", ["fingerprint"], unique=True)
    op.create_table(
        "dns_records",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain_id", sa.Integer(), sa.ForeignKey("domains.id"), nullable=True),
        sa.Column("record_type", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("value", sa.JSON(), nullable=True),
        sa.Column("ttl", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_dns_records_id"), "dns_records", ["id"], unique=False)
    op.create_table(
        "technologies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain_id", sa.Integer(), sa.ForeignKey("domains.id"), nullable=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=True),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_technologies_id"), "technologies", ["id"], unique=False)
    op.create_table(
        "vire_atlas",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("scan_mode", sa.String(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("emails_found", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("hits", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("domain", "scan_mode", name="uq_vire_atlas_domain_mode"),
    )
    op.create_index(op.f("ix_vire_atlas_id"), "vire_atlas", ["id"], unique=False)
    op.create_index(op.f("ix_vire_atlas_domain"), "vire_atlas", ["domain"], unique=False)

    op.drop_table("atlas_histories")
    op.drop_table("atlas_relationships")
    op.drop_table("atlas_technologies")
    op.drop_table("atlas_certificates")
    op.drop_table("atlas_usernames")
    op.drop_table("atlas_persons")
    op.drop_table("atlas_documents")
    op.drop_table("atlas_subdomains")
    op.drop_table("atlas_dns_records")
    op.drop_table("atlas_emails")
    op.drop_table("atlas_sources")
    op.drop_table("atlas_domains")
    op.drop_table("worker_logs")
    op.drop_table("worker_queues")
    op.drop_table("worker_jobs")
    op.drop_table("scan_results")
    op.drop_table("scan_progress")
    op.drop_table("scan_tasks")
    op.drop_table("scan_jobs")
    op.drop_table("sources")
    op.drop_table("team_members")
    op.drop_table("teams")
    op.drop_table("organizations")
