"""initial schema

Revision ID: 20260323_000001
Revises: None
Create Date: 2026-03-23 00:00:01

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260323_000001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("repo_url", sa.String(length=512), nullable=False),
        sa.Column("commit_sha", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "finding",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("file_path", sa.String(length=1024), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=False),
        sa.Column("line_end", sa.Integer(), nullable=False),
        sa.Column("evidence_hash", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scan.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "vulnerability",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.String(length=64), nullable=False),
        sa.Column("package_name", sa.String(length=256), nullable=False),
        sa.Column("installed_version", sa.String(length=128), nullable=False),
        sa.Column("fixed_version", sa.String(length=128), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=256), nullable=True),
        sa.Column("advisory_url", sa.String(length=2048), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id", "cve_id", name="uq_vulnerability_finding_cve"),
    )

    op.create_table(
        "scan_summary",
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("total_findings", sa.Integer(), nullable=False),
        sa.Column("critical_count", sa.Integer(), nullable=False),
        sa.Column("high_count", sa.Integer(), nullable=False),
        sa.Column("medium_count", sa.Integer(), nullable=False),
        sa.Column("low_count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("scan_id"),
    )

    op.create_index("ix_finding_scan_id", "finding", ["scan_id"])
    op.create_index("ix_finding_severity", "finding", ["severity"])
    op.create_index("ix_finding_type", "finding", ["type"])


def downgrade() -> None:
    op.drop_index("ix_finding_type", table_name="finding")
    op.drop_index("ix_finding_severity", table_name="finding")
    op.drop_index("ix_finding_scan_id", table_name="finding")
    op.drop_table("scan_summary")
    op.drop_table("vulnerability")
    op.drop_table("finding")
    op.drop_table("scan")
