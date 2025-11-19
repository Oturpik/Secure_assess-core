"""
Initial database migration creating vulnerability and compliance tables.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic
revision = '001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Create frameworks table
    op.create_table(
        'frameworks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(50), nullable=False),
        sa.Column('version', sa.String(20), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )
    
    # Create controls table
    op.create_table(
        'controls',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('framework_id', sa.Integer(), nullable=False),
        sa.Column('control_id', sa.String(50), nullable=False),
        sa.Column('title', sa.String(200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(100), nullable=True),
        sa.Column('subcategory', sa.String(100), nullable=True),
        sa.Column('severity', sa.String(20), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['framework_id'], ['frameworks.id'], )
    )
    
    # Create vulnerabilities table
    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('framework_id', sa.Integer(), nullable=False),
        sa.Column('cve_id', sa.String(20), nullable=True),
        sa.Column('title', sa.String(200), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(20), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cvss_vector', sa.String(100), nullable=True),
        sa.Column('published_date', sa.DateTime(), nullable=True),
        sa.Column('last_modified_date', sa.DateTime(), nullable=True),
        sa.Column('affected_products', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('references', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('mitigation', sa.Text(), nullable=True),
        sa.Column('metadata', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['framework_id'], ['frameworks.id'], ),
        sa.UniqueConstraint('cve_id')
    )
    
    # Create vulnerability_control_mappings table
    op.create_table(
        'vulnerability_control_mappings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('vulnerability_id', sa.Integer(), nullable=False),
        sa.Column('control_id', sa.Integer(), nullable=False),
        sa.Column('mapping_type', sa.String(50), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ),
        sa.ForeignKeyConstraint(['control_id'], ['controls.id'], )
    )
    
    # Create compliance_requirements table
    op.create_table(
        'compliance_requirements',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('framework_id', sa.Integer(), nullable=False),
        sa.Column('requirement_id', sa.String(50), nullable=False),
        sa.Column('title', sa.String(200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(100), nullable=True),
        sa.Column('priority', sa.String(20), nullable=True),
        sa.Column('validation_criteria', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('implementation_guidance', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['framework_id'], ['frameworks.id'], )
    )
    
    # Create scan_results table
    op.create_table(
        'scan_results',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.String(50), nullable=False),
        sa.Column('framework_id', sa.Integer(), nullable=False),
        sa.Column('repository_url', sa.String(200), nullable=True),
        sa.Column('branch', sa.String(100), nullable=True),
        sa.Column('commit_hash', sa.String(40), nullable=True),
        sa.Column('scan_date', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(20), nullable=True),
        sa.Column('findings', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('compliance_score', sa.Float(), nullable=True),
        sa.Column('raw_output', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['framework_id'], ['frameworks.id'], ),
        sa.UniqueConstraint('scan_id')
    )
    
    # Create indexes
    op.create_index('ix_vulnerabilities_cve_id', 'vulnerabilities', ['cve_id'])
    op.create_index('ix_vulnerabilities_severity', 'vulnerabilities', ['severity'])
    op.create_index('ix_controls_control_id', 'controls', ['control_id'])
    op.create_index('ix_scan_results_scan_date', 'scan_results', ['scan_date'])


def downgrade():
    op.drop_table('scan_results')
    op.drop_table('compliance_requirements')
    op.drop_table('vulnerability_control_mappings')
    op.drop_table('vulnerabilities')
    op.drop_table('controls')
    op.drop_table('frameworks')