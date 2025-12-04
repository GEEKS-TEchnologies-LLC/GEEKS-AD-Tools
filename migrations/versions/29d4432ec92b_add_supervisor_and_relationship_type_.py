"""Add supervisor and relationship type fields to UserDirectReport

Revision ID: 29d4432ec92b
Revises: 
Create Date: 2025-12-04 23:17:02.675058

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '29d4432ec92b'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Add new columns to user_direct_report table
    # SQLite requires special handling for NOT NULL columns with existing data
    with op.batch_alter_table('user_direct_report', schema=None) as batch_op:
        # Add nullable columns first
        batch_op.add_column(sa.Column('supervisor_username', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('supervisor_dn', sa.String(length=512), nullable=True))
        batch_op.add_column(sa.Column('is_indirect_report', sa.Boolean(), nullable=True, server_default='0'))
        batch_op.add_column(sa.Column('is_dotted_line', sa.Boolean(), nullable=True, server_default='0'))
        
        # Try to drop old constraint if it exists
        try:
            batch_op.drop_constraint('_employee_manager_uc', type_='unique')
        except:
            pass  # Constraint might not exist
        
        # Create index on supervisor_username
        batch_op.create_index(batch_op.f('ix_user_direct_report_supervisor_username'), ['supervisor_username'], unique=False)
    
    # Set default values for any existing NULL rows (shouldn't be any with server_default, but just in case)
    op.execute("UPDATE user_direct_report SET is_indirect_report = 0 WHERE is_indirect_report IS NULL")
    op.execute("UPDATE user_direct_report SET is_dotted_line = 0 WHERE is_dotted_line IS NULL")


def downgrade():
    with op.batch_alter_table('user_direct_report', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_user_direct_report_supervisor_username'))
        batch_op.drop_column('is_dotted_line')
        batch_op.drop_column('is_indirect_report')
        batch_op.drop_column('supervisor_dn')
        batch_op.drop_column('supervisor_username')
        # Recreate old constraint
        batch_op.create_unique_constraint('_employee_manager_uc', ['employee_username'])
