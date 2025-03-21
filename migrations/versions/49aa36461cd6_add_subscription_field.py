"""Add subscription field

Revision ID: 49aa36461cd6
Revises: 
Create Date: 2025-01-31 00:08:45.758613

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '49aa36461cd6'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('subscription', sa.String(length=10), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('subscription')

    # ### end Alembic commands ###
