"""add role pic model

Revision ID: 1d57f1faf956
Revises: 60c3e0b695e6
Create Date: 2023-03-26 12:31:47.904499

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1d57f1faf956'
down_revision = '60c3e0b695e6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('person_in__charge', schema=None) as batch_op:
        batch_op.add_column(sa.Column('role', sa.String(length=120), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('person_in__charge', schema=None) as batch_op:
        batch_op.drop_column('role')

    # ### end Alembic commands ###
