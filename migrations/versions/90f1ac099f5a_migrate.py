"""migrate

Revision ID: 90f1ac099f5a
Revises: 9abb3bf69c54
Create Date: 2023-03-27 15:35:04.023938

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '90f1ac099f5a'
down_revision = '9abb3bf69c54'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('complaint__ticket_pic__relation', schema=None) as batch_op:
        batch_op.add_column(sa.Column('delegate_task', sa.Integer(), nullable=False))
        batch_op.create_foreign_key(None, 'person_in__charge_member', ['delegate_task'], ['id'])

    with op.batch_alter_table('person_in__charge_member', schema=None) as batch_op:
        batch_op.alter_column('under_supervise_id',
               existing_type=mysql.INTEGER(display_width=11),
               nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('person_in__charge_member', schema=None) as batch_op:
        batch_op.alter_column('under_supervise_id',
               existing_type=mysql.INTEGER(display_width=11),
               nullable=False)

    with op.batch_alter_table('complaint__ticket_pic__relation', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('delegate_task')

    # ### end Alembic commands ###
