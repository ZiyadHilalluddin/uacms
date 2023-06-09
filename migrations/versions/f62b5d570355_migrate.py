"""migrate

Revision ID: f62b5d570355
Revises: 1d57f1faf956
Create Date: 2023-03-26 14:51:41.954871

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'f62b5d570355'
down_revision = '1d57f1faf956'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('person_in__charge', schema=None) as batch_op:
        batch_op.add_column(sa.Column('user_id', sa.Integer(), nullable=False))
        batch_op.drop_index('email')
        batch_op.create_foreign_key(None, 'users', ['user_id'], ['id'])
        batch_op.drop_column('username')
        batch_op.drop_column('email')
        batch_op.drop_column('name')
        batch_op.drop_column('role')
        batch_op.drop_column('password_hash')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('person_in__charge', schema=None) as batch_op:
        batch_op.add_column(sa.Column('password_hash', mysql.VARCHAR(length=120), nullable=False))
        batch_op.add_column(sa.Column('role', mysql.VARCHAR(length=120), nullable=False))
        batch_op.add_column(sa.Column('name', mysql.VARCHAR(length=200), nullable=False))
        batch_op.add_column(sa.Column('email', mysql.VARCHAR(length=120), nullable=False))
        batch_op.add_column(sa.Column('username', mysql.VARCHAR(length=200), nullable=False))
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.create_index('email', ['email'], unique=False)
        batch_op.drop_column('user_id')

    # ### end Alembic commands ###
