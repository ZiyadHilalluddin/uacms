import random
import mysql.connector
from flask import Flask, redirect, render_template, flash, request, url_for, session, abort,jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import IntegerField, StringField, PasswordField, SubmitField, SelectField, HiddenField
from wtforms.validators import DataRequired, EqualTo, Length, Email, ValidationError
from flask_mail import Mail, Message
from flask_login import UserMixin, login_user, login_required, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from flask_migrate import Migrate
from flask_restful import Api, Resource, reqparse
from sqlalchemy.orm import aliased
from random import choice
from sqlalchemy.orm import joinedload, subqueryload


# Create a Flask Intance
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root@localhost/uacms'
app.config['SECRET_KEY'] = 'secret_key'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Flask-Login Stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user_login'

# Generate a key
key = Fernet.generate_key()


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


# --> DATABASE
connection = mysql.connector.connect(
    host="localhost", user="root", passwd="", database="uacms")


# --> EMAIL
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True # Your email address
app.config['MAIL_USERNAME'] = 'ziyadhilalluddin@gmail.com'
app.config['MAIL_PASSWORD'] = 'rstoajochfhyyklp'  # Your email password Your email address
app.config['MAIL_DEFAULT_SENDER'] = 'ziyadhilalluddin@gmail.com'
app.config['MAIL_MAX_EMAILS'] = None
app.config['MAIL_ASCII_ATTACHMENTS'] = False
mail = Mail(app)

# Send email notification for complaint ticket


def send_complaint_notification_email(recipient, body):
    msg = Message(
        'New Complaint Ticket Submitted',
        recipients=[recipient],
        body=body
    )
    mail.send(msg)


################################################################################ Model Database ################################################################################


################################## Users Model ##################################
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(120), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def password(self):
        raise AttributeError('Password is not readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Create a String
    def __repr__(self):
        return self.name


################################## Admin Department Model ##################################
class Person_in_Charge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # foreign key
    department_id = db.Column(db.Integer, db.ForeignKey('lookup_data.id'), nullable=False)  # foreign key
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    num_of_member = db.Column(db.Integer, nullable=False)
    department = db.relationship('Lookup_data', backref='Lookup_for_deparetment')
    
    user = db.relationship('Users', backref='user_id')

    # Create a String
    def __repr__(self):
        return self.id
    
################################## Department Member Model ##################################
class Person_in_Charge_member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # foreign key
    department_id = db.Column(db.Integer, db.ForeignKey('lookup_data.id'), nullable=False)  # foreign key
    under_supervise_id = db.Column(db.Integer, db.ForeignKey('person_in__charge.id'), nullable=True)  # foreign key
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('Users', backref='person_in_charge_members')
    department = db.relationship('Lookup_data', backref='Lookup_deparetment')
    supervisor = db.relationship('Person_in_Charge', backref='supervise_department')

    # Create a String
    def __repr__(self):
        return self.id
    
################################## PIC-Ticket Relation Model ##################################
class Complaint_Ticket_PIC_Relation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id_fk = db.Column(db.Integer, db.ForeignKey('complaint__ticket.ticket_id'), nullable=False)
    pic_id_fk = db.Column(db.Integer, db.ForeignKey('person_in__charge.id'), nullable=False)
    delegate_task = db.Column(db.Integer, db.ForeignKey('person_in__charge_member.id'), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    ticket = db.relationship('Complaint_Ticket', backref='ticket_relation')
    pic = db.relationship('Person_in_Charge', backref='pic_relation')
    delegate = db.relationship('Person_in_Charge_member', backref='delegate_relation')

    # Create a String
    def __repr__(self):
        return self.id


################################## Ticket Model ##################################
class Complaint_Ticket(db.Model):
    ticket_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type_id = db.Column(db.Integer, db.ForeignKey('lookup_data.id'), nullable=False)
    message = db.Column(db.String(200), nullable=False)
    status_id = db.Column(db.Integer, db.ForeignKey('lookup_data.id'), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('Users', backref='complaint_tickets')
    type = db.relationship('Lookup_data', foreign_keys=[type_id])
    status = db.relationship('Lookup_data', foreign_keys=[status_id])


    # Create a String

    def __repr__(self):
        return self.user_id


################################## Ticket Logs Model ##################################
class Complaint_Ticket_Logs(db.Model):
    ticket_log_id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('complaint__ticket.ticket_id'), nullable=False)  # foreign key
    task = db.Column(db.String(120), nullable=False)
    assign_by_id = db.Column(db.Integer, db.ForeignKey('person_in__charge.id'), nullable=False) #foreign key
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    ticket = db.relationship('Complaint_Ticket', backref='complaint_tickets')
    assign_by = db.relationship('Person_in_Charge', backref='pic_ticket_logs')


    # Create a String

    def __repr__(self):
        return self.ticket_log_id



################################## Lookup Model ##################################
class Lookup_data(db.Model):
    __tablename__ = 'lookup_data'
    id = db.Column(db.Integer, primary_key=True)
    group_flow = db.Column(db.Integer)
    parent = db.Column(db.Integer)
    name = db.Column(db.String(100))
    date_created = db.Column(db.TIMESTAMP)

    # Create a String
    def __str__(self):
        return self.name
    
################################################################################################################################################################
################################################################################################################################################################
################################################################################################################################################################

app.route('/api/user/add', methods=['POST'])
def add_user_api():
    data = request.get_json()
    user = Users.query.filter_by(email=data['email']).first()
    if user is not None:
        return jsonify({'message': 'User already exists'}), 400
    hashed_password = generate_password_hash(data['password'], 'sha256')
    user = Users(name=data['name'], 
                 username=data['username'], 
                 email=data['email'], 
                 password_hash=hashed_password,  
                 role=data['role'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User added successfully'}), 201

################################################################################################################################################################
################################################################################################################################################################
################################################################################################################################################################

################################################################################ Flask Form  ################################################################################

################################## Users Form ##################################
class UserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo('password_hash2', message='Password Must Match!')])
    password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
    role = StringField("Occupation", validators=[DataRequired()])
    submit = SubmitField("Submit")

################################## PIC Form ##################################
class PICForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo('password_hash2', message='Password Must Match!')])
    password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
    department = SelectField("Department", validators=[DataRequired()])
    num_of_member = IntegerField("Number of Member Department")
    submit = SubmitField("Submit")

################################## Ticket Form ##################################
class TicketForm(FlaskForm):
    user_id = IntegerField("User ID")
    type = SelectField("Category", coerce=int, validators=[DataRequired()])
    message = StringField("Message", validators=[DataRequired()])
    status = StringField("Status", validators=[DataRequired()])
    submit = SubmitField("Submit")

################################## Ticket Logs Form ##################################
class Ticket_Logs_Form(FlaskForm):
    ticket_id = IntegerField("Ticket ID", validators=[DataRequired()])
    task = StringField("Task", validators=[DataRequired()])
    assign_by = SelectField("Re-Assign Person In Charge", validators=[DataRequired()])
    submit = SubmitField("Submit")

################################## PIC-Ticket Relation Form ##################################
class Ticket_Rel_PIC_Form(FlaskForm):
    ticket_id = IntegerField("Ticket ID", validators=[DataRequired()])
    pic_id = IntegerField("PIC ID", validators=[DataRequired()])
    submit = SubmitField("Submit")

################################## Lookup Form ##################################
class Lookup_dataForm(FlaskForm):
    group_flow = IntegerField("Group Flow", validators=[DataRequired()])
    parent = IntegerField("Parent", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Submit")

################################## login Form ##################################
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

################################## PIC Member Form ##################################
class PICMemberForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo('password_hash2', message='Password Must Match!')])
    password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
    department = StringField("Department", validators=[DataRequired()], default="")
    supervise = StringField("Supervise", validators=[DataRequired()])
    submit = SubmitField("Submit")

################################## Delegate Form ##################################
class DelegateMember(FlaskForm):
    name = SelectField("Delegate To", validators=[DataRequired()])
    ticket= StringField("ticket", validators=[DataRequired()])
    submit = SubmitField("Submit")  

################################## Change Status Form ##################################
class ChangeStatus(FlaskForm):
    name = StringField("Delegate To", validators=[DataRequired()])
    ticket = IntegerField("Ticket ID", validators=[DataRequired()])
    status= SelectField("Status", validators=[DataRequired()])
    submit = SubmitField("Submit") 

################################################################################ LOGIN - LOGOUT ################################################################################

################################## LOGIN ##################################
@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash("Login Successful!!")
            if user.role == 'Admin':
                return redirect(url_for('admin_dashboard'))
            if user.role == 'PIC':
                return redirect(url_for('pic_dashboard'))
            if user.role == 'PIC MEMBER':
                return redirect(url_for('pic_member_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash("Incorrect username or password. Please try again.")
    return render_template('/user/login.html', form=form)




################################## LOGOUT ##################################
@app.route('/user/logout', methods=['GET', 'POST'])
@login_required
def user_logout():
    logout_user()
    flash("You Have been Logged Out!")
    return redirect(url_for('user_login'))


################################################################################ USER COMPLAINER INTERFACE ################################################################################

################################## ADD ##################################
@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            # Hash the Password!!!
            hashed_password = generate_password_hash(
                form.password_hash.data, "sha256")
            user = Users(name=form.name.data,
                         username=form.username.data,
                         email=form.email.data,
                         password_hash=hashed_password,
                         role=form.role.data,)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.username.data = ''
        form.email.data = ''
        form.password_hash.data = ''
        form.role.data = ''
        flash("User Added Successfully")
        return redirect(url_for('user_login'))
    return render_template("add_user.html",form=form,name=name,)


################################## UPDATE ##################################
@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    name_to_update = Users.query.get_or_404(id)
    form = UserForm(obj=name_to_update)

    if request.method == 'POST':
        form.populate_obj(name_to_update)
        try:
            db.session.commit()
            flash("User Updated Successfully!")
            return redirect(url_for('user_dashboard'))
        except:
            flash("There was an error updating this user. Please try again.")
            db.session.rollback()

    return render_template("user_dashboard.html", form=form, name_to_update=name_to_update)


################################## DELETE ##################################
@app.route('/delete/<int:id>', methods=['GET', 'POST'])
def delete(id):
    user_to_delete = Users.query.get_or_404(id)
    name = None
    form = UserForm()
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User Deleted Successfully!")
        return redirect('/user/add')
    except:
        flash("Whoops! There was a problem deleting user")
        our_users = Users.query.order_by(Users.date_added)
        return render_template("add_user.html",
                               form=form,
                               name=name,
                               our_users=our_users
                               )

################################## DASHBOARD ##################################

@app.route('/user/dashboard', methods=['GET', 'POST'])
@login_required
def user_dashboard():
    form = TicketForm()
    departments = Lookup_data.query.filter_by(parent=0, group_flow=1).all()
    form.type.choices = [(department.id, department.name) for department in departments]

    if form.validate_on_submit():
        complaint_user_id = current_user.id
        status = Lookup_data.query.filter_by(group_flow=2, name='Pending').first()
        complaint_ticket = Complaint_Ticket(
            user_id=complaint_user_id,
            type_id=form.type.data,
            message=form.message.data,
            status_id=status.id,
            date_added=datetime.utcnow()
            )
        db.session.add(complaint_ticket)
        db.session.commit()

        # create a new Complaint_Ticket_Logs object to log the assignment
        department_id = form.type.data
        person_in_charge = Person_in_Charge.query.filter(Person_in_Charge.department.has(id=department_id)).first()
        complaint_ticket_log = Complaint_Ticket_Logs(
            ticket=complaint_ticket,
            task="Assigned to person in charge",
            assign_by_id=person_in_charge.id,
            date_added=datetime.utcnow()
        )

        db.session.add(complaint_ticket_log)
        db.session.commit()

        # get a list of members in the chosen department
        members = Person_in_Charge_member.query.filter_by(department_id=department_id).all()

        # choose a random member from the list
        chosen_member = choice(members)

        # create a new Complaint_Ticket_PIC_Relation object with the chosen delegate
        complaint_ticket_pic_relation = Complaint_Ticket_PIC_Relation(
            ticket=complaint_ticket,
            pic=person_in_charge,
            delegate=chosen_member,
            date_added=datetime.utcnow()
        )

        db.session.add(complaint_ticket_pic_relation)
        db.session.commit()

        flash("Complaint submitted successfully.")
        #send_complaint_notification_email(current_user.email, form.message.data)  #Send email notification
        return redirect(url_for('user_dashboard'))
    

    user_tickets = Complaint_Ticket.query.join(Lookup_data, Complaint_Ticket.status).\
        filter(Complaint_Ticket.user_id == current_user.id).\
        filter(Lookup_data.name.in_(['Pending', 'In Process'])).all()
    
    return render_template('/user/dashboard.html', form=form, user_tickets=user_tickets)



################################################################################ ADMINISTRATOR INTERFACE ################################################################################

################################## DASHBOARD ##################################
@app.route('/administrator/dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    count_open = db.session.query(Complaint_Ticket).count()
    count_ongoing = Complaint_Ticket.query.filter(Complaint_Ticket.status.has(Lookup_data.name.in_(["Pending", "In Process"]))).count()
    count_completed = db.session.query(Complaint_Ticket).filter(Complaint_Ticket.status.has(name='Completed')).count()
    
    return render_template('/administrator/dashboard.html',count_open=count_open,count_ongoing=count_ongoing,count_completed=count_completed)


################################## LOOKUP ##################################
@app.route('/administrator/lookup.html', methods=['GET', 'POST'])
@login_required
def lookup():

    cursor = connection.cursor()
    cursor.execute("SELECT * FROM lookup_data")
    rows = cursor.fetchall()
    lookup_head = []
    lookup_value = {}

    for row in rows:
        if row[2] == 1:
            date = row[4].strftime("%d")
            if date.endswith(('11', '12', '13')):
                suffix = 'th'
            elif date.endswith('1'):
                suffix = 'st'
            elif date.endswith('2'):
                suffix = 'nd'
            elif date.endswith('3'):
                suffix = 'rd'
            else:
                suffix = 'th'
            name = {'id': row[0], 'group_flow': row[1], 'parent': row[2], 'name': row[3],
                    'date_created': row[4].strftime("%d{S} %B %Y").replace('{S}', suffix)}
            lookup_head.append(name)
        else:
            date = row[4].strftime("%d")
            if date.endswith(('11', '12', '13')):
                suffix = 'th'
            elif date.endswith('1'):
                suffix = 'st'
            elif date.endswith('2'):
                suffix = 'nd'
            elif date.endswith('3'):
                suffix = 'rd'
            else:
                suffix = 'th'
            name = {'id': row[0], 'group_flow': row[1], 'parent': row[2], 'name': row[3],
                    'date_created': row[4].strftime("%d{S} %B %Y").replace('{S}', suffix)}
            if row[1] not in lookup_value:
                lookup_value[row[1]] = []
            lookup_value[row[1]].append(name)

    
    return render_template('/administrator/lookup.html', 
                           lookup_head=lookup_head, 
                           lookup_value=lookup_value)


################### LOOKUP ADD ###################
@app.route('/insert_lookup', methods=['POST'])
@login_required
def insert_lookup():
    if request.method == "POST":
        flash("Data Inserted Successfully")
        name = request.form['name']
        group_flow = request.form['group_flow']
        parent = request.form['parent']
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO lookup_data(group_flow, parent, name) VALUES (%s, %s, %s)", (group_flow, parent, name))
        connection.commit()
        return redirect(url_for('lookup'))


@app.route('/insert_lookup_head', methods=['POST'])
@login_required
def insert_lookup_head():
    if request.method == "POST":
        cursor = connection.cursor()
        cursor.execute("SELECT MAX(group_flow) FROM lookup_data;")
        max_group_flow = cursor.fetchone()[0]
        if max_group_flow is None:
            group_flow = 1
        else:
            group_flow = max_group_flow + 1
        name = request.form['name']
        parent = request.form['parent']

        cursor.execute(
            "INSERT INTO lookup_data(group_flow, parent, name) VALUES (%s, %s, %s)", (group_flow, parent, name))
        connection.commit()
        flash("Data Inserted Successfully")
        return redirect(url_for('lookup'))


################### LOOKUP EDIT ###################
@app.route('/update_lookup', methods=['POST'])
@login_required
def update_lookup():
    if request.method == 'POST':
        id = int(request.form['id'])
        group_flow = request.form['group_flow']
        name = request.form['name']
        cursor = connection.cursor()
        cursor.execute("""
        UPDATE lookup_data SET group_flow=%s, name=%s WHERE id=%s
        """, (group_flow, name, id))
        flash("Data Update Successfully")
        return redirect(url_for('lookup'))


################### LOOKUP DELETE ###################
@app.route('/delete_lookup/<string:id_data>', methods=['GET'])
@login_required
def delete_lookup(id_data):
    flash("Record has been deleted Successfully")
    cursor = connection.cursor()
    cursor.execute("DELETE FROM lookup_data WHERE id=%s", (id_data,))
    connection.commit()
    return redirect(url_for('lookup'))


################################## PIC ##################################
@app.route('/administraton/pic_management', methods=['GET', 'POST'])
@login_required
def pic_management():
    form=UserForm()
    form_pic = PICForm()
    form_member = PICMemberForm()

    departments = Lookup_data.query.filter_by(parent=0, group_flow=1).all()
    form_pic.department.choices = [(department.id, department.name) for department in departments]
    
    if form_pic.validate_on_submit():
        user = Users.query.filter_by(email=form_pic.email.data).first()
        if user is None:
            # Hash the Password!!!
            hashed_password = generate_password_hash(form_pic.password_hash.data, "sha256")

            user = Users(name=form_pic.name.data,
                         username=form_pic.username.data,
                         email=form_pic.email.data,
                         password_hash=hashed_password,
                         role="PIC")
            
            db.session.add(user)
            db.session.commit()

            # Create a new Person_in_Charge instance with the same user_id as the newly created Users instance
            person_in_charge = Person_in_Charge(
                user_id=user.id,
                department_id=form_pic.department.data,
                num_of_member=0
                )
            db.session.add(person_in_charge)
            db.session.commit()

            flash("Person in Charge Added Successfully")
        else:
            flash("Email has already been taken")

        form_pic.name.data = ''
        form_pic.username.data = ''
        form_pic.email.data = ''
        form_pic.password_hash.data = ''

    elif form_member.validate_on_submit():
        #department_id = request.form_member.get('department_id') # get the value of the department_id hidden field
        user = Users.query.filter_by(email=form_member.email.data).first()
        if user is None:
            # Hash the Password!!!
            hashed_password = generate_password_hash(form_member.password_hash.data, "sha256")
            user = Users(name=form_member.name.data,
                        username=form_member.username.data,
                        email=form_member.email.data,
                        password_hash=hashed_password,
                        role="PIC MEMBER",
                        )
            db.session.add(user)
            db.session.commit()

            # Get the department object based on the department name
            department_name = form_member.department.data
            department = Lookup_data.query.filter_by(name=department_name).first()

            # Check if a department was found
            if department is None:
                # Handle the case where the department is not found
                raise ValueError(f"No department found with name '{department_name}'")

            # Get the department ID from the department object
            department_id = department.id
                        
            supervises = Person_in_Charge.query.filter_by(id=form_member.supervise.data).first()
            supervise_id = supervises.id

            # Create a new Person_in_Charge_member instance with the same user_id as the newly created Users instance
            person_in_charge_mem = Person_in_Charge_member(
                user_id=user.id,
                under_supervise_id=supervise_id,
                department_id=department_id, 
                date_added=datetime.utcnow())
                
            db.session.add(person_in_charge_mem)
            db.session.commit()
            person_in_charge = Person_in_Charge.query.get(supervise_id)  # some_id is the id of the person in charge you want to update
            person_in_charge.num_of_member += 1
            db.session.commit()

            flash("Department Member Added Successfully")
        else:
            flash("Email has already been taken")

        form_member.name.data = ''
        form_member.username.data = ''
        form_member.email.data = ''
        form_member.password_hash.data = ''
    
    # retrieve all persons in charge and their corresponding user and department data
    our_pic = Person_in_Charge.query.join(Users).join(Lookup_data).\
        add_columns(Person_in_Charge.id, Users.name, Users.email, Lookup_data.name, Person_in_Charge.num_of_member).\
        order_by(Person_in_Charge.date_added.desc()).all()
    
    pic_members =Person_in_Charge_member.query.join(Users).join(Lookup_data).join(Person_in_Charge).\
        add_columns(Person_in_Charge_member.id, Users.name, Users.email, Lookup_data.name).\
        order_by(Person_in_Charge_member.date_added.desc()).all()
    




    return render_template('/administrator/pic_management.html',
                            our_pic=our_pic,
                            form_pic=form_pic,
                            form_member=form_member,
                            form=form,
                            pic_members=pic_members)




@app.route('/administrator/complaint_management')
@login_required
def complaint_management():
    form = PICForm()
    cursor = connection.cursor()
    cursor.execute("select * from users")
    data = cursor.fetchall()
    cursor.close()
    our_users = Users.query.filter((Users.role == 'Student') | (Users.role == 'Lecturer')).order_by(Users.date_added)


    return render_template('/administrator/complaint_management.html', pic_management=data, our_users=our_users, form=form)


################### PIC DELETE ###################
@app.route('/delete_pic/<int:id>', methods=['GET', 'POST'])
def delete_pic(id):
    pic_to_delete = Person_in_Charge.query.get_or_404(id)
    user_to_delete = pic_to_delete.user  # get the associated User object
    form = PICForm()
    try:
        db.session.delete(pic_to_delete)
        db.session.delete(user_to_delete)  # delete the associated User object
        db.session.commit()
        flash("User Deleted Successfully!")
        return redirect(url_for('pic_management'))
    except:
        flash("Whoops! There was a problem deleting user")
        our_users = Person_in_Charge.query.order_by(Person_in_Charge.date_added)
        return render_template("pic_management.html",
                               form=form,
                               our_users=our_users
                               )



################### PIC UPDATE ###################
@app.route('/update_pic/<int:id>', methods=['GET', 'POST'])
def update_pic(id):
    pic_to_update = Person_in_Charge.query.get_or_404(id)
    form_pic = PICForm()
    if request.method == 'POST':
        pic_to_update.name = request.form['name']
        pic_to_update.department_id = request.form['department']
        pic_to_update.email = request.form['email']
        try:
            db.session.commit()
            flash("Person In Charge Updated Successfully!")
            return redirect(url_for('pic_management'))
        except:
            flash("There was an error updating this user. Please try again.")
            db.session.rollback()
    # Pre-populate the form with the existing values from the database
    form_pic.name.data = pic_to_update.user.name
    form_pic.email.data = pic_to_update.user.email
    form_pic.department.data = pic_to_update.department_id
    return render_template("pic_management.html", form=form_pic, pic_to_update=pic_to_update)




################################## TICKET ##################################
@app.route('/administrator/ticket_logs')
@login_required
def ticket_logs():
    ticket = Complaint_Ticket.query.order_by(Complaint_Ticket.date_added)
    #assign_ticket = Complaint_Ticket_Logs.query.all()

    form = Ticket_Logs_Form()
    assigned = Complaint_Ticket_Logs.query.filter_by().all()
    form.assign_by.choices = [(assign.assign_by_id, assign.ticket_log_id) for assign in assigned]

    Lookup_data_1 = aliased(Lookup_data)
    Lookup_data_2 = aliased(Lookup_data)
    Users_2 = aliased(Users)
    assign_ticket = db.session.query(
        Complaint_Ticket.ticket_id,
        Users.name.label("Complainer"),
        Lookup_data_1.name.label("Department"),
        Complaint_Ticket_Logs.task,  # Change this line to select task instead of message
        Users_2.name.label("Assign to"),
        Lookup_data_2.name.label("Status"),
        Complaint_Ticket_Logs.date_added
    ).select_from(Complaint_Ticket).join(
        Users, Complaint_Ticket.user_id == Users.id
    ).join(
        Complaint_Ticket_Logs, Complaint_Ticket.ticket_id == Complaint_Ticket_Logs.ticket_id
    ).join(
        Person_in_Charge, Complaint_Ticket_Logs.assign_by_id == Person_in_Charge.id
    ).join(
        Users_2, Person_in_Charge.user_id == Users_2.id
    ).join(
        Lookup_data_1, Person_in_Charge.department_id == Lookup_data_1.id
    ).join(
        Lookup_data_2, Complaint_Ticket.status_id == Lookup_data_2.id
    ).order_by(Complaint_Ticket.date_added).all()

    return render_template('/administrator/ticket_logs.html',
                            ticket=ticket, 
                            assign_ticket=assign_ticket,
                            form=form)


@app.route('/administrator/pic_logs')
@login_required
def pic_logs():
    return render_template('/administrator/pic_logs.html')



################################################################################ PIC ADMIN DEPARTMENT INTERFACE ################################################################################
@app.route('/pic/dashboard', methods=['GET', 'POST'])
@login_required
def pic_dashboard():
    form = PICForm(obj=current_user)
    form_delegate = DelegateMember()

    current_user_department_id = db.session.query(Lookup_data.id).\
    join(Person_in_Charge, Lookup_data.id == Person_in_Charge.department_id).\
    join(Users, Users.id == Person_in_Charge.user_id).\
    filter(Users.id == current_user.id).\
    scalar()

    # create aliases for Lookup_data table
    Lookup_data_type = aliased(Lookup_data)
    Lookup_data_status = aliased(Lookup_data)

    # query data with aliases
    data = db.session.query(Complaint_Ticket, Users.name, Lookup_data_type, Lookup_data_status)\
    .join(Users, Complaint_Ticket.user_id == Users.id)\
    .join(Lookup_data_type, Complaint_Ticket.type_id == Lookup_data_type.id)\
    .join(Lookup_data_status, Complaint_Ticket.status_id == Lookup_data_status.id)\
    .join(Complaint_Ticket_PIC_Relation, Complaint_Ticket.ticket_id == Complaint_Ticket_PIC_Relation.ticket_id_fk)\
    .join(Person_in_Charge, Complaint_Ticket_PIC_Relation.pic_id_fk == Person_in_Charge.id)\
    .filter(Person_in_Charge.department_id == current_user_department_id)\
    .all()

    current_user_department_name = db.session.query(Lookup_data.name).\
        join(Person_in_Charge, Lookup_data.id == Person_in_Charge.department_id).\
        join(Users, Users.id == Person_in_Charge.user_id).\
        filter(Users.id == current_user.id).\
        scalar()

    # query for all users with Person_in_Charge_member.department_id == current_user_department_id
    users = Users.query.join(Person_in_Charge_member).filter(Person_in_Charge_member.department_id == current_user_department_id).all()

    # create a list of tuples with the user id and name
    form_delegate.name.choices = [(user.id, user.name) for user in users]
    
    
    return render_template('/person_in_charge/dashboard.html', form=form,
                            data=data,
                            form_delegate=form_delegate,
                            current_user_department_name=current_user_department_name)


@app.route('/update_delegate/<int:ticket_id>', methods=['GET', 'POST'])
def update_delegate(ticket_id):
    current_user_department_id = db.session.query(Lookup_data.id).\
    join(Person_in_Charge, Lookup_data.id == Person_in_Charge.department_id).\
    join(Users, Users.id == Person_in_Charge.user_id).\
    filter(Users.id == current_user.id).\
    scalar()

    # query for all users with Person_in_Charge_member.department_id == current_user_department_id
    users = Users.query.join(Person_in_Charge_member).filter(Person_in_Charge_member.department_id == current_user_department_id).all()

    # create a list of tuples with the user id and name
    form_delegate = DelegateMember()
    form_delegate.name.choices = [(user.id, user.name) for user in users]

    # find the complaint ticket to delegate
    delegate_member = db.session.query(Person_in_Charge_member)\
        .join(Person_in_Charge)\
        .join(Users)\
        .filter(Person_in_Charge_member.id == form_delegate.name.data)\
        .first()

    if form_delegate.validate_on_submit():
        # retrieve the existing Complaint_Ticket_PIC_Relation object
        ticket_assign = Complaint_Ticket_PIC_Relation.query.filter_by(ticket_id_fk=ticket_id).first()
        delegate_member_id = int(form_delegate.name.data)

        person_in_charge_member = Person_in_Charge_member.query.filter_by(user_id=delegate_member_id).first()
        delegate_member_id = person_in_charge_member.id

        # update the fields
        ticket_assign.ticket_id_fk = form_delegate.ticket.data
        ticket_assign.delegate_task = delegate_member_id 

        # commit the changes
        db.session.commit()

        delegate_member_name = person_in_charge_member.user.name

        assign_by_find_id = Person_in_Charge.query.filter_by(user_id=current_user.id).first()
        assign_id = assign_by_find_id.id
        ticket_logs = Complaint_Ticket_Logs(
            ticket_id=form_delegate.ticket.data,
            task=f"Delegate Task To {delegate_member_name}",
            assign_by_id=assign_id,
            date_added=datetime.utcnow()
        )   
        db.session.add(ticket_logs)
        db.session.commit()
        flash(f"Task delegated to {delegate_member_name} successfully.")

    # create aliases for Lookup_data table
    Lookup_data_type = aliased(Lookup_data)
    Lookup_data_status = aliased(Lookup_data)
 
    # query data with aliases
    data = db.session.query(Complaint_Ticket, Users.name, Lookup_data_type, Lookup_data_status)\
    .join(Users, Complaint_Ticket.user_id == Users.id)\
    .join(Lookup_data_type, Complaint_Ticket.type_id == Lookup_data_type.id)\
    .join(Lookup_data_status, Complaint_Ticket.status_id == Lookup_data_status.id)\
    .join(Complaint_Ticket_PIC_Relation, Complaint_Ticket.ticket_id == Complaint_Ticket_PIC_Relation.ticket_id_fk)\
    .join(Person_in_Charge, Complaint_Ticket_PIC_Relation.pic_id_fk == Person_in_Charge.id)\
    .filter(Person_in_Charge.department_id == current_user_department_id)\
    .all()
          
    return render_template('/person_in_charge/dashboard.html', data=data, form_delegate=form_delegate)



@app.route('/update_dashboard_pic/<int:id>', methods=['GET', 'POST'])
def update_dashboard_pic(id):
    name_to_update = Person_in_Charge.query.get_or_404(id)
    form = PICForm(obj=name_to_update)

    if request.method == 'POST':
        form.populate_obj(name_to_update)
        try:
            db.session.commit()
            flash("User Updated Successfully!")
            return redirect(url_for('pic_dashboard'))
        except:
            flash("There was an error updating this user. Please try again.")
            db.session.rollback()

    return


################################################################################ PIC MEMBER DEPARTMENT INTERFACE ################################################################################

################################## DASHBOARD ##################################
@app.route('/pic/member/dashboard', methods=['GET', 'POST'])
@login_required
def pic_member_dashboard():
    form = ChangeStatus()
    status_option = Lookup_data.query.filter_by(group_flow=2, parent=0).all()
    form.status.choices = [(status.id, status.name) for status in status_option]

    # get the person in charge member object associated with the current user
    pic_member = Person_in_Charge_member.query.filter_by(user_id=current_user.id).first()
    tickets = Complaint_Ticket.query \
        .join(Complaint_Ticket_PIC_Relation, Complaint_Ticket.ticket_id == Complaint_Ticket_PIC_Relation.ticket_id_fk) \
        .filter(Complaint_Ticket_PIC_Relation.delegate.has(id=pic_member.id)) \
        .all()
      
    return render_template('/person_in_charge/member/dashboard.html',tickets=tickets, form=form)




@app.route('/update_status> ', methods=['GET', 'POST'])
def update_status():
    form = ChangeStatus()
    status_option = Lookup_data.query.filter_by(parent=0, group_flow=2).all()
    form.status.choices = [(status.id, status.name) for status in status_option]

    # get the person in charge member object associated with the current user
    pic_member = Person_in_Charge_member.query.filter_by(user_id=current_user.id).first()
    tickets = Complaint_Ticket.query \
        .join(Complaint_Ticket_PIC_Relation, Complaint_Ticket.ticket_id == Complaint_Ticket_PIC_Relation.ticket_id_fk) \
        .filter(Complaint_Ticket_PIC_Relation.delegate.has(id=pic_member.id)) \
        .all()
    
    if request.method == "POST":
        ticket_id = form.ticket.data    
        new_status = form.status.data
        ticket = Complaint_Ticket.query.filter_by(ticket_id=ticket_id).first()
        ticket.status_id = new_status
        db.session.commit()
        flash('Ticket status has been updated!', 'success')
        return redirect(url_for('pic_member_dashboard'))
        


    return render_template('/person_in_charge/member/dashboard.html',tickets=tickets, form=form)



# Create custom Error Page
# Invalid URL
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

# Internal Server Error
@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"), 500


with app.app_context():
    db.create_all()

