from flask import jsonify, request
from uacms import Users, app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

db = SQLAlchemy(app)

@app.route('/api/user/add', methods=['POST'])
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
