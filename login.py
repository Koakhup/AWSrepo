from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import MySQLConnector
from flask_bcrypt import Bcrypt
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
app = Flask(__name__)
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app,'the_wall')
app.secret_key = 'this is secret_key'
name = re.compile(r'^[a-zA-Z]')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods = ['post'])
def register():
    error = 0
    if len(request.form['first_name']) < 2:
        error += 1
        flash("First name needs more characters")
    elif not name.match(request.form['first_name']):
        error += 1
        flash("Enter the valid first name")
    if len(request.form['last_name']) < 2:
        error += 1
        flash("Last name needs more characters")
    elif not name.match(request.form['last_name']):
        error += 1
        flash("Enter the valid last name")

    if not EMAIL_REGEX.match(request.form['email']):
        error += 1
        flash("Enter Valid Email")
    if len(request.form['password']) < 9 :
        error += 1
        flash(" Password needs more characters")
    if request.form['password'] != request.form['confirm']:
        error += 1
        flash("Passwords do not match")

    if error == 0:
        hashed = bcrypt.generate_password_hash(request.form['password'])
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (:first_name, :last_name, :email, :pw, NOW(), NOW())"
        data = { 'first_name': request.form['first_name'], 'last_name': request.form['last_name'], 'email': request.form['email'], 'pw': hashed }
        mysql.query_db(query, data)
        # session['user_id'] =['user_id']
        return redirect('/login')
    return redirect ('/')

@app.route('/login', methods =['post'])
def log():
    error = 0
    query = "SELECT id, password FROM users WHERE email='{}'".format(request.form['email'])
    user = mysql.query_db(query)
    print user
    if len(user) < 1:
        flash("Email doesn't exit")
        error += 1
    elif not bcrypt.check_password_hash(user[0]['password'], request.form['password']):
        flash("wrong password")
        error += 1
    elif error == 0:
        user_id = mysql.query_db(query)
        session['user_id'] =['user_id']
        session['user_id'] = user[0]['id']
        return redirect('/login')
    return redirect('/')
@app.route('/login')
def login():
    query = "SELECT messages.id, messages.message, messages.created_at, users.first_name, users.last_name FROM messages JOIN users ON users.id = messages.user_id"
    all_messages = mysql.query_db(query)

    query = "SELECT comments.message_id, comments.comment, comments.created_at, users.first_name, users.last_name FROM comments JOIN users ON users.id = comments.user_id"
    all_comments = mysql.query_db(query)

    return render_template ('login.html', messages = all_messages, comments = all_comments)

@app.route('/delete', methods = ['post'])
def logout():
    session.clear()
    return redirect('/')
    
@app.route('/message', methods = ['post'])
def message():
    print request.form
    print session
    query = "INSERT INTO messages (message, user_id, created_at, updated_at) VALUES (:message, :user_id, NOW(), NOW())"
    values = { "message": request.form['message'], "user_id": session['user_id']}
    mysql.query_db(query, values)
    return redirect('/login')

@app.route('/comment/<message_id>', methods = 'post')
def comment(message_id):
    query = "INSERT INTO comments (comment, user_id, message_id, created_at, updated_at) VALUES (:comment, :user_id, :message_id, NOW(), NOW())"
    values = { "comment": request.form['comment'], "user_id": session['user_id'], "message_id": message_id}
    mysql.query_db(query, values)
    return redirect('/login')
app.run(debug=True)
