import os
import re
import random
import cs50

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, json
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required
from flask_mail import Mail, Message

# Configure application
app = Flask(__name__)
app.config['MAIL_USERNAME'] = 't4sgedu@gmail.com'
app.config['MAIL_PASSWORD'] = 'education123!'
app.config["MAIL_PORT"] = 587
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config['MAIL_USE_TLS'] = True
mail = Mail(app)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///vaccines_database.db")
COUNTRIES = ['United States', 'Canada', 'Mexico', 'United Kingdom', 'France', 'China', 'Spain']
    
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()

    app.logger.info(generate_password_hash('admin'))

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # If user clicks on forgot password button
        if request.form.get("forgot"):
            return redirect("/forgotpassword")

        # Ensures username was submitted
        if not request.form.get("username"):
            return render_template("login.html", error = "Please input a username.")

        # Ensures password was submitted
        elif not request.form.get("password"):
            return render_template("login.html", error = "Please provide a password.")

        # Queries database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensures username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            return render_template("login.html", error = "Invalid username and/or password.")

        # Remembers which user has logged in
        session["user_id"] = rows[0]["id"]
        session["admin"] = rows[0]["admin"]
        session["user_country"] = rows[0]['user_country']

        # Redirects user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html", alert=0)

@app.route("/forgotpassword", methods=["GET", "POST"])
def forgotpassword():
    """Allows users to recover their account via email if they forgot password"""
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("apology.html", top = 400, bottom = "Please input a username.")

        # Generates a 6-digit code that will serve as the account's new temporary passworrd
        code = ""
        for i in range(6):
            code += str(random.randint(0, 9))

        # Retrieves the email associated with the given username
        rows = db.execute("SELECT email FROM users WHERE username = ?", request.form.get("username"))

        # Checks to see if the username entered is valid
        if len(rows) != 1:
            return render_template("apology.html", top = 400, bottom = "invalid username")
        email = rows[0]['email']

        # Sends email notifying user of password reset
        message = Message("Your Password Has Been Reset", sender = app.config["MAIL_USERNAME"], recipients=[email])
        message.body = "Your new (temporary) password is: " + code
        mail.send(message)

        # Resets password to account
        db.execute("UPDATE users SET hash = ? WHERE username = ?", generate_password_hash(
            code), request.form.get("username"))

        return render_template("resetpassword.html", forgot=1)
    else:
        return render_template("forgotpassword.html")

@app.route("/resetpassword", methods=["GET", "POST"])
def resetpassword():
    """Allows the user to reset password"""
    if request.method == "POST":
        # Ensures a username is entered
        if not request.form.get("username"):
            return render_template("apology.html", top = 400, bottom = "please enter username")
        
        # Retrieves the information of the user currently logged in
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensures username is valid
        if len(rows) == 0:
            return render_template("apology.html", top = 400, bottom = "invalid username")

        # Checks to see if user entered correct old password
        if not check_password_hash(rows[0]["hash"], request.form.get("old_password")):
            return render_template("apology.html", top = 400, bottom = "incorrect password")

        # Ensures user fills in a new password
        elif not request.form.get("new_password"):
            return render_template("apology.html", top = 400, bottom = "must provide new password")

        # Ensures passwords are different
        elif request.form.get("old_password") == request.form.get("new_password"):
            return render_template("apology.html", top = 400, bottom = "new password cannot equal old password")

        # Ensures that new passwords match
        elif not request.form.get("confirmation") == request.form.get("new_password"):
            return render_template("apology.html", top = 400, bottom = "new passwords do not match")

        # Updates the finance.db tables
        username = rows[0]['username']
        db.execute("UPDATE users SET hash = ? WHERE username = ?", generate_password_hash(
            request.form.get("new_password")), username)

        return redirect("/")
    else:
        return render_template("resetpassword.html", forgot = 0)

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Ensures user filled out a username
        if not request.form.get("username"):
            return render_template("apology.html", top = 400, bottom = "Please input a username.")

        # Ensures username is valid
        elif len(db.execute("SELECT * FROM users WHERE username = ?", request.form.get(
                "username"))) == 1:
            return render_template("apology.html", top = 400, bottom = "Username is already taken.")

        # Ensures user fills out required fields
        elif not request.form.get("password"):
            return render_template("apology.html", top = 400, bottom = "Must provide a password.")

        elif not request.form.get("confirmation") == request.form.get("password"):
            return render_template("apology.html", top = 400, bottom = "Passwords do not match.")

        elif not request.form.get("email"):
            return render_template("apology.html", top = 400, bottom = "Please input an email.")
        
        elif not request.form.get("country"):
            return render_template("apology.html", top = 400, bottom = "Please select a country.")

        # Ensures email has not already been used/associated with another account
        elif len(db.execute("SELECT * FROM users WHERE email = ?", request.form.get(
                "email"))) == 1:
            return render_template("apology.html", top = 400, bottom = "Email is already used.")

        # Records necessary information in session
        session['firstname'] = request.form.get("firstname")
        session['lastname'] = request.form.get("lastname")
        session['username'] =  request.form.get("username")
        session['password'] = generate_password_hash(request.form.get("password"))
        session['user_country'] = request.form.get("country")

        email = request.form.get("email")
        # Generates 6-digit verification code
        code = ""
        for i in range(6):
            code += str(random.randint(0, 9))

        # Sends email with verification code to user
        message = Message("Verification Email", sender = app.config["MAIL_USERNAME"], recipients=[email])
        message.body = "Please confirm your email by entering the following verification code: " + code
        mail.send(message)

        session['email'] = email
        session['code'] = code

        return redirect("/verifyemail")
    else:
        return render_template("register.html", countries=COUNTRIES)

@app.route("/verifyemail", methods=["GET", "POST"])
def verify_email():
    """Verifies the user's email and allows them to register"""
    if request.method == "POST":
        # User wants the email to be resent
        if request.form.get("re-send"):
            # Generates new code
            code = ""
            for i in range(6):
                code += str(random.randint(0, 9))
            # Sends a new email and updates code
            message = Message("Verification Email", sender = app.config["MAIL_USERNAME"], recipients=['alyssahuang@college.harvard.edu'])
            message.body = "Please confirm your email by entering the following verification code: " + code
            mail.send(message)
            session['code'] = code
            return redirect("/verifyemail")
        elif request.form.get("submit"):
            # Checks if verification code is correct
            if not request.form.get("code") == session['code']:
                return render_template("apology.html", top = 400, bottom = "Incorrect verification code.")

            # Updates users database and registers user
            db.execute("INSERT INTO users (firstname, lastname, username, password, admin, email, user_country) VALUES (?, ?, ?, ?, ?, ?, ?)",
                session['firstname'], session['lastname'], session['username'], session['password'], 0, session['email'], session['user_country'])

            # Clears session
            session.clear()

            # Let user know they're registered
            return render_template("login.html", alert=1)
    else:
        return render_template("verifyemail.html")

# home page
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    # stores admin status
    admin = session['admin']

    # queries database for vaccine information
    names = db.execute('SELECT name, amount_distributed, amount_left FROM vaccines JOIN entries ON vax_id = vaccines.id')
    vaccines = {}
    for name in names:
        vaccines[name['name']] = [name['amount_distributed'], name['amount_left']]

    if request.method == "POST":
        if admin:
            # selected a vaccine (store in session)
            if not request.form.get('vaccine_options'):
                return render_template('index.html', vaccines=vaccines, admin=admin, error="Please select a vaccine.")
            session['vaccine'] = request.form.get('vaccine_options')
            session['country'] = request.form.get('countries_options')
            return redirect("/editvaccine")
        else:
            # redirect dependent on add/delete
            if request.form.get("add"):
                return redirect("/addvaccine")
            return redirect("/deletevaccine")
    
    else:
        if admin:
            # display drop down menu with all vaccine options
            names = db.execute("SELECT name FROM countries")
            countries = []
            for name in names:
                countries.append(name['name'])
            names = db.execute("SELECT name FROM vaccines")
            vaccines = []
            for name in names:
                vaccines.append(name['name'])
            return render_template('index.html', vaccines=vaccines, countries = countries, admin=admin)
        else:
            # display starred vaccines (shortlist)
            country_id = db.execute('SELECT id FROM countries WHERE name = ?', session['user_country'])[0]['id']
            names = db.execute('SELECT name, amount_distributed, amount_left FROM vaccines JOIN entries ON vax_id = vaccines.id WHERE vaccines.id IN (SELECT vax_id FROM starred WHERE user_id = ?) AND country_id = ?', session['user_id'], country_id)
            starred = {}
            for name in names:
                starred[name['name']] = [name['amount_left']]
            first = 0
            if len(names) == 0:
                first = 1
            return render_template('index.html', starred=starred, admin=admin, first=first, country=session['user_country'])
# feature for normal account
@app.route("/addvaccine", methods=["GET", "POST"])
@login_required
def addvaccine():
    if request.method == "POST":
        # alter starred db to add tracked vaccine(s)
        if not request.form.get("vaccine"):
            return render_template('addvaccine.html', error='Please select at least one vaccine.')
        vaccine_ids = request.form.getlist("vaccine")
        for vaccine_id in vaccine_ids:
            vax_id = db.execute('SELECT id FROM vaccines WHERE name = ?', vaccine_id)[0]['id']
            db.execute("INSERT INTO starred (user_id, vax_id) VALUES (?, ?)", session['user_id'], vax_id)
        return redirect("/")
    else:
        # show all the unstarred vaccines
        names = db.execute('SELECT name FROM vaccines WHERE NOT id IN (SELECT vaccines.id FROM vaccines JOIN starred ON vax_id = vaccines.id WHERE user_id = ?)', session['user_id'])
        vaccines = []
        for name in names:
            vaccines.append(name['name'])
        app.logger.info(vaccines)
        return render_template('addvaccine.html', vaccines=vaccines)

# feature for normal account
@app.route("/deletevaccine", methods=["GET", "POST"])
@login_required
def deletevaccine():
    if request.method == "POST":
        # alter starred db to delete tracked vaccine(s)
        if not request.form.get("vaccine"):
            return render_template('deletevaccine.html', error='Please select at least one vaccine.')
        vaccine_ids = request.form.getlist("vaccine")
        for vaccine_id in vaccine_ids:
            vax_id = db.execute('SELECT id FROM vaccines WHERE name = ?', vaccine_id)[0]['id']
            db.execute("DELETE FROM starred WHERE user_id = ? AND vax_id = ?", session['user_id'], vax_id)
        return redirect("/")
    else:
        # show all the starred vaccines
        names = db.execute('SELECT name FROM vaccines JOIN starred ON vax_id = vaccines.id WHERE user_id = ?', session['user_id'])
        vaccines = []
        for name in names:
            vaccines.append(name['name'])
        return render_template('deletevaccine.html', vaccines=vaccines)

# administrative access required
@app.route("/editvaccine", methods=["GET", "POST"])
@login_required
def editvaccine():
    if request.method == "POST":
        if not request.form.get("distributed") or not request.form.get("remaining"):
            return render_template('editvaccine.html', error='Please fill out both blanks.')
        
        vax_id = db.execute('SELECT id FROM vaccines WHERE name = ?', session['vaccine'])[0]['id']
        db.execute("UPDATE entries SET amount_distributed = ?, amount_left = ? WHERE vax_id = ?", 
            request.form.get("distributed"), request.form.get("remaining"), vax_id)
        return redirect('/')
    else:
        vax_id = db.execute('SELECT id FROM vaccines WHERE name = ?', session['vaccine'])[0]['id']
        country_id = db.execute('SELECT id FROM countries WHERE name = ?', session['country'])[0]['id']
        info = db.execute('SELECT amount_left, amount_distributed FROM entries WHERE vax_id = ? AND country_id = ?', vax_id, country_id)[0]
        return render_template('editvaccine.html', vaccine = session['vaccine'], distributed=info['amount_distributed'], remaining = info['amount_left'])