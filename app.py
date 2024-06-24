import os
import json
from contextlib import contextmanager

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask import Flask, flash, redirect, render_template, request, session, jsonify, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

import datetime

import sqlitecloud

from helpers import login_required, check_password_strength_basic, apology

app = Flask(__name__)

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///xptracker.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db = SQLAlchemy(app)

# Get the secret key from an environment variable
# app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SECRET_KEY'] = 'trial-secret-key-123'
# Also add login required deocrator on required routes/functions
# Add know more, about us and updates templates

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@contextmanager
def get_db_connection():
    db = sqlitecloud.connect("")
    try:
        yield db  # Setup: Provide the connection to the block
    finally:
        db.close()  # Teardown: Close the connection after the block


@app.route("/", methods = ["GET", "POST"])
def index():
    return render_template("index.html", login=True)


@app.route("/login", methods = ["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":
        # Get details from the form
        username = request.form.get("username")
        username = username.strip()
        password = request.form.get("password")
        # Ensure username was submitted
        if not username:
            return apology("Must provide username", 403)

        # Ensure password was submitted
        elif not password:
            return apology("Must provide password", 403)

        with get_db_connection() as db:
            rows = db.execute("SELECT * FROM  users where username = ?", (username,))
        rows = [list(row) for row in rows]

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0][2], password 
        ):
            return apology("invalid username and/or password", 403)
        return jsonify(rows)

    else:
        return render_template("login.html", login=False)


@app.route("/signup", methods = ["GET", "POST"])
def signup():
    """Register user"""
    # Forget any user_id
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        username = username.strip()
        display_name = request.form.get("display_name")
        email = request.form.get("email")
        email = email.strip()
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        for i in username:
            if i == ' ':
                return apology("username must not contain space", 400)
        if not username:
            return apology("Must provide username", 400)
        if not display_name:
            return apology("Must provide Display Name", 400)
        if not email:
            return apology("Please provide Email Id", 400)
        if not password:
            return apology("Please set a password", 400)
        if not confirm_password:
            return apology("Must confirm password", 400)
        if password != confirm_password:
            return apology("Both password must be same", 403)

        if check_password_strength_basic(password):
            return apology("Password must contain atleast 8 characters, a special character, letters and numbers", 403)
        
        # Get password hash to store in the database
        hash = generate_password_hash(password)

        try:
            # Register user 
            # Add user details to the database
            with get_db_connection() as db:
                db.execute("BEGIN")
                db.execute(
                    """
                    INSERT INTO users (username, password, email, display_name)
                    VALUES (?, ?, ?, ?)
                    """,
                    (username, hash, email, display_name)
                )
                db.execute("COMMIT")
        except Exception as e:
            # Rollback execution on error
            db.execute("ROLLBACK")
            error_message = str(e)
            if "UNIQUE constraint failed: users.username" in error_message:
                return apology("Username already exists")
            elif "UNIQUE constraint failed: users.email_id" in error_message:
                return apology("Email ID already exists")
            else:
                return apology("An integrity error occurred: " + error_message)
        flash("Signed Up! Login to Proceed")
        return redirect(url_for('login'))
    else:
        return render_template("signup.html", login=False)

    
@app.route("/add-expenses", methods=["GET", "POST"])
def add_expense():
    user_id = 1
    #user_id = session["user_id"]
    if request.method == "POST":
        ...
    else:
        # mc - main category 
        mc_query = "SELECT * FROM main_category"
        sc_query = """
        SELECT sub_category.*, main_category.category 
        FROM sub_category 
        JOIN main_category 
        WHERE sub_category.main_category_id = main_category.id
        """
        uc_query = "SELECT * FROM user_category WHERE user_id = ?"

        with get_db_connection() as db:
            mc = db.execute(mc_query).fetchall()
            mc_columns = [desc[0] for desc in db.execute(mc_query).description]
            mc_rows = [dict(zip(mc_columns, row)) for row in mc]    
            sc = db.execute(sc_query).fetchall()
            sc_columns = [desc[0] for desc in db.execute(sc_query).description]
            sc_rows = [dict(zip(sc_columns, row)) for row in sc]    
            uc = db.execute(uc_query, (user_id,)).fetchall()
            uc_columns = [desc[0] for desc in db.execute(uc_query, (user_id,)).description]
            uc_rows = [dict(zip(uc_columns, row) for row in uc)]

        return render_template("add-expenses.html", uc_rows=uc_rows, mc_rows=mc_rows, sc_rows=sc_rows)


@app.route("/view-expenses", methods=["GET", "POST"])
def view_expenses():
    ...


@app.route("/add-earning", methods=["GET", "POST"])
def add_earning():
    ...


@app.route("/set-budget", methods=["GET", "POST"])
def set_budget():
    ...


@app.route("/testing")
def testing():
    sub_category_query = "SELECT * FROM sub_category"
    rows = db.execute(sub_category_query).fetchall()
    # rows = rows_db.fetchall()
    # Get the column names
    column_names = [desc[0] for desc in db.execute(sub_category_query).description]
    modified_rows = [dict(zip(column_names, row)) for row in rows]
    # modified_rows = [dict(row._mapping) for row in rows]
    return jsonify(modified_rows)