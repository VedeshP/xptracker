import os
import json

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask import Flask, flash, redirect, render_template, request, session, jsonify, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

import datetime

import sqlitecloud

from helpers import dummy_func

app = Flask(__name__)

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///xptracker.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db = SQLAlchemy(app)

# Do not forget to set secret key


db = sqlitecloud.connect("")


hello = dummy_func()
print(hello)


@app.route("/", methods = ["GET", "POST"])
def index():
    return render_template("index.html", login=True)


@app.route("/login", methods = ["GET", "POST"])
def login():
    if request.method == "POST":
        ...
    else:
        return render_template("login.html", login=False)


@app.route("/signup", methods = ["GET", "POST"])
def signup():
    if request.method == "POST":
        ...
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