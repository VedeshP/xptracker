import os
import json

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask import Flask, flash, redirect, render_template, request, session, jsonify, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

import datetime

from helpers import dummy_func

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///xptracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Do not forget to set secret key

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
    ...


@app.route("/view-expenses", methods=["GET", "POST"])
def view_expenses():
    ...


@app.route("/add-earning", methods=["GET", "POST"])
def add_earning():
    ...


@app.route("/set-budget", methods=["GET", "POST"])
def set_budget():
    ...