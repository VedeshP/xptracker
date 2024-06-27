import os
import json
from contextlib import contextmanager

from flask import Flask, flash, redirect, render_template, request, session, jsonify, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

import datetime

import sqlitecloud

from helpers import login_required, check_password_strength_basic, apology

app = Flask(__name__)


# Get the secret key from an environment variable
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


SQLITECLOUD_DATABASE_URL = os.getenv('SQLC_DB_URL')

@contextmanager
def get_db_connection():
    db = sqlitecloud.connect(SQLITECLOUD_DATABASE_URL)
    try:
        yield db  # Setup: Provide the connection to the block
    finally:
        db.close()  # Teardown: Close the connection after the block


@app.route("/", methods = ["GET", "POST"])
@login_required
def index():
    user_id = session["user_id"]
    with get_db_connection() as db:
        rows = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    rows = [list(row) for row in rows]
    display_name = rows[0][4]
    return render_template("index.html", display_name=display_name)


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
        
        # Remember which user has logged in
        session["user_id"] = rows[0][0]

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log User out"""
    # Forget user
    session.clear()
    return redirect("/know-more")


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
        with get_db_connection() as db:
            try:
            # Register user 
            # Add user details to the database
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
        return render_template("signup.html")

    
@app.route("/add-expenses", methods=["GET", "POST"])
@login_required
def add_expense():
    user_id = session["user_id"]
    if request.method == "POST":

        # Retrieve form data
        amount = request.form.get("amount")
        date = request.form.get("date")
        main_category = request.form.get("main_category")
        sub_category_check = request.form.get("sub_category_check")
        sub_category = request.form.get("sub_category")
        custom_category_check = request.form.get("custom_category_check")
        custom_category = request.form.get("custom_category")
        expense_description = request.form.get("description")

        # Validate form data
        if not custom_category_check and not main_category:
            return apology("Must select at least main category", 403)

        if sub_category_check and not sub_category:
            return apology("Do you want to select a sub category?", 403)

        if custom_category_check and not custom_category:
            return apology("Must add Custom Category", 403)

        if not amount:
            return apology("Must add amount", 403)

        if not date:
            return apology("Must add date", 403)

        # Handle optional sub_category and custom_category
        if not sub_category_check:
            sub_category = None

        if not custom_category_check:
            custom_category = None
        if not expense_description:
            expense_description = None

        amount = int(amount)

        with get_db_connection() as db:
            try:
                db.execute("BEGIN")
                db.execute(
                    """
                    INSERT INTO expenses 
                    (user_id, main_category_id, sub_category_id, user_category_id, amount, date, expense_description)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (user_id, main_category, sub_category, custom_category, amount, date, expense_description)
                )
                db.execute("COMMIT")
            except Exception as e:
                db.execute("ROLLBACK")
                return apology("An error occured")
            
            flash("Expense Added")
            return redirect(url_for('add_expense'))

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
            uc_rows = [dict(zip(uc_columns, row)) for row in uc]


        return render_template("add-expenses.html", uc_rows=uc_rows, mc_rows=mc_rows, sc_rows=sc_rows)


@app.route("/view-expenses", methods=["GET", "POST"])
@login_required
def view_expenses():
    user_id = session["user_id"]
    if request.method == "POST":
        period_type = request.form.get("period_type")
        period_year = request.form.get("period_year")
        if period_year:
            period_year = int(period_year)
        else:
            period_year = datetime.datetime.now().year

        period = int(request.form.get("period"))

        with get_db_connection() as db:
            # Query for detailed expenses
            query = """
                SELECT e.date, mc.category AS main_category, sc.sub_category, uc.category AS user_category, e.amount, e.expense_description
                FROM expenses e
                LEFT JOIN main_category mc ON e.main_category_id = mc.id
                LEFT JOIN sub_category sc ON e.sub_category_id = sc.id
                LEFT JOIN user_category uc ON e.user_category_id = uc.id
                WHERE e.user_id = ?
            """
            
            if period_type == 'monthly':
                query += " AND strftime('%Y', e.date) = ? AND strftime('%m', e.date) = ?"
                params = (user_id, str(period_year), str(period).zfill(2))
            elif period_type == 'quarterly':
                query += " AND strftime('%Y', e.date) = ? AND (strftime('%m', e.date) IN (?, ?, ?))"
                months = {
                    1: ('01', '02', '03'),
                    2: ('04', '05', '06'),
                    3: ('07', '08', '09'),
                    4: ('10', '11', '12')
                }
                params = (user_id, str(period_year), *months[period])
            elif period_type == 'yearly':
                query += " AND strftime('%Y', e.date) = ?"
                params = (user_id, str(period_year))
            
            detailed_expenses = db.execute(query, params).fetchall()
            column_names_d_e = [desc[0] for desc in db.execute(query, params).description]
            detailed_expenses_dict = [dict(zip(column_names_d_e, row)) for row in detailed_expenses]

            # return jsonify(detailed_expenses_dict)

            # Query for total expenses by category
            query = """
                SELECT category, SUM(amount) AS total FROM (
                    SELECT mc.category AS category, e.amount
                    FROM expenses e
                    LEFT JOIN main_category mc ON e.main_category_id = mc.id
                    WHERE e.user_id = ? AND strftime('%Y', e.date) = ?
                    {period_condition}
                UNION ALL
                    SELECT uc.category AS category, e.amount
                    FROM expenses e
                    LEFT JOIN user_category uc ON e.user_category_id = uc.id
                    WHERE e.user_id = ? AND strftime('%Y', e.date) = ?
                    {period_condition}
                )
                GROUP BY category
            """

            if period_type == 'monthly':
                period_condition = "AND strftime('%m', e.date) = ?"
                params = (user_id, str(period_year), str(period).zfill(2), user_id, str(period_year), str(period).zfill(2))
            elif period_type == 'quarterly':
                period_condition = "AND (strftime('%m', e.date) IN (?, ?, ?))"
                params = (user_id, str(period_year), *months[period], user_id, str(period_year), *months[period])
            elif period_type == 'yearly':
                period_condition = ""
                params = (user_id, str(period_year), user_id, str(period_year))

            query = query.format(period_condition=period_condition)

            category_summary = db.execute(query, params).fetchall()
            column_names_c_summary = [desc[0] for desc in db.execute(query, params).description]
            category_summary_dict = [dict(zip(column_names_c_summary, row)) for row in category_summary]
            for row in category_summary_dict:
                row['total'] = int(row['total'])
            category_summary_dict = [
                item for item in category_summary_dict if item['category'] is not None
            ]

            # return jsonify(category_summary_dict)

            # Query for total expenses by type
            query = """
                SELECT 
                    COALESCE(mc.type, uc.type) AS category_type, 
                    SUM(e.amount) AS total 
                FROM expenses e
                LEFT JOIN main_category mc ON e.main_category_id = mc.id
                LEFT JOIN user_category uc ON e.user_category_id = uc.id
                WHERE e.user_id = ? AND strftime('%Y', e.date) = ?
                {period_condition}
                GROUP BY category_type
            """

            if period_type == 'monthly':
                period_condition = "AND strftime('%m', e.date) = ?"
                params = (user_id, str(period_year), str(period).zfill(2))
            elif period_type == 'quarterly':
                period_condition = "AND (strftime('%m', e.date) IN (?, ?, ?))"
                params = (user_id, str(period_year), *months[period])
            elif period_type == 'yearly':
                period_condition = ""
                params = (user_id, str(period_year))

            query = query.format(period_condition=period_condition)

            type_summary = db.execute(query, params).fetchall()
            column_names_t_summary = [desc[0] for desc in db.execute(query, params).description]
            type_summary_dict = [dict(zip(column_names_t_summary, row)) for row in type_summary]

            for row in type_summary_dict:
                row['total'] = int(row['total'])

            # return jsonify(type_summary_dict)

            # Query for budget
            budget_query = """
                SELECT amount
                FROM budget
                WHERE user_id = ? AND period_type = ? AND period_year = ?
            """
            if period_type != 'yearly':
                budget_query += " AND period = ?"
                budget_params = (user_id, period_type, period_year, period)
            else:
                budget_params = (user_id, period_type, period_year)

            budget = db.execute(budget_query, budget_params).fetchall()
            column_names_budget = [desc[0] for desc in db.execute(budget_query, budget_params).description]
            budget_dict = [dict(zip(column_names_budget, row)) for row in budget]
            total_budget = budget_dict[0]['amount'] if budget_dict else 0
            total_budget = float(total_budget)
            # return jsonify(total_budget)
            total_expenses = sum(expense['total'] for expense in category_summary_dict)
            if total_budget != 0:
                predicted_savings = total_budget - total_expenses
            else:
                predicted_savings = "Not applicable as no budget set for this period"

            # return jsonify(predicted_savings)


        return render_template(
            "view-expenses.html", 
            detailed_expenses_dict=detailed_expenses_dict,
            category_summary_dict=category_summary_dict,
            type_summary_dict=type_summary_dict,
            predicted_savings=predicted_savings,
            total_expenses=total_expenses,
            total_budget=total_budget
        )

    else:
        return render_template("expense-filter.html")


@app.route("/add-category", methods=["GET", "POST"])
@login_required
def add_category():
    user_id = session["user_id"]
    if request.method == "POST":

        category = request.form.get("category")
        description = request.form.get("description")
        expense_type = request.form.get("type")

        if not category:
            return apology("Must give category/item", 403)
        if not description:
            description = None
        if not expense_type:
            return apology("Must specify Expense Type", 403)

        with get_db_connection() as db:
            try:
                db.execute("BEGIN")
                db.execute(
                    """
                    INSERT INTO user_category
                    (user_id, category, description, type)
                    VALUES (?, ?, ?, ?)
                    """,
                    (user_id, category, description, expense_type)
                )
                db.execute("COMMIT")
            except Exception as e:
                db.execute("ROLLBACK")
                return apology(f"An error occured {str(e)}")
        
        flash("Category Added")
        return redirect("/")
        
    else:
        return render_template("add-category.html")


@app.route("/add-earning", methods=["GET", "POST"])
@login_required
def add_earning():
    user_id = session["user_id"]
    if request.method == "POST":
        amount = request.form.get("amount")
        date = request.form.get("date")
        description = request.form.get("description")
        source = request.form.get("source")

        if not amount:
            return apology("Enter an Amount", 403)
        if not date:
            return apology("Enter an Date", 403)

        amount = int(amount)
        with get_db_connection() as db:
            try:
                db.execute("BEGIN")
                db.execute(
                    """
                    INSERT INTO earnings 
                    (user_id, amount, date, description, source)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (user_id, amount, date, description, source)
                )
                db.execute("COMMIT")
            except Exception as e:
                db.execute("ROLLBACK")        
                return apology(f"An error occured {str(e)}")
        
        return redirect("/")

    else:
        return render_template("add-earning.html")


@app.route("/set-budget", methods=["GET", "POST"])
@login_required
def set_budget():
    user_id = session["user_id"]
    if request.method == "POST":
        amount = request.form.get("amount")
        period_type = request.form.get("period_type")
        period = request.form.get("period")
        period_year = request.form.get("period_year")

        if not period_year:
            period_year = datetime.datetime.now().year
        if not amount:
            return apology("Must add amount", 403)
        if not period_type:
            return apology("Must add period type", 403)
        if not period:
            return apology("Must add period", 403)
        amount = int(amount)
        with get_db_connection() as db:
            try:
                db.execute("BEGIN")
                db.execute(
                    """
                    INSERT INTO budget
                    (user_id, amount, period_type, period_year, period)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (user_id, amount, period_type, period_year, period)
                )
                db.execute("COMMIT")
            except Exception as e:
                db.execute("ROLLBACK")
                return apology("An error occured")
        return redirect("/")

    else:
        return render_template("set-budget.html")


@app.route("/know-more")
def know_more():
    return render_template("know-more.html")


@app.route("/about-us")
def about_us():
    return render_template("about-us.html")


@app.route("/analysis", methods=["GET", "POST"])
@login_required
def analysis():
    return render_template("analysis.html")


# @app.route("/testing")
# def testing():
#     user_id = session["user_id"]
#     query = "SELECT * FROM expenses WHERE user_id = ?"
#     with get_db_connection() as db:
#         rows = db.execute(query, (user_id,)).fetchall()
#         rows = [list(row) for row in rows]
#         return jsonify(rows)
#         column_names = [desc[0] for desc in db.execute(query, (user_id,)).description]
#         modified_rows = [dict(zip(column_names, row)) for row in rows]
#     return jsonify(modiefied_rows)
    # sub_category_query = "SELECT * FROM sub_category"
    # rows = db.execute(sub_category_query).fetchall()
    # # rows = rows_db.fetchall()
    # # Get the column names
    # column_names = [desc[0] for desc in db.execute(sub_category_query).description]
    # modified_rows = [dict(zip(column_names, row)) for row in rows]
    # # modified_rows = [dict(row._mapping) for row in rows]
    