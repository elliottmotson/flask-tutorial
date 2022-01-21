import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.db import get_db

bp = Blueprint("auth", __name__, url_prefix="/auth")

@bp.route('/register', methods=('GET', 'POST')) # bp.route https://flask.palletsprojects.com/en/2.0.x/api/#flask.Blueprint.route
def register():
    if request.method == 'POST':
        username = request.form['username'] # What request.form actually does https://flask.palletsprojects.com/en/2.0.x/api/#flask.Request.form
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                db.execute( # execute(sql[, parameters]) - Creates cursor with parameters given
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit() # Commit's to database - Important or wont save changes to db!
            except db.IntegrityError: # https://docs.python.org/3/library/sqlite3.html#sqlite3.IntegrityError
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login")) #redirect after storing user
        flash(error)
    return render_template('auth/register.html')


"""LOGIN METHOD"""
@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone() # Returns 1 row from db - https://docs.python.org/3/library/sqlite3.html#sqlite3.Cursor.fetchone

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password): # checks password vs db row hash (I think this is bcrypt/blowfish but easier?)  https://werkzeug.palletsprojects.com/en/2.0.x/utils/#werkzeug.security.check_password_hash
            error = 'Incorrect password.' # blowfish - https://en.wikipedia.org/wiki/Blowfish_(cipher)

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for("index")) # TUTORIAL SAYS USE url_for - This doesn't work(?) - Using render_template for now... -- if no errors with login then... return to index page https://flask.palletsprojects.com/en/2.0.x/api/#flask.url_for
        flash(error) # Flashes error to user based on incorrect user/pwd
    return render_template('auth/login.html')


"""LOGOUT METHOD"""
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@bp.before_app_request # VERY USEFUL! executes before each request https://flask.palletsprojects.com/en/2.0.x/api/#flask.Blueprint.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()


"""Need to learn this more - Looks scary"""
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs): #What are kwargs, why **??
        if g.user is None:
            return redirect(url_for('auth.login')) # https://flask.palletsprojects.com/en/2.0.x/api/#flask.url_for
        return view(**kwargs)
    return wrapped_view
