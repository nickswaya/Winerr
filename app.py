#----------------------------------------------------------------------------#
# Imports
#----------------------------------------------------------------------------#

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt
import stripe
from apscheduler.schedulers.background import BackgroundScheduler
import logging
from datetime import datetime, timedelta
import pytz
from logging import Formatter, FileHandler
from forms import *
from dotenv import load_dotenv
import os
load_dotenv()

#----------------------------------------------------------------------------#
# App Config.
#----------------------------------------------------------------------------#

app = Flask(__name__)
app.config.from_object('config')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['STRIPE_TEST_PUBLIC_KEY'] = os.getenv("STRIPE_TEST_PUBLIC_KEY")
app.config['STRIPE_TEST_SECRET_KEY'] = os.getenv("STRIPE_TEST_SECRET_KEY")
app.app_context().push()
stripe.api_key = app.config['STRIPE_TEST_SECRET_KEY']

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

scheduler = BackgroundScheduler()
scheduler.start()

# Automatically tear down SQLAlchemy.
'''
@app.teardown_request
def shutdown_session(exception=None):
    db_session.remove()
'''

# Login required decorator.
'''
def login_required(test):
    @wraps(test)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return test(*args, **kwargs)
        else:
            flash('You need to login first.')
            return redirect(url_for('login'))
    return wrap
'''

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    current_score = db.Column(db.Integer, default=0)
    total_spend = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.now())


# Define Transaction model
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, unique=False, nullable=False)
    g_bucks = db.Column(db.Integer(), unique=False, nullable=False)
    price = db.Column(db.Float(), unique=False, nullable=False)


#----------------------------------------------------------------------------#
# Controllers.
#----------------------------------------------------------------------------#


@app.route('/')
def home():
    top_users = db.session.query(User.username, db.func.sum(Transaction.price).label('total_price'))\
    .order_by(db.func.sum(Transaction.price).desc())\
     .limit(100)\
     .all()
    
    top_users = db.session.query(
        User.username, db.func.sum(Transaction.price).label('total_price')
    ).join(Transaction, User.id == Transaction.user_id)\
     .group_by(User.username)\
     .order_by(db.func.sum(Transaction.price).desc())\
     .limit(100)\
     .all()
    
    winners = User.query.order_by(User.current_score.desc()).limit(100).all()
    return render_template('pages/placeholder.home.html', top_users=top_users)


@app.route('/about')
def about():
    # top_users = db.session.query(Transaction.price).all()
    # top_users = db.session.query(
    #     User.username, db.func.sum(Transaction.price).label('total_price')
    # ).join(Transaction, User.username == Transaction.username)\
    #  .group_by(User.username).all()
     
    # print(top_users)
    return render_template('pages/placeholder.about.html')


@app.route('/halloffame')
def halloffame():
    users = User.query.limit(10).all()
    return render_template('pages/placeholder.halloffame.html', users=users)


@app.route('/legalfaq')
def legalfaq():
    return render_template('pages/placeholder.legalfaq.html')


@app.route('/yourrights')
def yourrights():
    return render_template('pages/placeholder.yourrights.html')


@app.route('/checkout', methods=['GET'])
def checkout():
    return render_template('forms/checkout.html', key=app.config['STRIPE_TEST_PUBLIC_KEY'])

@app.route('/charge', methods=['POST'])
def charge():
    try:
        amount = int(request.form['amount'])
        token = request.form['stripeToken']

        charge = stripe.Charge.create(
            amount=amount,
            currency='usd',
            description='Example charge',
            source=token
        )
        user = User.query.get(session['user_id'])
        dollars = amount / 100
        if user:
            print(user)
            user.total_spend += dollars
            user.current_score += dollars
            user.last_updated = datetime.now()
        new_transaction = Transaction(user_id=user.id, g_bucks=dollars, price=dollars)
        db.session.add(new_transaction)
        db.session.commit()
        user_transactions = Transaction.query.filter_by(user_id=user.id).all()
        total_price = sum([transaction.price for transaction in user_transactions])
        flash(f"Transaction of ${dollars} recorded! You've spent ${total_price}! Seek Therapy!", 'success')
        return jsonify({'success': True})

    except stripe.error.CardError as e:
        return jsonify({'success': False, 'error': str(e)})
    

@app.route('/buy', methods=['GET', 'POST'])
def buy():
    form = PayForm(request.form)
    user = User.query.get(session['user_id'])
    # user = session.get(User, session['username'])
    if form.is_submitted():
        amount = request.form.get('amount')
        new_transaction = Transaction(user_id=user.id, g_bucks=amount, price=amount)
        db.session.add(new_transaction)
        db.session.commit()
        user_transactions = Transaction.query.filter_by(user_id=user.id).all()
        total_price = sum([transaction.price for transaction in user_transactions])
        flash(f"Transaction of ${amount} recorded! You've spent ${total_price}! Seek Therapy!", 'success')
    return render_template('forms/buy.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if form.is_submitted():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            session['username'] = form.username.data
            session['user_logged_in']=True
            flash('You have been logged in!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('forms/login.html', form=form)


@app.route('/logout')
def logout():
    session['user_logged_in']=False
    session.pop('user_id', None)
    flash('You have been logged out!', 'success')
    return redirect(url_for('home'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if form.is_submitted():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, email=form.email.data, password=hashed_password, total_spend=0, last_updated=None, current_score=0)
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created!', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Email or Username already exists. Please use a different email.', 'error')
            return redirect(url_for('register'))
    return render_template('forms/register.html', form=form)


@app.route('/forgot')
def forgot():
    form = ForgotForm(request.form)
    return render_template('forms/forgot.html', form=form)




# Error handlers.

@app.errorhandler(500)
def internal_error(error):
    #db_session.rollback()
    return render_template('errors/500.html'), 500


@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

if not app.debug:
    file_handler = FileHandler('error.log')
    file_handler.setFormatter(
        Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    )
    app.logger.setLevel(logging.INFO)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.info('errors')


#----------------------------------------------------------------------------#
# Query.
#----------------------------------------------------------------------------#

@app.route('/users')
def users():
    users = User.query.limit(10).all()
    return render_template('users.html', users=users)



#----------------------------------------------------------------------------#
# Degrade.
#----------------------------------------------------------------------------#

# def degrade_scores():
#     with app.context():
#         now = datetime.now()
#         users = User.query.all()
#         for user in users:
#             time_diff = now - user.last_updated
#             hours = time_diff.total_seconds() / 3600
#             degrade_amount = int(hours)  # $1 per hour, convert to cents
#             if degrade_amount > 0:
#                 user.current_score = max(user.current_score - degrade_amount, 0)
#                 user.last_updated = now
#                 db.session.commit()

# scheduler.add_job(degrade_scores, 'interval', hours=1)  # Run every hour


#----------------------------------------------------------------------------#
# Launch.
#----------------------------------------------------------------------------#

# Default port:
if __name__ == '__main__':
    app.run()

# Or specify port manually:
'''
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
'''
