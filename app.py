from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_restful import Api, Resource
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt
import pytz
import os
import logging
import redis
from flask_mail import Mail, Message
import csv
from io import StringIO
import requests
from wtforms import StringField, PasswordField, BooleanField, SubmitField, FloatField, IntegerField, SelectField, DateTimeField
from wtforms.validators import DataRequired, Email, Length, Optional, NumberRange
from flask_caching import Cache
from celery import Celery
from celery.schedules import crontab
import uuid
from dotenv import load_dotenv
from flask_migrate import Migrate

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise ValueError("No FLASK_SECRET_KEY set. Set it in environment variables for security.")
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')
os.makedirs(instance_path, exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_path, "parking.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'
app.config['CACHE_TYPE'] = 'redis'
app.config['CACHE_REDIS_URL'] = 'redis://localhost:6379/0'
app.config['GOOGLE_CHAT_WEBHOOK_URL'] = os.getenv('GOOGLE_CHAT_WEBHOOK_URL')

# Validate environment variables
if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
    logging.warning("MAIL_USERNAME or MAIL_PASSWORD not set. Email features may not work.")
if not app.config['GOOGLE_CHAT_WEBHOOK_URL']:
    logging.warning("GOOGLE_CHAT_WEBHOOK_URL not set. Google Chat notifications will not work.")

# Initialize extensions
csrf = CSRFProtect(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Moved after app and db definitions
login_manager = LoginManager(app)
login_manager.login_view = 'login'
api = Api(app)
mail = Mail(app)
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    redis_client.ping()
except redis.ConnectionError as e:
    logging.error(f"Failed to connect to Redis: {e}")
    raise ValueError("Cannot connect to Redis. Ensure Redis server is running.")
cache = Cache(app)
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_blocked = db.Column(db.Boolean, default=False)
    reservations = db.relationship('Reservation', backref='user', lazy=True)

class ParkingLot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prime_location_name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    pin_code = db.Column(db.String(10), nullable=False)
    price = db.Column(db.Float, nullable=False)
    maximum_number_of_spots = db.Column(db.Integer, nullable=False)
    spots = db.relationship('ParkingSpot', backref='lot', lazy=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(pytz.timezone('Asia/Kolkata')))

class ParkingSpot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lot_id = db.Column(db.Integer, db.ForeignKey('parking_lot.id'), nullable=False)
    status = db.Column(db.String(1), default='A')  # A: Available, O: Occupied
    reservations = db.relationship('Reservation', backref='spot', lazy=True)

class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    spot_id = db.Column(db.Integer, db.ForeignKey('parking_spot.id'), nullable=False)
    parking_timestamp = db.Column(db.DateTime)
    leaving_timestamp = db.Column(db.DateTime)
    parking_cost = db.Column(db.Float)
    vehicle_no = db.Column(db.String(20))
    hours = db.Column(db.Float, default=1.0)

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    is_admin = BooleanField('Admin Status', default=False)
    submit = SubmitField('Register')

class ParkingLotForm(FlaskForm):
    prime_location_name = StringField('Location Name', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    pin_code = StringField('Pin Code', validators=[DataRequired(), Length(min=6, max=6)])
    price = FloatField('Price per Hour', validators=[DataRequired(), NumberRange(min=0)])
    maximum_number_of_spots = IntegerField('Number of Spots', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Create Lot')

class ParkingSpotForm(FlaskForm):
    lot_id = IntegerField('Lot ID', validators=[DataRequired()])
    status = StringField('Status', validators=[DataRequired(), Length(max=1)])
    submit = SubmitField('Add Spot')

class ReservationForm(FlaskForm):
    spot_id = IntegerField('Spot ID', validators=[DataRequired()])
    user_id = IntegerField('User ID', validators=[DataRequired()], render_kw={'type': 'hidden'})
    vehicle_no = StringField('Vehicle Number', validators=[DataRequired()])
    hours = FloatField('Hours', validators=[DataRequired(), NumberRange(min=0.1, max=24)])
    parking_timestamp = DateTimeField('Parking Time', format='%Y-%m-%d %H:%M:%S', validators=[Optional()])
    leaving_timestamp = DateTimeField('Leaving Time', format='%Y-%m-%d %H:%M:%S', validators=[Optional()])
    parking_cost = FloatField('Parking Cost', validators=[Optional()])
    submit = SubmitField('Book Spot')

class SelectParkingLotForm(FlaskForm):
    lot_id = SelectField('Parking Lot', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Select Lot')

class SearchForm(FlaskForm):
    search_type = SelectField('Search Type', choices=[
        ('user_email', 'User Email'),
        ('vehicle_no', 'Vehicle Number'),
        ('lot_location', 'Lot Location or ID')
    ], validators=[DataRequired()])
    query_text = StringField('Search Query', validators=[DataRequired()])
    submit = SubmitField('Search')

class EditUserForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    is_admin = BooleanField('Admin Status')
    is_blocked = BooleanField('Blocked Status')
    submit = SubmitField('Update')

class ProfileForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    current_password = PasswordField('Current Password', validators=[Optional()])
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=6)])
    confirm_new_password = PasswordField('Confirm New Password', validators=[Optional()])
    submit = SubmitField('Update Profile')

# Helper function for IST time
def get_ist_time():
    try:
        return datetime.now(pytz.timezone('Asia/Kolkata'))
    except Exception as e:
        logging.error(f"Failed to get IST time: {e}. Returning naive UTC datetime.")
        return datetime.utcnow()

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception as e:
        logging.error(f"Error loading user {user_id}: {e}")
        return None

# CSRF Protection
@app.before_request
def protect_against_csrf():
    try:
        csrf.protect()
    except Exception as e:
        logging.error(f"CSRF protection error: {e}")
        flash('CSRF validation failed. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

# API Resources with Caching
class ParkingLotAPI(Resource):
    @cache.cached(timeout=300, key_prefix='parking_lots')
    def get(self, lot_id=None):
        try:
            if lot_id:
                lot = ParkingLot.query.get_or_404(lot_id)
                return {'id': lot.id, 'name': lot.prime_location_name, 'price': lot.price, 'spots': len(lot.spots)}
            lots = ParkingLot.query.all()
            return [{'id': lot.id, 'name': lot.prime_location_name, 'price': lot.price, 'spots': len(lot.spots)} for lot in lots]
        except Exception as e:
            logging.error(f"Error in ParkingLotAPI: {e}")
            return {'error': 'Internal server error'}, 500

class ParkingSpotAPI(Resource):
    @cache.cached(timeout=300, key_prefix=lambda: f'parking_spots_{request.view_args["lot_id"]}')
    def get(self, lot_id):
        try:
            spots = ParkingSpot.query.filter_by(lot_id=lot_id).all()
            return [{'id': spot.id, 'status': 'Available' if spot.status == 'A' else 'Occupied'} for spot in spots]
        except Exception as e:
            logging.error(f"Error in ParkingSpotAPI: {e}")
            return {'error': 'Internal server error'}, 500

api.add_resource(ParkingLotAPI, '/api/lots', '/api/lots/<int:lot_id>')
api.add_resource(ParkingSpotAPI, '/api/lots/<int:lot_id>/spots')

# Celery Tasks
@celery.task
def send_daily_reminders():
    with app.app_context():
        threshold_date = get_ist_time() - timedelta(days=7)
        new_lots = ParkingLot.query.filter(ParkingLot.created_at >= threshold_date).all()
        users = User.query.filter_by(is_blocked=False, is_admin=False).all()
        webhook_url = app.config['GOOGLE_CHAT_WEBHOOK_URL']
        
        for user in users:
            recent_reservation = Reservation.query.filter_by(user_id=user.id).filter(
                Reservation.parking_timestamp >= threshold_date
            ).first()
            if not recent_reservation or new_lots:
                message = "Hi! You haven't booked a parking spot recently."
                if new_lots:
                    lot_names = ", ".join(lot.prime_location_name for lot in new_lots)
                    message += f" New parking lots available: {lot_names}."
                message += " Book a spot now at http://127.0.0.1:5000/user/select_lot"
                try:
                    if webhook_url:
                        requests.post(webhook_url, json={'text': f"Reminder for {user.email}: {message}"})
                        logging.info(f"Sent GChat reminder to {user.email}")
                    else:
                        msg = Message('Daily Parking Reminder', recipients=[user.email], body=message)
                        mail.send(msg)
                        logging.info(f"Sent email reminder to {user.email}")
                except Exception as e:
                    logging.error(f"Failed to send reminder to {user.email}: {e}")

@celery.task
def send_monthly_reports():
    with app.app_context():
        users = User.query.filter_by(is_blocked=False, is_admin=False).all()
        last_month_start = get_ist_time().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        if last_month_start.month == 1:
            last_month_start = last_month_start.replace(year=last_month_start.year - 1, month=12)
        else:
            last_month_start = last_month_start.replace(month=last_month_start.month - 1)
        last_month_end = last_month_start.replace(day=28) + timedelta(days=4)
        last_month_end = last_month_end - timedelta(days=last_month_end.day)

        for user in users:
            reservations = Reservation.query.filter_by(user_id=user.id).filter(
                Reservation.parking_timestamp >= last_month_start,
                Reservation.parking_timestamp <= last_month_end
            ).all()
            if not reservations:
                continue

            total_spots_booked = len(reservations)
            total_cost = sum(r.parking_cost for r in reservations if r.parking_cost)
            lot_counts = db.session.query(
                ParkingLot.prime_location_name,
                db.func.count(Reservation.id).label('count')
            ).join(ParkingSpot).join(Reservation).filter(
                Reservation.user_id == user.id,
                Reservation.parking_timestamp >= last_month_start,
                Reservation.parking_timestamp <= last_month_end
            ).group_by(ParkingLot.id).order_by(db.func.count(Reservation.id).desc()).first()

            most_used_lot = lot_counts.prime_location_name if lot_counts else 'N/A'
            
            html_content = f"""
            <html>
                <body>
                    <h2>Monthly Parking Report for {user.email}</h2>
                    <p>Period: {last_month_start.strftime('%B %Y')}</p>
                    <ul>
                        <li>Total Spots Booked: {total_spots_booked}</li>
                        <li>Most Used Parking Lot: {most_used_lot}</li>
                        <li>Total Amount Spent: ₹{total_cost:.2f}</li>
                    </ul>
                    <h3>Reservation Details</h3>
                    <table border='1'>
                        <tr><th>ID</th><th>Lot</th><th>Spot</th><th>Vehicle</th><th>Parking Time</th><th>Hours</th><th>Cost</th></tr>
            """
            for r in reservations:
                html_content += f"""
                    <tr>
                        <td>{r.id}</td>
                        <td>{r.spot.lot.prime_location_name if r.spot and r.spot.lot else 'N/A'}</td>
                        <td>{r.spot_id}</td>
                        <td>{r.vehicle_no}</td>
                        <td>{r.parking_timestamp.strftime('%Y-%m-%d %H:%M') if r.parking_timestamp else 'N/A'}</td>
                        <td>{r.hours:.1f}</td>
                        <td>₹{r.parking_cost:.2f}</td>
                    </tr>
                """
            html_content += "</table></body></html>"

            try:
                msg = Message(f'Your Monthly Parking Report - {last_month_start.strftime("%B %Y")}',
                             recipients=[user.email], html=html_content)
                mail.send(msg)
                logging.info(f"Sent monthly report to {user.email}")
            except Exception as e:
                logging.error(f"Failed to send monthly report to {user.email}: {e}")

@celery.task
def generate_user_csv(user_id, email):
    with app.app_context():
        try:
            reservations = Reservation.query.filter_by(user_id=user_id).all()
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow(['Reservation ID', 'Lot Name', 'Spot ID', 'Vehicle No', 'Parking Time', 'Leaving Time', 'Hours', 'Cost', 'Remarks'])
            for r in reservations:
                remarks = 'Active' if not r.leaving_timestamp else 'Released'
                writer.writerow([
                    r.id,
                    r.spot.lot.prime_location_name if r.spot and r.spot.lot else 'N/A',
                    r.spot_id,
                    r.vehicle_no,
                    r.parking_timestamp.strftime('%Y-%m-%d %H:%M') if r.parking_timestamp else 'N/A',
                    r.leaving_timestamp.strftime('%Y-%m-%d %H:%M') if r.leaving_timestamp else 'N/A',
                    f'{r.hours:.1f}' if r.hours else 'N/A',
                    f'₹{r.parking_cost:.2f}' if r.parking_cost else 'N/A',
                    remarks
                ])
            csv_key = f'csv_{user_id}_{uuid.uuid4().hex}'
            redis_client.setex(csv_key, 3600, output.getvalue())
            download_url = url_for('download_csv', csv_key=csv_key, _external=True)
            msg = Message('Your Parking History CSV', recipients=[email])
            msg.body = f'Access your parking history CSV here: {download_url}\nThis link expires in 1 hour.'
            mail.send(msg)
            webhook_url = app.config['GOOGLE_CHAT_WEBHOOK_URL']
            if webhook_url:
                requests.post(webhook_url, json={'text': f"CSV export completed for {email}"})
            logging.info(f"Generated CSV for user {email}, key: {csv_key}")
        except Exception as e:
            logging.error(f"Failed to generate CSV for user {email}: {e}")

# Celery Beat Schedule
celery.conf.beat_schedule = {
    'send-daily-reminders': {
        'task': 'app.send_daily_reminders',
        'schedule': crontab(hour=18, minute=0),  # 6:00 PM IST
    },
    'send-monthly-reports': {
        'task': 'app.send_monthly_reports',
        'schedule': crontab(day_of_month=1, hour=9, minute=0),  # 9:00 AM IST on 1st
    },
}

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        logging.info(f"Authenticated user {current_user.email} redirected from login")
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            if user.is_blocked:
                flash('Your account is blocked. Contact an admin.', 'danger')
                logging.info(f"Blocked login attempt for {form.email.data}")
                return render_template('login.html', form=form)
            login_user(user)
            flash('Logged in successfully', 'success')
            logging.info(f"User {form.email.data} logged in")
            return redirect(url_for('dashboard'))
        flash('Invalid email or password', 'danger')
        logging.warning(f"Failed login attempt for {form.email.data}")
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')  # Use bcrypt instance
        user = User(email=form.email.data, password=hashed_password, is_admin=form.is_admin.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)
    
@app.route('/logout')
@login_required
def logout():
    email = current_user.email
    logout_user()
    flash('Logged out successfully', 'success')
    logging.info(f"User {email} logged out")
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
@cache.cached(timeout=60)
def dashboard():
    if current_user.is_blocked:
        flash('Your account is blocked. Contact an admin.', 'danger')
        logout_user()
        logging.info(f"Blocked user {current_user.email} logged out due to block status")
        return redirect(url_for('login'))

    lots = ParkingLot.query.all()

    if current_user.is_admin:
        logging.info(f"Admin {current_user.email} accessed dashboard")
        return render_template('admin/dashboard.html', lots=lots)
    else:
        user_reservations = Reservation.query.filter_by(user_id=current_user.id).all()
        active_reservations = [r for r in user_reservations if r.leaving_timestamp is None]
        released_reservations = [r for r in user_reservations if r.leaving_timestamp is not None]

        user_reservation_chart = {
            'type': 'pie',
            'data': {
                'labels': ['Active', 'Released'],
                'datasets': [{
                    'data': [len(active_reservations), len(released_reservations)],
                    'backgroundColor': ['#007bff', '#6c757d'],
                    'borderColor': ['#ffffff', '#ffffff'],
                    'borderWidth': 1
                }]
            },
            'options': {
                'responsive': True,
                'plugins': {
                    'legend': {'position': 'top'},
                    'title': {'display': True, 'text': 'Reservation Status'}
                }
            }
        }
        recent_history = sorted(user_reservations, key=lambda x: x.parking_timestamp or datetime.min, reverse=True)[:5]
        
        logging.info(f"User {current_user.email} accessed dashboard with {len(user_reservations)} reservations")
        return render_template('user/dashboard.html',
                               lots=lots,
                               reservations=user_reservations,
                               recent_history=recent_history,
                               user_reservation_chart=user_reservation_chart)

@app.route('/user/select_lot', methods=['GET', 'POST'])
@login_required
def select_lot():
    if current_user.is_blocked:
        flash('Your account is blocked.', 'danger')
        return redirect(url_for('dashboard'))
    if current_user.is_admin:
        flash('Admins cannot book spots', 'danger')
        return redirect(url_for('dashboard'))

    available_lots_query = db.session.query(ParkingLot).join(ParkingSpot).filter(ParkingSpot.status == 'A').distinct()
    available_lots = available_lots_query.all()

    form = SelectParkingLotForm()
    form.lot_id.choices = [(lot.id, f"{lot.prime_location_name} ({lot.address}) - ₹{lot.price}/hr") for lot in available_lots]

    if not available_lots:
        flash('No parking lots with available spots at the moment.', 'warning')
        return redirect(url_for('dashboard'))

    if form.validate_on_submit():
        selected_lot_id = form.lot_id.data
        return redirect(url_for('book_spot', lot_id=selected_lot_id))

    return render_template('user/select_lot.html', form=form)

@app.route('/user/book_spot/<int:lot_id>', methods=['GET', 'POST'])
@login_required
def book_spot(lot_id):
    if current_user.is_blocked:
        flash('Your account is blocked.', 'danger')
        return redirect(url_for('dashboard'))
    if current_user.is_admin:
        flash('Admins cannot book spots', 'danger')
        return redirect(url_for('dashboard'))

    lot = ParkingLot.query.get_or_404(lot_id)
    available_spots = ParkingSpot.query.filter_by(lot_id=lot_id, status='A').all()
    logging.debug(f"Available spots in lot {lot_id} at {get_ist_time()}: {len(available_spots)}")

    if request.method == 'GET':
        spot = ParkingSpot.query.filter_by(lot_id=lot_id, status='A').first()
        if not spot:
            flash('No available spots in this lot. Please select another lot.', 'danger')
            logging.warning(f"No available spots for user {current_user.email} in lot {lot_id} at {get_ist_time()}.")
            return redirect(url_for('select_lot'))
        session['selected_spot'] = {'id': spot.id, 'timestamp': get_ist_time().isoformat()}
        form = ReservationForm()
        form.spot_id.data = spot.id
        form.user_id.data = current_user.id
        return render_template('user/book_spot.html', lot=lot, spot=spot, form=form)

    if request.method == 'POST':
        form = ReservationForm()
        if not form.validate_on_submit():
            flash('Invalid spot selection or form submission.', 'danger')
            logging.error(f"Invalid POST for user {current_user.email} in lot {lot_id} at {get_ist_time()}: {form.errors}")
            session.pop('selected_spot', None)
            return redirect(url_for('dashboard'))

        if 'selected_spot' not in session or form.spot_id.data != session['selected_spot']['id'] or form.user_id.data != current_user.id:
            flash('Session data mismatch. Please try again.', 'danger')
            logging.error(f"Session mismatch for user {current_user.email} in lot {lot_id} at {get_ist_time()}: Form spot_id={form.spot_id.data}, Session spot_id={session.get('selected_spot', {}).get('id')}, Form user_id={form.user_id.data}, Current user_id={current_user.id}")
            session.pop('selected_spot', None)
            return redirect(url_for('select_lot'))

        selected_spot_data = session['selected_spot']
        re_checked_spot = ParkingSpot.query.get(selected_spot_data['id'])
        if not re_checked_spot or re_checked_spot.status != 'A':
            next_spot = ParkingSpot.query.filter_by(lot_id=lot_id, status='A').first()
            if not next_spot:
                flash('The selected spot and all others are no longer available. Please try again.', 'danger')
                logging.warning(f"No available spots for user {current_user.email} in lot {lot_id} at {get_ist_time()}.")
                session.pop('selected_spot', None)
                return redirect(url_for('select_lot'))
            re_checked_spot = next_spot
            form.spot_id.data = re_checked_spot.id
            logging.info(f"Switched to next available spot {re_checked_spot.id} for user {current_user.email} in lot {lot_id}.")

        session_timestamp = datetime.fromisoformat(selected_spot_data['timestamp']).astimezone(pytz.timezone('Asia/Kolkata'))
        current_time = get_ist_time()
        if (current_time - session_timestamp).total_seconds() > 300:
            flash('Session for spot selection has expired. Please try again.', 'danger')
            logging.warning(f"Stale session spot {selected_spot_data['id']} for user {current_user.email} in lot {lot_id}.")
            session.pop('selected_spot', None)
            return redirect(url_for('select_lot'))

        try:
            hours = float(form.hours.data or 1.0)
            if hours <= 0:
                raise ValueError("Parking duration must be greater than 0.")
        except ValueError as e:
            flash(f'Invalid parking duration: {str(e)}. Defaulting to 1 hour.', 'danger')
            logging.warning(f"Invalid hours '{form.hours.data}' from user {current_user.email}, defaulting to 1.")
            hours = 1.0

        vehicle_no = form.vehicle_no.data.strip()[:15]
        if not vehicle_no:
            vehicle_no = 'TEMP1234'

        re_checked_spot.status = 'O'
        parking_cost = lot.price * hours

        reservation = Reservation(
            spot_id=re_checked_spot.id,
            user_id=current_user.id,
            vehicle_no=vehicle_no,
            parking_cost=parking_cost,
            hours=hours,
            parking_timestamp=get_ist_time()
        )
        try:
            db.session.add(reservation)
            db.session.commit()
            cache.delete(f'parking_spots_{lot_id}')
            flash(f'Spot {re_checked_spot.id} booked successfully for {hours} hours! Total Cost: ₹{parking_cost:.2f}', 'success')
            logging.info(f"User {current_user.email} booked spot {re_checked_spot.id} in lot {lot_id} for {hours} hours, reservation ID {reservation.id} at {get_ist_time()}")
            session.pop('selected_spot', None)
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            if re_checked_spot:
                re_checked_spot.status = 'A'
                db.session.commit()
            flash(f'Booking failed due to an error: {str(e)}. Redirecting to dashboard.', 'danger')
            logging.error(f"Booking error for user {current_user.email}, spot {re_checked_spot.id if re_checked_spot else 'N/A'}: {str(e)} at {get_ist_time()}")
            session.pop('selected_spot', None)
            return redirect(url_for('dashboard'))

@app.route('/user/release_reservation_page/<int:reservation_id>', methods=['GET'])
@login_required
def release_reservation_page(reservation_id):
    if current_user.is_blocked:
        flash('Your account is blocked.', 'danger')
        return redirect(url_for('dashboard'))
    if current_user.is_admin:
        flash('Admins cannot release spots', 'danger')
        return redirect(url_for('dashboard'))

    reservation = Reservation.query.get_or_404(reservation_id)

    if reservation.user_id != current_user.id:
        flash('Unauthorized action: You do not own this reservation.', 'danger')
        logging.warning(f"User {current_user.email} attempted unauthorized access to release page for reservation {reservation_id}")
        return redirect(url_for('dashboard'))

    if reservation.leaving_timestamp:
        flash('This spot has already been released.', 'warning')
        return redirect(url_for('dashboard'))

    spot = reservation.spot
    lot = spot.lot if spot else None

    if not spot or not lot:
        flash('Associated parking spot or lot not found.', 'danger')
        logging.error(f"Spot or Lot not found for reservation {reservation_id} during release page access.")
        return redirect(url_for('dashboard'))

    current_ist_time = get_ist_time()
    return render_template('user/release_spot.html', reservation=reservation, spot=spot, lot=lot, current_ist_time=current_ist_time)

@app.route('/user/release_spot/<int:reservation_id>', methods=['POST'])
@login_required
def release_spot(reservation_id):
    logging.debug(f"Received POST data: {request.form}")
    if current_user.is_blocked:
        flash('Your account is blocked.', 'danger')
        return redirect(url_for('dashboard'))
    if current_user.is_admin:
        flash('Admins cannot release spots', 'danger')
        return redirect(url_for('dashboard'))

    reservation = Reservation.query.get_or_404(reservation_id)

    if reservation.user_id != current_user.id:
        flash('Unauthorized action: You do not own this reservation.', 'danger')
        logging.warning(f"User {current_user.email} attempted unauthorized release of reservation {reservation_id}")
        return redirect(url_for('dashboard'))

    if reservation.leaving_timestamp:
        flash('This spot has already been released.', 'warning')
        logging.warning(f"User {current_user.email} attempted to release already released reservation {reservation_id}")
        return redirect(url_for('dashboard'))

    spot = ParkingSpot.query.get(reservation.spot_id)
    if spot:
        spot.status = 'A'
        reservation.leaving_timestamp = get_ist_time()
        
        try:
            db.session.commit()
            cache.delete(f'parking_spots_{spot.lot_id}')
            flash('Spot released successfully. Thank you for using our service!', 'success')
            logging.info(f"User {current_user.email} released spot {reservation.spot_id} for reservation {reservation.id}")
        except Exception as e:
            db.session.rollback()
            flash('Failed to release spot. Please try again.', 'danger')
            logging.error(f"Error releasing spot {reservation.spot_id} for reservation {reservation.id}: {e}")
    else:
        flash('Associated parking spot not found.', 'danger')
        logging.error(f"Parking spot {reservation.spot_id} not found for reservation {reservation.id} during release.")

    return redirect(url_for('dashboard'))

@app.route('/user/cancel_reservation/<int:reservation_id>', methods=['POST'])
@login_required
def cancel_reservation(reservation_id):
    if current_user.is_blocked:
        flash('Your account is blocked.', 'danger')
        return redirect(url_for('dashboard'))
    if current_user.is_admin:
        flash('Admins cannot cancel reservations', 'danger')
        return redirect(url_for('dashboard'))

    reservation = Reservation.query.get_or_404(reservation_id)

    if reservation.user_id != current_user.id:
        flash('Unauthorized action: You do not own this reservation.', 'danger')
        logging.warning(f"User {current_user.email} attempted unauthorized cancellation of reservation {reservation_id}")
        return redirect(url_for('dashboard'))

    if reservation.leaving_timestamp:
        flash('Cannot cancel a reservation that has already been released.', 'danger')
        logging.warning(f"User {current_user.email} attempted to cancel a released reservation {reservation_id}")
        return redirect(url_for('dashboard'))

    spot = ParkingSpot.query.get(reservation.spot_id)
    lot_id = spot.lot_id if spot else None
    if spot:
        spot.status = 'A'
    else:
        logging.warning(f"Spot {reservation.spot_id} not found for reservation {reservation_id} during cancellation.")

    try:
        db.session.delete(reservation)
        db.session.commit()
        if lot_id:
            cache.delete(f'parking_spots_{lot_id}')
        flash('Reservation cancelled successfully.', 'success')
        logging.info(f"User {current_user.email} cancelled reservation {reservation_id}. Spot {spot.id if spot else 'N/A'} set to available.")
    except Exception as e:
        db.session.rollback()
        flash('Failed to cancel reservation. Please try again.', 'danger')
        logging.error(f"Error cancelling reservation {reservation_id}: {e}")

    return redirect(url_for('dashboard'))

@app.route('/user/summary')
@login_required
def user_summary():
    if current_user.is_blocked:
        flash('Your account is blocked.', 'danger')
        return redirect(url_for('dashboard'))

    user_reservations = Reservation.query.filter_by(user_id=current_user.id).all()
    active_reservations_count = sum(1 for r in user_reservations if r.leaving_timestamp is None)
    released_reservations_count = sum(1 for r in user_reservations if r.leaving_timestamp is not None)
    total_cost_spent = sum(r.parking_cost for r in user_reservations if r.parking_cost is not None)

    reservation_status_chart = {
        'type': 'pie',
        'data': {
            'labels': ['Active Reservations', 'Released Reservations'],
            'datasets': [{
                'data': [active_reservations_count, released_reservations_count],
                'backgroundColor': ['#FF6384', '#36A2EB'],
                'borderColor': ['#ffffff', '#ffffff'],
                'borderWidth': 1
            }]
        },
        'options': {
            'responsive': True,
            'plugins': {
                'legend': {'position': 'top'},
                'title': {'display': True, 'text': 'Reservation Status'}
            }
        }
    }

    total_cost_chart = {
        'type': 'bar',
        'data': {
            'labels': ['Total Cost Spent'],
            'datasets': [{
                'label': 'Amount (₹)',
                'data': [total_cost_spent],
                'backgroundColor': '#4BC0C0',
                'borderColor': '#4BC0C0',
                'borderWidth': 1
            }]
        },
        'options': {
            'responsive': True,
            'scales': {
                'y': {'beginAtZero': True}
            },
            'plugins': {
                'legend': {'display': False},
                'title': {'display': True, 'text': 'Total Cost Spent'}
            }
        }
    }

    logging.info(f"User {current_user.email} accessed summary page.")
    return render_template('user/summary.html',
                           reservation_status_chart=reservation_status_chart,
                           total_cost_spent=total_cost_spent,
                           total_cost_chart=total_cost_chart)

@app.route('/user/export_csv', methods=['POST'])
@login_required
def user_export_csv():
    if current_user.is_blocked:
        flash('Your account is blocked.', 'danger')
        return redirect(url_for('dashboard'))
    if current_user.is_admin:
        flash('Admins cannot export user CSV.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        generate_user_csv.delay(current_user.id, current_user.email)
        flash('CSV export job started. You will receive an email with the download link shortly.', 'success')
        logging.info(f"Triggered async CSV export for user {current_user.email}")
    except Exception as e:
        logging.error(f"Failed to start CSV export job for {current_user.email}: {e}")
        flash('Failed to start CSV export job. Please try again later.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/download_csv/<csv_key>')
def download_csv(csv_key):
    try:
        csv_data = redis_client.get(csv_key)
        if not csv_data:
            flash('Download link expired or invalid.', 'danger')
            return redirect(url_for('dashboard'))
        return app.response_class(
            csv_data,
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment;filename=parking_history_{csv_key}.csv'}
        )
    except redis.ConnectionError:
        logging.error("Redis connection failed. CSV download unavailable.")
        flash('CSV download is currently unavailable due to server issues.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/user/profile', methods=['GET', 'POST'])
@login_required
def user_profile():
    if current_user.is_blocked:
        flash('Your account is blocked.', 'danger')
        return redirect(url_for('dashboard'))
    form = ProfileForm(email=current_user.email)
    if form.validate_on_submit():
        if form.email.data != current_user.email:
            existing_user = User.query.filter_by(email=form.email.data).first()
            if existing_user:
                flash('Email already in use.', 'danger')
                logging.warning(f"User {current_user.email} attempted to change to existing email {form.email.data}")
                return render_template('user/profile.html', form=form)
            current_user.email = form.email.data
            logging.info(f"User {current_user.email} updated email to {form.email.data}")
        if form.current_password.data and form.new_password.data and form.confirm_new_password.data:
            if not check_password_hash(current_user.password, form.current_password.data):
                flash('Current password is incorrect.', 'danger')
                logging.warning(f"User {current_user.email} provided incorrect current password")
                return render_template('user/profile.html', form=form)
            if form.new_password.data != form.confirm_new_password.data:
                flash('New passwords do not match.', 'danger')
                logging.warning(f"User {current_user.email} provided mismatched new passwords")
                return render_template('user/profile.html', form=form)
            current_user.password = generate_password_hash(form.new_password.data)
            logging.info(f"User {current_user.email} updated password")
        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            logging.info(f"User {current_user.email} updated profile")
        except Exception as e:
            db.session.rollback()
            flash('Failed to update profile. Please try again.', 'danger')
            logging.error(f"Error updating profile for {current_user.email}: {e}")
        return redirect(url_for('dashboard'))
    return render_template('user/profile.html', form=form)

@app.route('/admin/create_lot', methods=['GET', 'POST'])
@login_required
def create_lot():
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    form = ParkingLotForm()
    if form.validate_on_submit():
        existing_lot = ParkingLot.query.filter(
            db.or_(
                db.and_(
                    db.func.lower(ParkingLot.prime_location_name) == db.func.lower(form.prime_location_name.data),
                    db.func.lower(ParkingLot.address) == db.func.lower(form.address.data)
                ),
                db.func.lower(ParkingLot.pin_code) == db.func.lower(form.pin_code.data)
            )
        ).first()

        if existing_lot:
            if existing_lot.pin_code.lower() == form.pin_code.data.lower():
                flash('A parking lot with this pin code already exists.', 'danger')
            else:
                flash('A parking lot with this name and address already exists.', 'danger')
            logging.warning(f"Admin {current_user.email} attempted to create duplicate lot (name/address or pin_code).")
            return render_template('admin/create_lot.html', form=form)

        lot = ParkingLot(
            prime_location_name=form.prime_location_name.data,
            price=form.price.data,
            address=form.address.data,
            pin_code=form.pin_code.data,
            maximum_number_of_spots=form.maximum_number_of_spots.data,
            created_at=get_ist_time()
        )
        db.session.add(lot)
        try:
            db.session.commit()
            for _ in range(form.maximum_number_of_spots.data):
                spot = ParkingSpot(lot_id=lot.id)
                db.session.add(spot)
            db.session.commit()
            cache.delete('parking_lots')
            flash('Parking lot and its spots created successfully!', 'success')
            logging.info(f"Admin {current_user.email} created lot {lot.id} ({lot.prime_location_name}) with {lot.maximum_number_of_spots} spots.")
            return redirect(url_for('dashboard'))
        except db.exc.IntegrityError as e:
            db.session.rollback()
            flash('Failed to create lot due to a database error. Check unique constraints.', 'danger')
            logging.error(f"IntegrityError in create_lot for {form.prime_location_name.data}: {e}")
        except Exception as e:
            db.session.rollback()
            flash('An unexpected error occurred while creating the lot. Please try again.', 'danger')
            logging.error(f"General error in create_lot for {form.prime_location_name.data}: {e}")

    return render_template('admin/create_lot.html', form=form)

@app.route('/admin/edit_lot/<int:lot_id>', methods=['GET', 'POST'])
@login_required
def edit_lot(lot_id):
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    lot = ParkingLot.query.get_or_404(lot_id)
    form = ParkingLotForm(obj=lot)

    if form.validate_on_submit():
        existing_lot = ParkingLot.query.filter(
            db.and_(
                ParkingLot.id != lot_id,
                db.or_(
                    db.and_(
                        db.func.lower(ParkingLot.prime_location_name) == db.func.lower(form.prime_location_name.data),
                        db.func.lower(ParkingLot.address) == db.func.lower(form.address.data)
                    ),
                    db.func.lower(ParkingLot.pin_code) == db.func.lower(form.pin_code.data)
                )
            )
        ).first()
        if existing_lot:
            if existing_lot.pin_code.lower() == form.pin_code.data.lower():
                flash('Another parking lot with this pin code already exists.', 'danger')
            else:
                flash('Another parking lot with this name and address already exists.', 'danger')
            logging.warning(f"Admin {current_user.email} attempted to update lot {lot_id} to duplicate (name/address or pin_code).")
            return render_template('admin/edit_lot.html', form=form, lot=lot)

        old_max_spots = lot.maximum_number_of_spots
        new_max_spots = form.maximum_number_of_spots.data

        if new_max_spots > old_max_spots:
            for _ in range(new_max_spots - old_max_spots):
                spot = ParkingSpot(lot_id=lot.id)
                db.session.add(spot)
            logging.info(f"Admin {current_user.email} added {new_max_spots - old_max_spots} new spots to lot {lot_id}.")
        elif new_max_spots < old_max_spots:
            current_occupied_spots = ParkingSpot.query.filter_by(lot_id=lot.id, status='O').count()
            if new_max_spots < current_occupied_spots:
                flash(f'Cannot reduce max spots to {new_max_spots} as {current_occupied_spots} spots are currently occupied.', 'danger')
                logging.warning(f"Admin {current_user.email} attempted to reduce max_spots below occupied count for lot {lot_id}.")
                return render_template('admin/edit_lot.html', form=form, lot=lot)
            
            available_spots_to_delete_count = old_max_spots - new_max_spots
            if available_spots_to_delete_count > 0:
                spots_to_delete = ParkingSpot.query.filter_by(lot_id=lot.id, status='A').order_by(ParkingSpot.id.desc()).limit(available_spots_to_delete_count).all()
                for spot_to_delete in spots_to_delete:
                    db.session.delete(spot_to_delete)
                logging.info(f"Admin {current_user.email} deleted {available_spots_to_delete_count} available spots from lot {lot_id}.")

        lot.prime_location_name = form.prime_location_name.data
        lot.price = form.price.data
        lot.address = form.address.data
        lot.pin_code = form.pin_code.data
        lot.maximum_number_of_spots = new_max_spots

        try:
            db.session.commit()
            cache.delete('parking_lots')
            cache.delete(f'parking_spots_{lot_id}')
            flash('Parking lot updated successfully!', 'success')
            logging.info(f"Admin {current_user.email} updated lot {lot_id}.")
            return redirect(url_for('dashboard'))
        except db.exc.IntegrityError as e:
            db.session.rollback()
            flash('Failed to update lot due to a database error. Check unique constraints.', 'danger')
            logging.error(f"IntegrityError in edit_lot for lot {lot_id}: {e}")
        except Exception as e:
            db.session.rollback()
            flash('An unexpected error occurred while updating the lot. Please try again.', 'danger')
            logging.error(f"General error in edit_lot for lot {lot_id}: {e}")

    return render_template('admin/edit_lot.html', form=form, lot=lot)

@app.route('/admin/delete_lot/<int:lot_id>', methods=['POST'])
@login_required
def delete_lot(lot_id):
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    lot = ParkingLot.query.get_or_404(lot_id)

    if any(spot.status == 'O' for spot in lot.spots):
        flash('Cannot delete lot with occupied spots. Please release them first.', 'danger')
        logging.warning(f"Admin {current_user.email} attempted to delete lot {lot_id} with occupied spots.")
        return redirect(url_for('dashboard'))

    try:
        db.session.delete(lot)
        db.session.commit()
        cache.delete('parking_lots')
        cache.delete(f'parking_spots_{lot_id}')
        flash('Parking lot and all associated data deleted successfully!', 'success')
        logging.info(f"Admin {current_user.email} deleted lot {lot.id}.")
    except Exception as e:
        db.session.rollback()
        flash('Failed to delete parking lot. Please try again.', 'danger')
        logging.error(f"Error deleting lot {lot.id}: {e}")

    return redirect(url_for('dashboard'))

@app.route('/admin/view_lot/<int:lot_id>')
@login_required
def view_lot(lot_id):
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    lot = ParkingLot.query.get_or_404(lot_id)
    return render_template('admin/view_lot.html', lot=lot)

@app.route('/admin/spot_details/<int:spot_id>')
@login_required
def admin_spot_details(spot_id):
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    spot = ParkingSpot.query.get_or_404(spot_id)
    return render_template('admin/view_spot_details.html', spot=spot)

@app.route('/admin/create_spot/<int:lot_id>', methods=['GET', 'POST'])
@login_required
def create_spot(lot_id):
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    lot = ParkingLot.query.get_or_404(lot_id)
    form = ParkingSpotForm()
    form.lot_id.choices = [(lot_item.id, lot_item.prime_location_name) for lot_item in ParkingLot.query.all()]
    form.lot_id.data = lot_id

    if form.validate_on_submit():
        current_spots_count = ParkingSpot.query.filter_by(lot_id=lot.id).count()
        if current_spots_count >= lot.maximum_number_of_spots:
            flash(f'Cannot add more spots. This lot (ID: {lot_id}) has reached its maximum of {lot.maximum_number_of_spots} spots.', 'danger')
            logging.warning(f"Admin {current_user.email} attempted to add spot to full lot {lot_id}.")
            return render_template('admin/create_spot.html', form=form, lot=lot)

        spot = ParkingSpot(
            lot_id=form.lot_id.data,
            status=form.status.data
        )
        try:
            db.session.add(spot)
            db.session.commit()
            cache.delete(f'parking_spots_{lot_id}')
            flash(f'Spot {spot.id} created successfully in Lot {lot.prime_location_name}!', 'success')
            logging.info(f"Admin {current_user.email} created spot {spot.id} in lot {lot_id}.")
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to create spot. Please try again.', 'danger')
            logging.error(f"Error creating spot in lot {lot_id}: {e}")

    return render_template('admin/create_spot.html', form=form, lot=lot)

@app.route('/admin/edit_spot/<int:spot_id>', methods=['GET', 'POST'])
@login_required
def edit_spot(spot_id):
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))

    spot = ParkingSpot.query.get_or_404(spot_id)
    form = ParkingSpotForm(obj=spot)
    form.lot_id.choices = [(lot_item.id, lot_item.prime_location_name) for lot_item in ParkingLot.query.all()]

    if form.validate_on_submit():
        old_lot_id = spot.lot_id
        new_lot_id = form.lot_id.data

        if old_lot_id != new_lot_id:
            new_lot = ParkingLot.query.get_or_404(new_lot_id)
            current_spots_in_new_lot = ParkingSpot.query.filter_by(lot_id=new_lot_id).count()
            if current_spots_in_new_lot >= new_lot.maximum_number_of_spots:
                flash(f'Cannot move spot to Lot {new_lot.prime_location_name}. It has reached its maximum spots.', 'danger')
                logging.warning(f"Admin {current_user.email} attempted to move spot {spot_id} to full lot {new_lot_id}.")
                return render_template('admin/edit_spot.html', form=form, spot=spot)
            
            spot.lot_id = new_lot_id
            logging.info(f"Admin {current_user.email} moved spot {spot_id} from lot {old_lot_id} to {new_lot_id}.")

        spot.status = form.status.data
        try:
            db.session.commit()
            cache.delete(f'parking_spots_{old_lot_id}')
            if old_lot_id != new_lot_id:
                cache.delete(f'parking_spots_{new_lot_id}')
            flash(f'Spot {spot.id} updated successfully!', 'success')
            logging.info(f"Admin {current_user.email} updated spot {spot.id}.")
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to update spot. Please try again.', 'danger')
            logging.error(f"Error updating spot {spot.id}: {e}")

    return render_template('admin/edit_spot.html', form=form, spot=spot)

@app.route('/admin/delete_spot/<int:spot_id>', methods=['POST'])
@login_required
def delete_spot(spot_id):
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))

    spot = ParkingSpot.query.get_or_404(spot_id)
    if spot.status == 'O':
        flash('Cannot delete an occupied spot. It must be released first.', 'danger')
        logging.warning(f"Admin {current_user.email} attempted to delete occupied spot {spot_id}.")
        return redirect(url_for('dashboard'))

    try:
        db.session.delete(spot)
        db.session.commit()
        cache.delete(f'parking_spots_{spot.lot_id}')
        flash(f'Spot {spot_id} and its history deleted successfully!', 'success')
        logging.info(f"Admin {current_user.email} deleted spot {spot_id}.")
    except Exception as e:
        db.session.rollback()
        flash('Failed to delete spot. Please try again.', 'danger')
        logging.error(f"Error deleting spot {spot_id}: {e}")

    return redirect(url_for('dashboard'))

@app.route('/admin/view_delete_spot', methods=['GET', 'POST'])
@login_required
def admin_view_delete_spot():
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))

    spot = None
    form_submitted = False

    if request.method == 'POST':
        form_submitted = True
        spot_id = request.form.get('spot_id')
        if request.form.get('action') == 'delete':
            if spot_id:
                try:
                    spot_id_int = int(spot_id)
                    spot_to_delete = ParkingSpot.query.get(spot_id_int)
                    if spot_to_delete:
                        if spot_to_delete.status == 'O':
                            flash(f'Cannot delete occupied spot {spot_id_int}. It must be released first.', 'danger')
                            logging.warning(f"Admin {current_user.email} attempted to delete occupied spot {spot_id_int}.")
                        else:
                            db.session.delete(spot_to_delete)
                            db.session.commit()
                            cache.delete(f'parking_spots_{spot_to_delete.lot_id}')
                            flash(f'Spot {spot_id_int} and its history deleted successfully!', 'success')
                            logging.info(f"Admin {current_user.email} deleted spot {spot_id_int}.")
                            return redirect(url_for('dashboard'))
                    else:
                        flash(f'Spot with ID {spot_id_int} not found for deletion.', 'danger')
                        logging.warning(f"Admin {current_user.email} attempted to delete non-existent spot ID {spot_id_int}.")
                except ValueError:
                    flash('Invalid Spot ID. Please enter a number.', 'danger')
                    logging.warning(f"Admin {current_user.email} entered non-numeric spot ID for deletion: {spot_id}.")
                except Exception as e:
                    db.session.rollback()
                    flash(f'An error occurred during deletion: {e}', 'danger')
                    logging.error(f"Error deleting spot {spot_id}: {e}")
            else:
                flash('Please enter a Spot ID to delete.', 'warning')
        else:
            if spot_id:
                try:
                    spot_id = int(spot_id)
                    spot = ParkingSpot.query.get(spot_id)
                    if not spot:
                        flash(f'Spot with ID {spot_id} not found.', 'danger')
                        logging.warning(f"Admin {current_user.email} searched for non-existent spot ID {spot_id}.")
                except ValueError:
                    flash('Invalid Spot ID. Please enter a number.', 'danger')
                    logging.warning(f"Admin {current_user.email} entered non-numeric spot ID: {request.form.get('spot_id')}.")
            else:
                flash('Please enter a Spot ID to search.', 'warning')

    spot_details = None
    if spot:
        occupying_user_email = 'N/A'
        active_reservation = Reservation.query.filter_by(spot_id=spot.id, leaving_timestamp=None).first()
        if active_reservation and active_reservation.user:
            occupying_user_email = active_reservation.user.email
        spot_details = {
            'id': spot.id,
            'lot_name': spot.lot.prime_location_name if spot.lot else 'N/A',
            'status': 'Available' if spot.status == 'A' else 'Occupied',
            'occupying_user_email': occupying_user_email
        }
    
    return render_template('admin/view_delete_spot.html', spot_details=spot_details, form_submitted=form_submitted)

@app.route('/admin/occupied_spots')
@login_required
def admin_occupied_spots():
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))

    occupied_reservations = Reservation.query.filter_by(leaving_timestamp=None).all()
    occupied_reservations.sort(key=lambda r: r.parking_timestamp or datetime.min, reverse=True)

    occupied_spot_data = []
    for res in occupied_reservations:
        current_time = get_ist_time()
        parking_time_naive = res.parking_timestamp.replace(tzinfo=None) if res.parking_timestamp and res.parking_timestamp.tzinfo else res.parking_timestamp
        current_time_naive = current_time.replace(tzinfo=None) if current_time.tzinfo else current_time

        estimated_current_cost = 'N/A'
        if parking_time_naive and res.spot and res.spot.lot:
            duration_td = current_time_naive - parking_time_naive
            actual_hours = duration_td.total_seconds() / 3600
            estimated_current_cost = f"₹{(res.spot.lot.price * actual_hours):.2f}"

        occupied_spot_data.append({
            'reservation_id': res.id,
            'spot_id': res.spot_id,
            'lot_name': res.spot.lot.prime_location_name if res.spot and res.spot.lot else 'N/A',
            'customer_email': res.user.email if res.user else 'N/A',
            'vehicle_no': res.vehicle_no,
            'parking_timestamp': res.parking_timestamp.strftime('%Y-%m-%d %H:%M') if res.parking_timestamp else 'N/A',
            'current_cost_estimate': estimated_current_cost
        })

    logging.info(f"Admin {current_user.email} accessed occupied spots page.")
    return render_template('admin/occupied_spots.html', occupied_spot_data=occupied_spot_data)

@app.route('/admin/view_users')
@login_required
def view_users():
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('admin/view_users.html', users=users)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))

    user_to_edit = User.query.get_or_404(user_id)
    form = EditUserForm(obj=user_to_edit)

    if user_to_edit.id == current_user.id:
        form.is_admin.render_kw = {'disabled': 'disabled'}
        form.is_blocked.render_kw = {'disabled': 'disabled'}

    if form.validate_on_submit():
        if user_to_edit.id == current_user.id:
            flash('You cannot change your own admin or block status.', 'warning')
            return render_template('admin/edit_user.html', form=form, user=user_to_edit)

        existing_user = User.query.filter(User.email == form.email.data, User.id != user_id).first()
        if existing_user:
            flash('Another user with this email already exists.', 'danger')
            logging.warning(f"Admin {current_user.email} attempted to update user {user_id} to duplicate email.")
            return render_template('admin/edit_user.html', form=form, user=user_to_edit)

        user_to_edit.email = form.email.data
        user_to_edit.is_admin = form.is_admin.data
        user_to_edit.is_blocked = form.is_blocked.data
        
        try:
            db.session.commit()
            flash(f'User {user_to_edit.email} updated successfully!', 'success')
            logging.info(f"Admin {current_user.email} updated user {user_to_edit.email} (ID: {user_id}).")
            return redirect(url_for('view_users'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to update user. Please try again.', 'danger')
            logging.error(f"Error updating user {user_id}: {e}")

    return render_template('admin/edit_user.html', form=form, user=user_to_edit)

@app.route('/admin/block_user/<int:user_id>', methods=['POST'])
@login_required
def block_user(user_id):
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    user_to_block = User.query.get_or_404(user_id)
    if user_to_block.is_admin:
        flash('Cannot block another admin user.', 'danger')
        logging.warning(f"Admin {current_user.email} attempted to block admin user {user_id}.")
        return redirect(url_for('view_users'))
    if user_to_block.id == current_user.id:
        flash('Cannot block your own account.', 'danger')
        logging.warning(f"Admin {current_user.email} attempted to block self.")
        return redirect(url_for('view_users'))

    user_to_block.is_blocked = True
    try:
        db.session.commit()
        flash(f'User {user_to_block.email} has been blocked.', 'success')
        logging.info(f"Admin {current_user.email} blocked user {user_to_block.email}.")
    except Exception as e:
        db.session.rollback()
        flash('Failed to block user. Please try again.', 'danger')
        logging.error(f"Error blocking user {user_id}: {e}")
    return redirect(url_for('view_users'))

@app.route('/admin/unblock_user/<int:user_id>', methods=['POST'])
@login_required
def unblock_user(user_id):
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    user_to_unblock = User.query.get_or_404(user_id)
    user_to_unblock.is_blocked = False
    try:
        db.session.commit()
        flash(f'User {user_to_unblock.email} has been unblocked.', 'success')
        logging.info(f"Admin {current_user.email} unblocked user {user_to_unblock.email}.")
    except Exception as e:
        db.session.rollback()
        flash('Failed to unblock user. Please try again.', 'danger')
        logging.error(f"Error unblocking user {user_id}: {e}")
    return redirect(url_for('view_users'))

@app.route('/admin/edit_reservation/<int:reservation_id>', methods=['GET', 'POST'])
@login_required
def edit_reservation(reservation_id):
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))

    reservation = Reservation.query.get_or_404(reservation_id)
    form = ReservationForm(obj=reservation)

    if request.method == 'GET':
        if reservation.parking_timestamp:
            form.parking_timestamp.data = reservation.parking_timestamp.replace(tzinfo=None)
        if reservation.leaving_timestamp:
            form.leaving_timestamp.data = reservation.leaving_timestamp.replace(tzinfo=None)

    if form.validate_on_submit():
        reservation.vehicle_no = form.vehicle_no.data
        reservation.hours = form.hours.data
        reservation.parking_cost = form.parking_cost.data
        reservation.parking_timestamp = form.parking_timestamp.data
        reservation.leaving_timestamp = form.leaving_timestamp.data

        spot = ParkingSpot.query.get(reservation.spot_id)
        if spot:
            if reservation.leaving_timestamp:
                spot.status = 'A'
            else:
                spot.status = 'O'
        else:
            logging.warning(f"Spot {reservation.spot_id} not found for reservation {reservation_id} during admin edit.")

        try:
            db.session.commit()
            if spot:
                cache.delete(f'parking_spots_{spot.lot_id}')
            flash(f'Reservation {reservation_id} updated successfully!', 'success')
            logging.info(f"Admin {current_user.email} updated reservation {reservation_id}.")
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to update reservation. Please try again.', 'danger')
            logging.error(f"Error updating reservation {reservation_id}: {e}")

    return render_template('admin/edit_reservation.html', form=form, reservation=reservation, user_email=reservation.user.email if reservation.user else 'N/A')

@app.route('/admin/delete_reservation/<int:reservation_id>', methods=['POST'])
@login_required
def delete_reservation(reservation_id):
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))

    reservation = Reservation.query.get_or_404(reservation_id)
    spot = ParkingSpot.query.get(reservation.spot_id)

    try:
        db.session.delete(reservation)
        if spot and not reservation.leaving_timestamp:
            spot.status = 'A'
        db.session.commit()
        if spot:
            cache.delete(f'parking_spots_{spot.lot_id}')
        flash(f'Reservation {reservation_id} deleted successfully!', 'success')
        logging.info(f"Admin {current_user.email} deleted reservation {reservation_id}.")
    except Exception as e:
        db.session.rollback()
        flash('Failed to delete reservation. Please try again.', 'danger')
        logging.error(f"Error deleting reservation {reservation_id}: {e}")
    return redirect(url_for('dashboard'))

@app.route('/admin/cleanup_old_data', methods=['POST'])
@login_required
def cleanup_old_data():
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))

    threshold_date = get_ist_time() - timedelta(days=30)
    old_reservations = Reservation.query.filter(
        Reservation.leaving_timestamp != None,
        Reservation.leaving_timestamp < threshold_date
    ).all()

    if not old_reservations:
        flash('No old released reservations found to clean up.', 'info')
        logging.info(f"Admin {current_user.email} ran cleanup, no old data found.")
        return redirect(url_for('dashboard'))

    deleted_count = 0
    lot_ids = set()
    try:
        for res in old_reservations:
            if res.spot:
                lot_ids.add(res.spot.lot_id)
            db.session.delete(res)
            deleted_count += 1
        db.session.commit()
        for lot_id in lot_ids:
            cache.delete(f'parking_spots_{lot_id}')
        flash(f'Successfully deleted {deleted_count} old released reservations.', 'success')
        logging.info(f"Admin {current_user.email} deleted {deleted_count} old released reservations.")
    except Exception as e:
        db.session.rollback()
        flash('Failed to clean up old data. Please try again.', 'danger')
        logging.error(f"Error during old data cleanup: {e}")

    return redirect(url_for('dashboard'))

@app.route('/admin/search', methods=['GET', 'POST'])
@login_required
def search():
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))

    form = SearchForm()
    search_results = {'users': [], 'spots': [], 'reservations': []}
    search_performed = False

    if form.validate_on_submit():
        search_performed = True
        search_type = form.search_type.data
        query_text = form.query_text.data

        if search_type == 'user_email' and query_text:
            users = User.query.filter(User.email.ilike(f'%{query_text}%')).all()
            search_results['users'] = users
            logging.info(f"Admin {current_user.email} searched for user email: '{query_text}'")
        elif search_type == 'vehicle_no' and query_text:
            reservations = Reservation.query.filter(Reservation.vehicle_no.ilike(f'%{query_text}%')).all()
            search_results['reservations'] = reservations
            logging.info(f"Admin {current_user.email} searched for vehicle no: '{query_text}'")
        elif search_type == 'lot_location' and query_text:
            lot = None
            try:
                lot_id_int = int(query_text)
                lot = ParkingLot.query.get(lot_id_int)
            except ValueError:
                lot = ParkingLot.query.filter(
                    db.func.lower(ParkingLot.prime_location_name).ilike(f'%{query_text.lower()}%')
                ).first()
            if lot:
                spots = ParkingSpot.query.filter_by(lot_id=lot.id).all()
                search_results['spots'] = spots
                lot_spot_ids = [s.id for s in spots]
                reservations = Reservation.query.filter(Reservation.spot_id.in_(lot_spot_ids)).all()
                search_results['reservations'].extend(reservations)
                logging.info(f"Admin {current_user.email} searched for spots in lot '{query_text}' (ID: {lot.id})")
            else:
                flash(f"No parking lot found matching '{query_text}'.", 'warning')
        if not any(search_results.values()):
            flash('No results found for your query.', 'info')

    return render_template('admin/search.html', form=form, search_results=search_results, search_performed=search_performed)

@app.route('/admin/summary')
@login_required
def admin_summary():
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))

    total_users = User.query.count()
    total_lots = ParkingLot.query.count()
    total_spots = ParkingSpot.query.count()
    total_reservations = Reservation.query.count()
    
    spot_status_chart = {
        'type': 'pie',
        'data': {
            'labels': ['Available', 'Occupied'],
            'datasets': [{
                'data': [ParkingSpot.query.filter_by(status='A').count(), ParkingSpot.query.filter_by(status='O').count()],
                'backgroundColor': ['#28a745', '#dc3545'],
                'borderColor': ['#ffffff', '#ffffff'],
                'borderWidth': 1
            }]
        },
        'options': {
            'responsive': True,
            'plugins': {
                'legend': {'position': 'top'},
                'title': {'display': True, 'text': 'Spot Status'}
            }
        }
    }
    reservation_status_chart = {
        'type': 'pie',
        'data': {
            'labels': ['Active', 'Released'],
            'datasets': [{
                'data': [Reservation.query.filter_by(leaving_timestamp=None).count(), Reservation.query.filter(Reservation.leaving_timestamp != None).count()],
                'backgroundColor': ['#007bff', '#6c757d'],
                'borderColor': ['#ffffff', '#ffffff'],
                'borderWidth': 1
            }]
        },
        'options': {
            'responsive': True,
            'plugins': {
                'legend': {'position': 'top'},
                'title': {'display': True, 'text': 'Reservation Status'}
            }
        }
    }
    total_revenue = sum(r.parking_cost for r in Reservation.query.filter(Reservation.leaving_timestamp != None).all() if r.parking_cost)

    logging.info(f"Admin {current_user.email} accessed summary page.")
    return render_template('admin/summary.html',
                           total_users=total_users,
                           total_lots=total_lots,
                           total_spots=total_spots,
                           total_reservations=total_reservations,
                           spot_status_chart=spot_status_chart,
                           reservation_status_chart=reservation_status_chart,
                           total_revenue=total_revenue)

# --- Database Initialization ---
with app.app_context():
    db.create_all()
    if not User.query.filter_by(is_admin=True).first():
        admin_user = User(email='admin@example.com',
                          password=generate_password_hash('adminpass'),
                          is_admin=True)
        db.session.add(admin_user)
        db.session.commit()
        logging.info("Default admin user created: admin@example.com")
        print("Default admin user created: admin@example.com with password 'adminpass'")

if __name__ == '__main__':
    app.run(debug=True)