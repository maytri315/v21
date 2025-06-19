from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_restful import Api, Resource
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, ParkingLot, ParkingSpot, Reservation
from forms import LoginForm, RegistrationForm, ParkingLotForm, ParkingSpotForm, ReservationForm, SelectParkingLotForm
from datetime import datetime
try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None
import pytz
import os
import logging

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key')
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')
if not os.path.exists(instance_path):
    os.makedirs(instance_path)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_path, "parking.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Enable CSRF protection
csrf = CSRFProtect(app)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
api = Api(app)

def get_ist_time():
    """Get current time in Asia/Kolkata timezone."""
    if ZoneInfo:
        try:
            return datetime.now(ZoneInfo("Asia/Kolkata"))
        except Exception as e:
            logging.warning(f"ZoneInfo failed: {e}, falling back to pytz")
    return datetime.now(pytz.timezone("Asia/Kolkata"))

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    try:
        return db.session.get(User, int(user_id))
    except Exception as e:
        logging.error(f"Error loading user {user_id}: {e}")
        return None

# API Resources
class ParkingLotAPI(Resource):
    def get(self, lot_id=None):
        """Get parking lot(s) via API."""
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
    def get(self, lot_id):
        """Get parking spots for a lot via API."""
        try:
            spots = ParkingSpot.query.filter_by(lot_id=lot_id).all()
            return [{'id': spot.id, 'status': 'Available' if spot.status == 'A' else 'Occupied'} for spot in spots]
        except Exception as e:
            logging.error(f"Error in ParkingSpotAPI: {e}")
            return {'error': 'Internal server error'}, 500

api.add_resource(ParkingLotAPI, '/api/lots', '/api/lots/<int:lot_id>')
api.add_resource(ParkingSpotAPI, '/api/lots/<int:lot_id>/spots')

@app.route('/')
def home():
    """Render the home page."""
    return render_template('home.html')

@app.route('/contact')
def contact():
    """Render the contact page."""
    return render_template('contact.html')

@app.route('/about')
def about():
    """Render the about page."""
    return render_template('about.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if current_user.is_authenticated:
        logging.info(f"Authenticated user {current_user.email} redirected from login")
        return redirect(url_for('dashboard'))
    form = LoginForm()
    logging.debug(f"Login form instantiated: {form}")
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
    logging.debug(f"Rendering login.html with form: {form}")
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    if current_user.is_authenticated:
        logging.info(f"Authenticated user {current_user.email} redirected from register")
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists', 'danger')
            logging.warning(f"Registration failed: {form.email.data} already exists")
            return render_template('register.html', form=form)
        user = User(email=form.email.data, password=generate_password_hash(form.password.data))
        db.session.add(user)
        db.session.commit()
        flash('Registration successful', 'success')
        logging.info(f"User {form.email.data} registered")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    email = current_user.email
    logout_user()
    flash('Logged out successfully', 'success')
    logging.info(f"User {email} logged out")
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Render user or admin dashboard based on role."""
    if current_user.is_blocked:
        flash('Your account is blocked. Contact an admin.', 'danger')
        logout_user()
        logging.info(f"Blocked user {current_user.email} logged out")
        return redirect(url_for('login'))
    lots = ParkingLot.query.all()
    if current_user.is_admin:
        users = User.query.all()
        spots = ParkingSpot.query.all()
        reservations = Reservation.query.all()
        # Chart data for Spot Status
        spot_status_data = {
            'labels': ['Available', 'Occupied'],
            'datasets': [{
                'data': [ParkingSpot.query.filter_by(status='A').count(), ParkingSpot.query.filter_by(status='O').count()],
                'backgroundColor': ['#36A2EB', '#FF6384']
            }]
        }
        # Chart data for Reservation Status
        reservation_status_data = {
            'labels': ['Active', 'Released'],
            'datasets': [{
                'data': [Reservation.query.filter_by(leaving_timestamp=None).count(), Reservation.query.filter(Reservation.leaving_timestamp != None).count()],
                'backgroundColor': ['#36A2EB', '#FF6384']
            }]
        }
        logging.info(f"Admin {current_user.email} accessed dashboard")
        return render_template('admin/dashboard.html', lots=lots, users=users, spots=spots, reservations=reservations, spot_status_data=spot_status_data, reservation_status_data=reservation_status_data)
    reservations = Reservation.query.filter_by(user_id=current_user.id).all()
    # Chart data for User Spot Status
    active_spots = sum(1 for r in reservations if r.leaving_timestamp is None)
    released_spots = sum(1 for r in reservations if r.leaving_timestamp is not None)
    user_spot_status_data = {
        'labels': ['Occupied', 'Released'],
        'datasets': [{
            'data': [active_spots, released_spots],
            'backgroundColor': ['#FF6384', '#36A2EB']
        }]
    }
    # Chart data for User Reservation Status
    user_reservation_status_data = {
        'labels': ['Active', 'Released'],
        'datasets': [{
            'data': [active_spots, released_spots],
            'backgroundColor': ['#36A2EB', '#FF6384']
        }]
    }
    logging.info(f"User {current_user.email} accessed dashboard with {len(reservations)} reservations")
    return render_template('user/dashboard.html', lots=lots, reservations=reservations, user_spot_status_data=user_spot_status_data, user_reservation_status_data=user_reservation_status_data)

@app.route('/user/select_lot', methods=['GET', 'POST'])
@login_required
def select_lot():
    """Allow users to select a parking lot."""
    if current_user.is_blocked:
        flash('Your account is blocked.', 'danger')
        return redirect(url_for('dashboard'))
    if current_user.is_admin:
        flash('Admins cannot book spots', 'danger')
        return redirect(url_for('dashboard'))
    # Get lots with at least one available spot
    available_lots = db.session.query(ParkingLot).join(ParkingSpot).filter(ParkingSpot.status == 'A').distinct().all()
    form = SelectParkingLotForm()
    form.lot_id.choices = [(lot.id, f"{lot.prime_location_name} ({lot.address})") for lot in available_lots]
    if not available_lots:
        flash('No lots with available spots.', 'warning')
        return render_template('user/select_lot.html', form=form)
    if form.validate_on_submit():
        return redirect(url_for('book_spot', lot_id=form.lot_id.data))
    return render_template('user/select_lot.html', form=form)

@app.route('/user/book_spot/<int:lot_id>', methods=['GET', 'POST'])
@login_required
def book_spot(lot_id):
    """Allow users to book the first available spot in a parking lot."""
    if current_user.is_blocked:
        flash('Your account is blocked.', 'danger')
        return redirect(url_for('dashboard'))
    if current_user.is_admin:
        flash('Admins cannot book spots', 'danger')
        return redirect(url_for('dashboard'))
    lot = ParkingLot.query.get_or_404(lot_id)
    # Get the first available spot
    spot = ParkingSpot.query.filter_by(lot_id=lot_id, status='A').first()
    form = ReservationForm()
    if not spot:
        flash('No available spots in this lot.', 'warning')
        return render_template('user/book_spot.html', lot=lot, form=form)
    if form.validate_on_submit():
        if spot.status == 'O':
            flash('Spot already occupied', 'danger')
            logging.warning(f"User {current_user.email} attempted to book occupied spot {spot.id}")
            return render_template('user/book_spot.html', lot=lot, form=form)
        try:
            hours = float(form.hours.data)
            if hours <= 0:
                raise ValueError("Hours must be positive")
        except ValueError as e:
            flash(f'Invalid hours value: {e}', 'danger')
            logging.warning(f"Invalid hours input by user {current_user.email}: {e}")
            return render_template('user/book_spot.html', lot=lot, form=form)
        spot.status = 'O'
        reservation = Reservation(
            spot_id=spot.id,
            user_id=current_user.id,
            parking_cost=lot.price * hours,
            hours=hours,
            parking_timestamp=get_ist_time(),
            leaving_timestamp=None
        )
        try:
            db.session.add(reservation)
            db.session.commit()
            flash(f'Spot {spot.id} booked successfully for {hours} hours', 'success')
            logging.info(f"User {current_user.email} booked spot {spot.id} in lot {lot_id} for {hours} hours, reservation ID {reservation.id}")
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to book spot. Please try again.', 'danger')
            logging.error(f"Booking failed for user {current_user.email}, spot {spot.id}: {e}")
            return render_template('user/book_spot.html', lot=lot, form=form)
    return render_template('user/book_spot.html', lot=lot, form=form)

@app.route('/user/release_spot/<int:reservation_id>', methods=['POST'])
@login_required
def release_spot(reservation_id):
    """Allow users to release a booked spot."""
    if current_user.is_blocked:
        flash('Your account is blocked.', 'danger')
        return redirect(url_for('dashboard'))
    if current_user.is_admin:
        flash('Admins cannot release spots', 'danger')
        return redirect(url_for('dashboard'))
    reservation = Reservation.query.get_or_404(reservation_id)
    if reservation.user_id != current_user.id:
        flash('Unauthorized action', 'danger')
        logging.warning(f"User {current_user.email} attempted unauthorized release of reservation {reservation_id}")
        return redirect(url_for('dashboard'))
    spot = ParkingSpot.query.get(reservation.spot_id)
    spot.status = 'A'
    reservation.leaving_timestamp = get_ist_time()
    db.session.commit()
    flash('Spot released successfully', 'success')
    logging.info(f"User {current_user.email} released spot {reservation.spot_id}")
    return redirect(url_for('dashboard'))

@app.route('/user/cancel_reservation/<int:reservation_id>', methods=['POST'])
@login_required
def cancel_reservation(reservation_id):
    """Allow users to cancel a reservation."""
    if current_user.is_blocked:
        flash('Your account is blocked.', 'danger')
        return redirect(url_for('dashboard'))
    if current_user.is_admin:
        flash('Admins cannot cancel reservations', 'danger')
        return redirect(url_for('dashboard'))
    reservation = Reservation.query.get_or_404(reservation_id)
    if reservation.user_id != current_user.id:
        flash('Unauthorized action', 'danger')
        logging.warning(f"User {current_user.email} attempted unauthorized cancellation of reservation {reservation_id}")
        return redirect(url_for('dashboard'))
    if reservation.leaving_timestamp:
        flash('Cannot cancel a released reservation', 'danger')
        logging.warning(f"User {current_user.email} attempted to cancel released reservation {reservation_id}")
        return redirect(url_for('dashboard'))
    spot = ParkingSpot.query.get(reservation.spot_id)
    spot.status = 'A'
    db.session.delete(reservation)
    db.session.commit()
    flash('Reservation cancelled successfully', 'success')
    logging.info(f"User {current_user.email} cancelled reservation {reservation_id}")
    return redirect(url_for('dashboard'))

@app.route('/admin/create_lot', methods=['GET', 'POST'])
@login_required
def create_lot():
    """Allow admins to create a parking lot."""
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    form = ParkingLotForm()
    if form.validate_on_submit():
        # Check for duplicate name, address, or pin_code
        existing_lot = ParkingLot.query.filter(
            db.or_(
                db.and_(
                    ParkingLot.prime_location_name == form.location_name.data,
                    ParkingLot.address == form.address.data
                ),
                ParkingLot.pin_code == form.pin_code.data
            )
        ).first()
        if existing_lot:
            if existing_lot.pin_code == form.pin_code.data:
                flash('A parking lot with this pin code already exists', 'danger')
            else:
                flash('A parking lot with this name and address already exists', 'danger')
            logging.warning(f"Admin {current_user.email} attempted to create duplicate lot {form.location_name.data} or pin_code {form.pin_code.data}")
            return render_template('admin/create_lot.html', form=form)
        lot = ParkingLot(
            prime_location_name=form.location_name.data,
            price=form.price.data,
            address=form.address.data,
            pin_code=form.pin_code.data,
            maximum_number_of_spots=form.max_spots.data
        )
        db.session.add(lot)
        try:
            db.session.commit()
            for _ in range(form.max_spots.data):
                spot = ParkingSpot(lot_id=lot.id)
                db.session.add(spot)
            db.session.commit()
            flash('Parking lot created', 'success')
            logging.info(f"Admin {current_user.email} created lot {form.location_name.data}")
            return redirect(url_for('dashboard'))
        except db.exc.IntegrityError as e:
            db.session.rollback()
            flash('Failed to create lot: Pin code already in use.', 'danger')
            logging.error(f"IntegrityError in create_lot for pin_code {form.pin_code.data}: {e}")
            return render_template('admin/create_lot.html', form=form)
    return render_template('admin/create_lot.html', form=form)

@app.route('/admin/edit_lot/<int:lot_id>', methods=['GET', 'POST'])
@login_required
def edit_lot(lot_id):
    """Allow admins to edit a parking lot."""
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    lot = ParkingLot.query.get_or_404(lot_id)
    form = ParkingLotForm(obj=lot)
    if form.validate_on_submit():
        existing_lot = ParkingLot.query.filter(
            db.or_(
                db.and_(
                    ParkingLot.prime_location_name == form.location_name.data,
                    ParkingLot.address == form.address.data
                ),
                ParkingLot.pin_code == form.pin_code.data
            ),
            ParkingLot.id != lot_id
        ).first()
        if existing_lot:
            if existing_lot.pin_code == form.pin_code.data:
                flash('A parking lot with this pin code already exists', 'danger')
            else:
                flash('A parking lot with this name and address already exists', 'danger')
            logging.warning(f"Admin {current_user.email} attempted to update lot {lot_id} to duplicate")
            return render_template('admin/edit_lot.html', form=form, lot=lot)
        lot.prime_location_name = form.location_name.data
        lot.price = form.price.data
        lot.address = form.address.data
        lot.pin_code = form.pin_code.data
        if form.max_spots.data > lot.maximum_number_of_spots:
            for _ in range(form.max_spots.data - lot.maximum_number_of_spots):
                spot = ParkingSpot(lot_id=lot.id)
                db.session.add(spot)
        lot.maximum_number_of_spots = form.max_spots.data
        try:
            db.session.commit()
            flash('Parking lot updated', 'success')
            logging.info(f"Admin {current_user.email} updated lot {lot_id}")
            return redirect(url_for('dashboard'))
        except db.exc.IntegrityError as e:
            db.session.rollback()
            flash('Failed to update lot: Pin code already in use.', 'danger')
            logging.error(f"IntegrityError in edit_lot for pin_code {form.pin_code.data}: {e}")
            return render_template('admin/edit_lot.html', form=form, lot=lot)
    return render_template('admin/edit_lot.html', form=form, lot=lot)

@app.route('/admin/delete_lot/<int:lot_id>', methods=['POST'])
@login_required
def delete_lot(lot_id):
    """Allow admins to delete a parking lot."""
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    lot = ParkingLot.query.get_or_404(lot_id)
    if any(spot.status == 'O' for spot in lot.spots):
        flash('Cannot delete lot with occupied spots', 'danger')
        logging.warning(f"Admin {current_user.email} attempted to delete lot {lot_id} with occupied spots")
        return redirect(url_for('dashboard'))
    db.session.delete(lot)
    db.session.commit()
    flash('Parking lot deleted', 'success')
    logging.info(f"Admin {current_user.email} deleted lot {lot_id}")
    return redirect(url_for('dashboard'))

@app.route('/admin/view_lot/<int:lot_id>')
@login_required
def view_lot(lot_id):
    """Allow admins to view a parking lot."""
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    lot = ParkingLot.query.get_or_404(lot_id)
    return render_template('admin/view_lot.html', lot=lot)

@app.route('/admin/create_spot/<int:lot_id>', methods=['GET', 'POST'])
@login_required
def create_spot(lot_id):
    """Allow admins to create a parking spot."""
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    lot = ParkingLot.query.get_or_404(lot_id)
    form = ParkingSpotForm()
    if form.validate_on_submit():
        spot = ParkingSpot(lot_id=lot_id, status=form.status.data)
        db.session.add(spot)
        db.session.commit()
        flash('Parking spot created', 'success')
        logging.info(f"Admin {current_user.email} created spot in lot {lot_id}")
        return redirect(url_for('dashboard'))
    return render_template('admin/edit_spot.html', form=form, lot=lot, action='create')

@app.route('/admin/edit_spot/<int:spot_id>', methods=['GET', 'POST'])
@login_required
def edit_spot(spot_id):
    """Allow admins to edit a parking spot."""
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    spot = ParkingSpot.query.get_or_404(spot_id)
    form = ParkingSpotForm(obj=spot)
    if form.validate_on_submit():
        spot.lot_id = form.lot_id.data
        spot.status = form.status.data
        db.session.commit()
        flash('Spot updated', 'success')
        logging.info(f"Admin {current_user.email} updated spot {spot_id}")
        return redirect(url_for('dashboard'))
    return render_template('admin/edit_spot.html', form=form, spot=spot, action='edit')

@app.route('/admin/delete_spot/<int:spot_id>', methods=['POST'])
@login_required
def delete_spot(spot_id):
    """Allow admins to delete a parking spot."""
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    spot = ParkingSpot.query.get_or_404(spot_id)
    if spot.status == 'O':
        flash('Cannot delete occupied spot', 'danger')
        logging.warning(f"Admin {current_user.email} attempted to delete occupied spot {spot_id}")
        return redirect(url_for('dashboard'))
    db.session.delete(spot)
    db.session.commit()
    flash('Spot deleted', 'success')
    logging.info(f"Admin {current_user.email} deleted spot {spot_id}")
    return redirect(url_for('dashboard'))

@app.route('/admin/view_spot/<int:spot_id>')
@login_required
def view_spot(spot_id):
    """Allow admins to view a parking spot."""
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    spot = ParkingSpot.query.get_or_404(spot_id)
    reservation = Reservation.query.filter_by(spot_id=spot_id, leaving_timestamp=None).first()
    occupying_user_email = None
    if reservation:
        user = User.query.get(reservation.user_id)
        if user:
            occupying_user_email = user.email
            logging.info(f"Fetched user email {occupying_user_email} for spot {spot_id}, reservation {reservation.id}")
        else:
            logging.error(f"User ID {reservation.user_id} not found for spot {spot_id}, reservation {reservation.id}")
    return render_template('admin/view_spot.html', spot=spot, occupying_user_email=occupying_user_email)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    """Allow admins to edit a user."""
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    form = RegistrationForm(obj=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.password = generate_password_hash(form.password.data)
        user.is_admin = form.is_admin.data if hasattr(form, 'is_admin') else user.is_admin
        db.session.commit()
        flash('User updated', 'success')
        logging.info(f"Admin {current_user.email} updated user {user_id}")
        return redirect(url_for('dashboard'))
    return render_template('admin/edit_user.html', form=form, user=user, action='edit')

@app.route('/admin/block_user/<int:user_id>', methods=['POST'])
@login_required
def block_user(user_id):
    """Allow admins to block a user."""
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Cannot block yourself', 'danger')
        logging.warning(f"Admin {current_user.email} attempted to block themselves")
        return redirect(url_for('dashboard'))
    if user.is_admin:
        flash('Cannot block another admin', 'danger')
        logging.warning(f"Admin {current_user.email} attempted to block admin {user.email}")
        return redirect(url_for('dashboard'))
    user.is_blocked = True
    db.session.commit()
    flash(f'User {user.email} blocked', 'success')
    logging.info(f"Admin {current_user.email} blocked user {user.email}")
    return redirect(url_for('dashboard'))

@app.route('/admin/unblock_user/<int:user_id>', methods=['POST'])
@login_required
def unblock_user(user_id):
    """Allow admins to unblock a user."""
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    user.is_blocked = False
    db.session.commit()
    flash(f'User {user.email} unblocked', 'success')
    logging.info(f"Admin {current_user.email} unblocked user {user.email}")
    return redirect(url_for('dashboard'))

@app.route('/admin/edit_reservation/<int:reservation_id>', methods=['GET', 'POST'])
@login_required
def edit_reservation(reservation_id):
    """Allow admins to edit a reservation."""
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    reservation = Reservation.query.get_or_404(reservation_id)
    user = User.query.get(reservation.user_id)
    if not user:
        logging.error(f"User ID {reservation.user_id} not found for reservation {reservation_id}")
        flash(f'User ID {reservation.user_id} not found for this reservation', 'danger')
        return redirect(url_for('dashboard'))
    user_email = user.email
    form = ReservationForm(obj=reservation)
    if form.validate_on_submit():
        try:
            reservation.spot_id = form.spot_id.data
            reservation.user_id = form.user_id.data
            reservation.parking_cost = form.parking_cost.data
            reservation.hours = form.hours.data
            reservation.parking_timestamp = form.parking_timestamp.data
            reservation.leaving_timestamp = form.leaving_timestamp.data
            db.session.commit()
            flash('Reservation updated', 'success')
            logging.info(f"Admin {current_user.email} updated reservation {reservation_id}")
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to update reservation. Please try again.', 'danger')
            logging.error(f"Reservation update failed for {reservation_id}: {e}")
            return render_template('admin/edit_reservation.html', form=form, reservation=reservation, user_email=user_email)
    return render_template('admin/edit_reservation.html', form=form, reservation=reservation, user_email=user_email)

@app.route('/admin/delete_reservation/<int:reservation_id>', methods=['POST'])
@login_required
def delete_reservation(reservation_id):
    """Allow admins to delete a reservation."""
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    reservation = Reservation.query.get_or_404(reservation_id)
    spot = ParkingSpot.query.get(reservation.spot_id)
    if not reservation.leaving_timestamp:
        spot.status = 'A'
    db.session.delete(reservation)
    db.session.commit()
    flash('Reservation deleted', 'success')
    logging.info(f"Admin {current_user.email} deleted reservation {reservation_id}")
    return redirect(url_for('dashboard'))

@app.route('/admin/search', methods=['GET', 'POST'])
@login_required
def search():
    """Allow admins to search for lots, users, spots, or reservations."""
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    lots = users = spots = reservations = []
    if request.method == 'POST':
        search_type = request.form.get('search_type')
        query = request.form.get('query', '').lower()
        if search_type == 'lots':
            lots = ParkingLot.query.filter(
                db.or_(
                    ParkingLot.prime_location_name.ilike(f'%{query}%'),
                    ParkingLot.address.ilike(f'%{query}%'),
                    ParkingLot.pin_code.ilike(f'%{query}%')
                )
            ).all()
        elif search_type == 'users':
            users = User.query.filter(User.email.ilike(f'%{query}%')).all()
        elif search_type == 'spots':
            status = request.form.get('status')
            spots = ParkingSpot.query.filter(
                ParkingSpot.status == status if status else True
            ).all()
        elif search_type == 'reservations':
            reservations = Reservation.query.join(User).filter(
                db.or_(
                    User.email.ilike(f'%{query}%'),
                    Reservation.parking_timestamp.ilike(f'%{query}%')
                )
            ).all()
    return render_template('admin/search.html', lots=lots, users=users, spots=spots, reservations=reservations)

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()
        if not User.query.filter_by(email='admin@gmail.com').first():
            admin = User(email='admin@gmail.com', password=generate_password_hash('admin123'), is_admin=True)
            db.session.add(admin)
            db.session.commit()
            logging.info("Created default admin user")
        # Debug: Print registered routes
        print("Registered routes:")
        for rule in app.url_map.iter_rules():
            print(f"{rule.endpoint}: {rule}")
    app.run(debug=True, use_reloader=False)