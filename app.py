from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_restful import Api, Resource
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, ParkingLot, ParkingSpot, Reservation
from forms import LoginForm, RegistrationForm, ParkingLotForm, ParkingSpotForm, ReservationForm, SelectParkingLotForm, SearchForm, EditUserForm
from datetime import datetime, timedelta
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
# Ensure a strong SECRET_KEY is set (use environment variable in production)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'a_very_secure_key_change_me_in_production_1234567890')
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
            logging.warning(f"ZoneInfo failed for Asia/Kolkata: {e}, falling back to pytz.")
    try:
        return datetime.now(pytz.timezone("Asia/Kolkata"))
    except Exception as e:
        logging.error(f"Failed to get Asia/Kolkata time with pytz: {e}. Returning naive UTC datetime.")
        return datetime.utcnow()

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    try:
        return db.session.get(User, int(user_id))
    except Exception as e:
        logging.error(f"Error loading user {user_id}: {e}")
        return None

# CSRF Debugging
@app.before_request
def protect_against_csrf():
    try:
        csrf.protect()
    except Exception as e:
        logging.error(f"CSRF protection error: {e}")
        flash('CSRF validation failed. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

# --- API Resources ---
class ParkingLotAPI(Resource):
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
    def get(self, lot_id):
        try:
            spots = ParkingSpot.query.filter_by(lot_id=lot_id).all()
            return [{'id': spot.id, 'status': 'Available' if spot.status == 'A' else 'Occupied'} for spot in spots]
        except Exception as e:
            logging.error(f"Error in ParkingSpotAPI: {e}")
            return {'error': 'Internal server error'}, 500

api.add_resource(ParkingLotAPI, '/api/lots', '/api/lots/<int:lot_id>')
api.add_resource(ParkingSpotAPI, '/api/lots/<int:lot_id>/spots')

# --- General Routes ---
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
    if current_user.is_authenticated:
        logging.info(f"Authenticated user {current_user.email} redirected from register")
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists', 'danger')
            logging.warning(f"Registration failed: {form.email.data} already exists")
            return render_template('register.html', form=form)
        user = User(email=form.email.data, password=generate_password_hash(form.password.data), is_admin=form.is_admin.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        logging.info(f"User {form.email.data} registered (Admin: {form.is_admin.data})")
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

        user_reservation_chart_data = {
            'labels': ['Active', 'Released'],
            'datasets': [{
                'data': [len(active_reservations), len(released_reservations)],
                'backgroundColor': ['#007bff', '#6c757d']
            }]
        }
        recent_history = sorted(user_reservations, key=lambda x: x.parking_timestamp or datetime.min, reverse=True)[:5]
        
        logging.info(f"User {current_user.email} accessed dashboard with {len(user_reservations)} reservations")
        return render_template('user/dashboard.html',
                               lots=lots,
                               reservations=user_reservations,
                               recent_history=recent_history,
                               user_reservation_chart_data=user_reservation_chart_data)

# --- User Specific Routes ---
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
            if 'selected_spot' in session:
                del session['selected_spot']
            return redirect(url_for('dashboard'))

        if 'selected_spot' not in session or form.spot_id.data != session['selected_spot']['id'] or form.user_id.data != current_user.id:
            flash('Session data mismatch. Please try again.', 'danger')
            logging.error(f"Session mismatch for user {current_user.email} in lot {lot_id} at {get_ist_time()}: Form spot_id={form.spot_id.data}, Session spot_id={session.get('selected_spot', {}).get('id')}, Form user_id={form.user_id.data}, Current user_id={current_user.id}")
            if 'selected_spot' in session:
                del session['selected_spot']
            return redirect(url_for('select_lot'))

        selected_spot_data = session['selected_spot']
        re_checked_spot = ParkingSpot.query.get(selected_spot_data['id'])
        if not re_checked_spot or re_checked_spot.status != 'A':
            next_spot = ParkingSpot.query.filter_by(lot_id=lot_id, status='A').first()
            if not next_spot:
                flash('The selected spot and all others are no longer available. Please try again.', 'danger')
                logging.warning(f"No available spots for user {current_user.email} in lot {lot_id} at {get_ist_time()}.")
                del session['selected_spot']
                return redirect(url_for('select_lot'))
            re_checked_spot = next_spot
            form.spot_id.data = re_checked_spot.id
            logging.info(f"Switched to next available spot {re_checked_spot.id} for user {current_user.email} in lot {lot_id}.")

        session_timestamp = datetime.fromisoformat(selected_spot_data['timestamp']).replace(tzinfo=pytz.UTC)
        current_time = get_ist_time().replace(tzinfo=pytz.UTC)
        if (current_time - session_timestamp).total_seconds() > 300:
            flash('Session for spot selection has expired. Please try again.', 'danger')
            logging.warning(f"Stale session spot {selected_spot_data['id']} for user {current_user.email} in lot {lot_id}.")
            del session['selected_spot']
            return redirect(url_for('select_lot'))

        try:
            hours = float(form.hours.data or 1.0)
            if hours <= 0:
                raise ValueError("Parking duration must be greater than 0.")
        except ValueError as e:
            flash(f'Invalid parking duration: {str(e)}. Defaulting to 1 hour.', 'danger')
            logging.warning(f"Invalid hours '{form.hours.data}' from user {current_user.email}, defaulting to 1.")
            hours = 1.0

        vehicle_no = form.vehicle_no.data.strip() if form.vehicle_no.data else 'TEMP1234'
        if len(vehicle_no) > 15:
            flash('Vehicle number exceeds 15 characters. Truncating to 15.', 'warning')
            logging.warning(f"Vehicle number '{vehicle_no}' truncated for user {current_user.email}.")
            vehicle_no = vehicle_no[:15]

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
            flash(f'Spot {re_checked_spot.id} booked successfully for {hours} hours! Total Cost: ₹{parking_cost:.2f}', 'success')
            logging.info(f"User {current_user.email} booked spot {re_checked_spot.id} in lot {lot_id} for {hours} hours, reservation ID {reservation.id} at {get_ist_time()}")
            del session['selected_spot']
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            if re_checked_spot:
                re_checked_spot.status = 'A'
                db.session.commit()
            flash(f'Booking failed due to an error: {str(e)}. Redirecting to dashboard.', 'danger')
            logging.error(f"Booking error for user {current_user.email}, spot {re_checked_spot.id if re_checked_spot else 'N/A'}: {str(e)} at {get_ist_time()}")
            del session['selected_spot']
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
    if spot:
        spot.status = 'A'
    else:
        logging.warning(f"Spot {reservation.spot_id} not found for reservation {reservation_id} during cancellation.")

    try:
        db.session.delete(reservation)
        db.session.commit()
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

    reservation_status_chart_data = {
        'labels': ['Active Reservations', 'Released Reservations'],
        'datasets': [{
            'data': [active_reservations_count, released_reservations_count],
            'backgroundColor': ['#FF6384', '#36A2EB'],
            'hoverOffset': 4
        }]
    }

    total_cost_chart_data = {
        'labels': ['Total Cost Spent'],
        'datasets': [{
            'label': 'Amount (₹)',
            'data': [total_cost_spent],
            'backgroundColor': '#4BC0C0'
        }]
    }

    logging.info(f"User {current_user.email} accessed summary page.")
    return render_template('user/summary.html',
                           reservation_status_chart_data=reservation_status_chart_data,
                           total_cost_spent=total_cost_spent,
                           total_cost_chart_data=total_cost_chart_data)

# --- Admin Specific Routes ---
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
                    db.func.lower(ParkingLot.prime_location_name) == db.func.lower(form.location_name.data),
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
            prime_location_name=form.location_name.data,
            price=form.price.data,
            address=form.address.data,
            pin_code=form.pin_code.data,
            maximum_number_of_spots=form.maximum_number_of_spots.data
        )
        db.session.add(lot)
        try:
            db.session.commit()
            for _ in range(form.maximum_number_of_spots.data):
                spot = ParkingSpot(lot_id=lot.id)
                db.session.add(spot)
            db.session.commit()
            flash('Parking lot and its spots created successfully!', 'success')
            logging.info(f"Admin {current_user.email} created lot {lot.id} ({lot.prime_location_name}) with {lot.maximum_number_of_spots} spots.")
            return redirect(url_for('dashboard'))
        except db.exc.IntegrityError as e:
            db.session.rollback()
            flash('Failed to create lot due to a database error. Check unique constraints.', 'danger')
            logging.error(f"IntegrityError in create_lot for {form.location_name.data}: {e}")
        except Exception as e:
            db.session.rollback()
            flash('An unexpected error occurred while creating the lot. Please try again.', 'danger')
            logging.error(f"General error in create_lot for {form.location_name.data}: {e}")

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
                    db.func.lower(ParkingLot.prime_location_name) == db.func.lower(form.location_name.data),
                    db.func.lower(ParkingLot.address) == db.func.lower(form.address.data),
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

        lot.prime_location_name = form.location_name.data
        lot.price = form.price.data
        lot.address = form.address.data
        lot.pin_code = form.pin_code.data
        lot.maximum_number_of_spots = new_max_spots

        try:
            db.session.commit()
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
        if hasattr(form.is_admin, 'render_kw'):
            form.is_admin.render_kw['disabled'] = 'disabled'
        else:
            form.is_admin.render_kw = {'disabled': 'disabled'}
        if hasattr(form.is_blocked, 'render_kw'):
            form.is_blocked.render_kw['disabled'] = 'disabled'
        else:
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
    try:
        for res in old_reservations:
            db.session.delete(res)
            deleted_count += 1
        db.session.commit()
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
    
    spot_status_data = {
        'labels': ['Available', 'Occupied'],
        'datasets': [{
            'data': [ParkingSpot.query.filter_by(status='A').count(), ParkingSpot.query.filter_by(status='O').count()],
            'backgroundColor': ['#28a745', '#dc3545']
        }]
    }
    reservation_status_data = {
        'labels': ['Active', 'Released'],
        'datasets': [{
            'data': [Reservation.query.filter_by(leaving_timestamp=None).count(), Reservation.query.filter(Reservation.leaving_timestamp != None).count()],
            'backgroundColor': ['#007bff', '#6c757d']
        }]
    }
    total_revenue = sum(r.parking_cost for r in Reservation.query.filter(Reservation.leaving_timestamp != None).all() if r.parking_cost)

    logging.info(f"Admin {current_user.email} accessed summary page.")
    return render_template('admin/summary.html',
                           total_users=total_users,
                           total_lots=total_lots,
                           total_spots=total_spots,
                           total_reservations=total_reservations,
                           spot_status_data=spot_status_data,
                           reservation_status_data=reservation_status_data,
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