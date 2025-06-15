from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from flask_restful import Api, Resource
from models import db, User, ParkingLot, ParkingSpot, Reservation
from forms import LoginForm, RegisterForm, ParkingLotForm
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "instance", "parking.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
api = Api(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# API Resources
class ParkingLotAPI(Resource):
    def get(self, lot_id=None):
        if lot_id:
            lot = ParkingLot.query.get_or_404(lot_id)
            return {'id': lot.id, 'name': lot.prime_location_name, 'price': lot.price, 'spots': len(lot.spots)}
        lots = ParkingLot.query.all()
        return [{'id': lot.id, 'name': lot.prime_location_name, 'price': lot.price, 'spots': len(lot.spots)} for lot in lots]

class ParkingSpotAPI(Resource):
    def get(self, lot_id):
        spots = ParkingSpot.query.filter_by(lot_id=lot_id).all()
        return [{'id': spot.id, 'status': spot.status} for spot in spots]

api.add_resource(ParkingLotAPI, '/api/lots', '/api/lots/<int:lot_id>')
api.add_resource(ParkingSpotAPI, '/api/lots/<int:lot_id>/spots')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard' if not current_user.is_admin else 'admin_dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data, password=form.password.data).first()
        if user:
            login_user(user)
            flash('Logged in successfully', 'success')
            return redirect(url_for('admin_dashboard' if user.is_admin else 'user_dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard'))
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists', 'danger')
        else:
            user = User(username=form.username.data, password=form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    lots = ParkingLot.query.all()
    reservations = Reservation.query.filter_by(user_id=current_user.id).all()
    return render_template('user/dashboard.html', lots=lots, reservations=reservations)

@app.route('/user/book_spot/<int:lot_id>', methods=['GET', 'POST'])
@login_required
def book_spot(lot_id):
    lot = ParkingLot.query.get_or_404(lot_id)
    spots = ParkingSpot.query.filter_by(lot_id=lot_id).all()
    if request.method == 'POST':
        spot_id = request.form.get('spot_id')
        spot = ParkingSpot.query.get_or_404(spot_id)
        if spot.status == 'O':
            flash('Spot already occupied', 'danger')
            return redirect(url_for('book_spot', lot_id=lot_id))
        hours = float(request.form.get('hours', 1))
        spot.status = 'O'
        reservation = Reservation(
            spot_id=spot.id,
            user_id=current_user.id,
            parking_cost=lot.price * hours,
            parking_timestamp=datetime.utcnow(),
            leaving_timestamp=datetime.utcnow() + timedelta(hours=hours)
        )
        db.session.add(reservation)
        db.session.commit()
        flash('Spot booked successfully', 'success')
        return redirect(url_for('user_dashboard'))
    return render_template('user/book_spot.html', lot=lot, spots=spots)

@app.route('/user/release_spot/<int:reservation_id>')
@login_required
def release_spot(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)
    if reservation.user_id != current_user.id:
        flash('Unauthorized action', 'danger')
        return redirect(url_for('user_dashboard'))
    reservation.leaving_timestamp = datetime.utcnow()
    reservation.spot.status = 'A'
    db.session.commit()
    flash('Spot released successfully', 'success')
    return redirect(url_for('user_dashboard'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    lots = ParkingLot.query.all()
    users = User.query.all()
    return render_template('admin/dashboard.html', lots=lots, users=users)

@app.route('/admin/create_lot', methods=['GET', 'POST'])
@login_required
def create_lot():
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    form = ParkingLotForm()
    if form.validate_on_submit():
        lot = ParkingLot(
            prime_location_name=form.location_name.data,
            price=form.price.data,
            address=form.address.data,
            pin_code=form.pin_code.data,
            maximum_number_of_spots=form.max_spots.data
        )
        db.session.add(lot)
        db.session.commit()
        for _ in range(lot.maximum_number_of_spots):
            spot = ParkingSpot(lot_id=lot.id)
            db.session.add(spot)
        db.session.commit()
        flash('Parking lot created', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/create_lot.html', form=form)

@app.route('/admin/edit_lot/<int:lot_id>', methods=['GET', 'POST'])
@login_required
def edit_lot(lot_id):
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    lot = ParkingLot.query.get_or_404(lot_id)
    form = ParkingLotForm(obj=lot)
    if form.validate_on_submit():
        lot.prime_location_name = form.location_name.data
        lot.price = form.price.data
        lot.address = form.address.data
        lot.pin_code = form.pin_code.data
        if form.max_spots.data > lot.maximum_number_of_spots:
            for _ in range(form.max_spots.data - lot.maximum_number_of_spots):
                spot = ParkingSpot(lot_id=lot.id)
                db.session.add(spot)
        lot.maximum_number_of_spots = form.max_spots.data
        db.session.commit()
        flash('Parking lot updated', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/edit_lot.html', form=form, lot=lot)

@app.route('/admin/delete_lot/<int:lot_id>')
@login_required
def delete_lot(lot_id):
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    lot = ParkingLot.query.get_or_404(lot_id)
    if any(spot.status == 'O' for spot in lot.spots):
        flash('Cannot delete lot with occupied spots', 'danger')
        return redirect(url_for('admin_dashboard'))
    db.session.delete(lot)
    db.session.commit()
    flash('Parking lot deleted', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/cleanup')
@login_required
def cleanup_old_data():
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('user_dashboard'))
    cutoff_date = datetime.utcnow() - timedelta(days=30)
    old_reservations = Reservation.query.filter(
        Reservation.leaving_timestamp.isnot(None),
        Reservation.leaving_timestamp <= cutoff_date
    ).delete()
    db.session.commit()
    flash(f'Deleted {old_reservations} old reservations', 'success')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', password='admin123', is_admin=True)
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)