from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    # Add this line to handle re-declarations gracefully during development/reloads
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_blocked = db.Column(db.Boolean, default=False)
    # Relationship to Reservations (one-to-many)
    reservations = db.relationship('Reservation', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.email}>'

class ParkingLot(db.Model):
    # Add this line to handle re-declarations gracefully during development/reloads
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    prime_location_name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False) # Price per hour
    address = db.Column(db.String(200), nullable=False)
    pin_code = db.Column(db.String(10), unique=True, nullable=False) # Unique Pin Code
    maximum_number_of_spots = db.Column(db.Integer, nullable=False)
    # Relationship to ParkingSpot (one-to-many)
    spots = db.relationship('ParkingSpot', backref='lot', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<ParkingLot {self.prime_location_name}>'

    # New properties to dynamically calculate spot counts
    @property
    def occupied_spots_count(self):
        # Count spots associated with this lot that have status 'O' (Occupied)
        return ParkingSpot.query.with_parent(self).filter_by(status='O').count()

    @property
    def available_spots_count(self):
        # Count spots associated with this lot that have status 'A' (Available)
        return ParkingSpot.query.with_parent(self).filter_by(status='A').count()


class ParkingSpot(db.Model):
    # Add this line to handle re-declarations gracefully during development/reloads
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    lot_id = db.Column(db.Integer, db.ForeignKey('parking_lot.id'), nullable=False)
    # Status: 'A' for Available, 'O' for Occupied
    status = db.Column(db.String(1), default='A', nullable=False)
    # Relationship to Reservations (one-to-many)
    # This ensures that deleting a spot also deletes associated reservations for consistency
    reservations = db.relationship('Reservation', backref='spot', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<ParkingSpot {self.id} (Lot: {self.lot_id}, Status: {self.status})>'

class Reservation(db.Model):
    # Add this line to handle re-declarations gracefully during development/reloads
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    spot_id = db.Column(db.Integer, db.ForeignKey('parking_spot.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vehicle_no = db.Column(db.String(20), nullable=True) # Vehicle number for the reservation
    parking_cost = db.Column(db.Float, nullable=False)
    hours = db.Column(db.Float, nullable=False) # Duration of parking in hours
    parking_timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    leaving_timestamp = db.Column(db.DateTime, nullable=True) # Null if spot is still occupied

    def __repr__(self):
        return f'<Reservation {self.id} (User: {self.user_id}, Spot: {self.spot_id}, Cost: {self.parking_cost})>'

