from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FloatField, IntegerField, SelectField, DateTimeField, BooleanField
from wtforms.validators import DataRequired, Length, NumberRange, Optional, Email, Regexp

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(),
        Length(min=4, max=120),
        Email(),
        Regexp(r'^.+@gmail\.com$', message="Must be a valid Gmail address")
    ])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=120)])

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(),
        Length(min=4, max=120),
        Email(),
        Regexp(r'^.+@gmail\.com$', message="Must be a valid Gmail address")
    ])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=120)])
    is_admin = BooleanField('Is Admin', default=False)

class ParkingLotForm(FlaskForm):
    location_name = StringField('Location Name', validators=[DataRequired(), Length(max=100)])
    price = FloatField('Price per Hour', validators=[DataRequired(), NumberRange(min=0)])
    address = StringField('Address', validators=[DataRequired(), Length(max=200)])
    pin_code = StringField('Pin Code', validators=[DataRequired(), Length(min=6, max=10)])
    max_spots = IntegerField('Max Spots', validators=[DataRequired(), NumberRange(min=1)])

class ParkingSpotForm(FlaskForm):
    lot_id = IntegerField('Lot ID', validators=[DataRequired(), NumberRange(min=1)])
    status = SelectField('Status', choices=[('A', 'Available'), ('O', 'Occupied')], validators=[DataRequired()])

class ReservationForm(FlaskForm):
    spot_id = IntegerField('Spot ID', validators=[DataRequired(), NumberRange(min=1)])
    user_id = IntegerField('User ID', validators=[DataRequired(), NumberRange(min=1)])
    parking_cost = FloatField('Parking Cost', validators=[DataRequired(), NumberRange(min=0)])
    hours = FloatField('Hours', validators=[DataRequired(), NumberRange(min=0.1)])
    parking_timestamp = DateTimeField('Parking Timestamp', validators=[DataRequired()])
    leaving_timestamp = DateTimeField('Leaving Timestamp', validators=[Optional()])