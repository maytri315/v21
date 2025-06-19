from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, IntegerField, SelectField, SubmitField
from wtforms.validators import DataRequired, NumberRange

class ParkingLotForm(FlaskForm):
    location_name = StringField('Location Name', validators=[DataRequired()])
    price = FloatField('Price per Hour', validators=[DataRequired(), NumberRange(min=0)])
    address = StringField('Address', validators=[DataRequired()])
    pin_code = StringField('Pin Code', validators=[DataRequired()])
    max_spots = IntegerField('Maximum Spots', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Submit')

class ParkingSpotForm(FlaskForm):
    lot_id = IntegerField('Lot ID', validators=[DataRequired()])
    status = SelectField('Status', choices=[('A', 'Available'), ('O', 'Occupied')], validators=[DataRequired()])
    submit = SubmitField('Submit')

class ReservationForm(FlaskForm):
    hours = FloatField('Hours', validators=[DataRequired(), NumberRange(min=0.1)])
    submit = SubmitField('Book Spot')

class SelectParkingLotForm(FlaskForm):
    lot_id = SelectField('Parking Lot', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Select Lot')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')