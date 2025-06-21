from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, IntegerField, FloatField, DateTimeLocalField
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, Optional, ValidationError
from datetime import datetime

# Custom Validator for DatetimeLocalField to ensure past/present
def valid_datetime_past_or_present(form, field):
    if field.data and field.data > datetime.now():
        raise ValidationError('Datetime cannot be in the future.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, message='Password must be at least 6 characters long.')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    is_admin = BooleanField('Register as Admin (for initial setup only)')
    submit = SubmitField('Register')

    # Email uniqueness check moved to app.py route

class ParkingLotForm(FlaskForm):
    location_name = StringField('Prime Location Name', validators=[DataRequired(), Length(max=100)])
    price = FloatField('Price Per Hour (₹)', validators=[DataRequired(), NumberRange(min=0.01, message='Price must be positive.')])
    address = StringField('Address', validators=[DataRequired(), Length(max=200)])
    pin_code = StringField('Pin Code', validators=[DataRequired(), Length(min=4, max=10)])
    maximum_number_of_spots = IntegerField('Maximum Number of Spots', validators=[DataRequired(), NumberRange(min=1, message='Must have at least 1 spot.')])
    submit = SubmitField('Submit')

    def validate_pin_code(self, pin_code):
        pass  # Uniqueness check moved to app.py

class ParkingSpotForm(FlaskForm):
    lot_id = SelectField('Parking Lot', coerce=int, validators=[DataRequired()])
    status = SelectField('Status', choices=[('A', 'Available'), ('O', 'Occupied')], validators=[DataRequired()])
    submit = SubmitField('Submit')

    # Choices populated in app.py routes

class ReservationForm(FlaskForm):
    spot_id = IntegerField('Spot ID', validators=[Optional()])  # Hidden, pre-filled by route
    user_id = IntegerField('User ID', validators=[Optional()])  # Hidden, pre-filled by route
    vehicle_no = StringField('Vehicle Number', validators=[DataRequired(), Length(max=20)])
    hours = FloatField('Duration in Hours', validators=[DataRequired(), NumberRange(min=0.1, message='Duration must be at least 0.1 hours.')])
    parking_cost = FloatField('Parking Cost (₹)', validators=[Optional(), NumberRange(min=0.0)], render_kw={'readonly': True})  # Calculated by backend
    parking_timestamp = DateTimeLocalField('Parking Time', format='%Y-%m-%dT%H:%M', validators=[Optional(), valid_datetime_past_or_present])
    leaving_timestamp = DateTimeLocalField('Leaving Time', format='%Y-%m-%dT%H:%M', validators=[Optional(), valid_datetime_past_or_present], render_kw={'step': '60'})
    submit = SubmitField('Book Spot')

    def validate_leaving_timestamp(self, field):
        if self.parking_timestamp.data and field.data and field.data < self.parking_timestamp.data:
            raise ValidationError('Leaving time cannot be before parking time.')

    # Removed validate_spot_id and validate_user_id; handled in app.py

class SelectParkingLotForm(FlaskForm):
    lot_id = SelectField('Select Parking Lot', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Select Lot')

    # Choices populated in app.py routes

class SearchForm(FlaskForm):
    def coerce_lot_id(value):
        """Custom coerce function for lot_id to handle empty string."""
        if value == '':
            return None
        return int(value)

    search_type = SelectField('Search By', choices=[
        ('user_email', 'User Email'),
        ('vehicle_no', 'Vehicle Number'),
        ('lot_location', 'Parking Lot (by location/ID)')
    ], validators=[DataRequired()])
    query_text = StringField('Search Query', validators=[Optional(), Length(max=100)])
    lot_id = SelectField('Select Parking Lot', coerce=coerce_lot_id, validators=[Optional()])
    submit = SubmitField('Search')

class EditUserForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    is_admin = BooleanField('Is Admin')
    is_blocked = BooleanField('Is Blocked')
    submit = SubmitField('Update User')