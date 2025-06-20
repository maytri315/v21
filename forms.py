from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, FloatField, IntegerField, SelectField, DateTimeLocalField
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, Optional, ValidationError

# IMPORTANT: Removed all direct imports from 'models' here.
# This is crucial to prevent circular import issues.
# All database-related logic (like populating SelectField choices or unique checks)
# should now be handled directly within your Flask routes in app.py,
# where the application context and database are fully initialized.

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, message='Password must be at least 6 characters long.')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    is_admin = BooleanField('Register as Admin (for initial setup only)') # Added for admin creation
    submit = SubmitField('Register')

    # The validate_email method is removed from here.
    # The uniqueness check for email should be performed in the Flask route (app.py).
    # Your app.py already contains this check, ensuring it happens when the DB is ready.

class ParkingLotForm(FlaskForm):
    location_name = StringField('Prime Location Name', validators=[DataRequired(), Length(max=100)])
    price = FloatField('Price Per Hour (₹)', validators=[DataRequired(), NumberRange(min=0.01, message='Price must be positive.')])
    address = StringField('Address', validators=[DataRequired(), Length(max=200)])
    pin_code = StringField('Pin Code', validators=[DataRequired(), Length(min=4, max=10)])
    maximum_number_of_spots = IntegerField('Maximum Number of Spots', validators=[DataRequired(), NumberRange(min=1, message='Must have at least 1 spot.')])
    submit = SubmitField('Submit')

    # This validator for pin_code is fine as it doesn't access the database.
    # The crucial database uniqueness check for pin_code is also handled in app.py.
    def validate_pin_code(self, pin_code):
        pass

class ParkingSpotForm(FlaskForm):
    # The lot_id choices MUST be populated in the Flask view function (e.g., in app.py's create_spot, edit_spot routes).
    # The __init__ method that attempted to query the database here has been removed.
    lot_id = SelectField('Parking Lot', coerce=int, validators=[DataRequired()])
    status = SelectField('Status', choices=[('A', 'Available'), ('O', 'Occupied')], validators=[DataRequired()])
    submit = SubmitField('Submit')

class ReservationForm(FlaskForm):
    spot_id = IntegerField('Spot ID', validators=[Optional()]) # Can be hidden field, auto-filled
    user_id = IntegerField('User ID', validators=[Optional()]) # Can be hidden field, auto-filled
    vehicle_no = StringField('Vehicle Number', validators=[DataRequired(), Length(max=20)])
    hours = FloatField('Duration in Hours', validators=[DataRequired(), NumberRange(min=0.1, message='Duration must be at least 0.1 hours.')])
    parking_cost = FloatField('Parking Cost (₹)', validators=[Optional(), NumberRange(min=0.0)]) # Optional for initial booking, calculated by backend
    
    # For admin editing of existing reservations, these might be needed
    parking_timestamp = DateTimeLocalField('Parking Time', format='%Y-%m-%dT%H:%M', validators=[Optional()])
    leaving_timestamp = DateTimeLocalField('Leaving Time', format='%Y-%m-%dT%H:%M', validators=[Optional()])

    submit = SubmitField('Book Spot') # For user booking

class SelectParkingLotForm(FlaskForm):
    # The lot_id choices MUST be populated in the Flask view function (e.g., in app.py's select_lot route).
    # The __init__ method that attempted to query the database here has been removed.
    lot_id = SelectField('Select Parking Lot', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Select Lot')

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
    # Using the custom coerce function here
    lot_id = SelectField('Select Parking Lot', coerce=coerce_lot_id, validators=[Optional()])
    submit = SubmitField('Search')

class EditUserForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    is_admin = BooleanField('Is Admin')
    is_blocked = BooleanField('Is Blocked')
    submit = SubmitField('Update User')
