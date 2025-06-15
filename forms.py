from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FloatField, IntegerField
from wtforms.validators import DataRequired, Length, NumberRange

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=120)])

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=120)])

class ParkingLotForm(FlaskForm):
    location_name = StringField('Location Name', validators=[DataRequired(), Length(max=100)])
    price = FloatField('Price per Hour', validators=[DataRequired(), NumberRange(min=0)])
    address = StringField('Address', validators=[DataRequired(), Length(max=200)])
    pin_code = StringField('Pin Code', validators=[DataRequired(), Length(min=6, max=10)])
    max_spots = IntegerField('Max Spots', validators=[DataRequired(), NumberRange(min=1)])