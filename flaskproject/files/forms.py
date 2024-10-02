from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length

class UploadFileForm(FlaskForm):
    nof = StringField('Name of File', validators=[DataRequired(), Length(min=1, max=24)])
    myfile = FileField('Upload A File')
    submit = SubmitField('Upload')

class DownloadFileForm(FlaskForm):
    file_key = StringField('File Key', validators=[DataRequired()])
    submit = SubmitField('Download')