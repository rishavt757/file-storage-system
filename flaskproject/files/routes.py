import os, base64
from cryptography.fernet import Fernet
import zipfile
from flaskproject import db, app
from io import BytesIO
from flask import render_template, url_for, flash, redirect, abort, send_file, Blueprint
from flaskproject.files.forms import UploadFileForm, DownloadFileForm
from flaskproject.models import File
import secrets
from flask_login import current_user, login_required

files = Blueprint('files', __name__)

@files.route("/files", methods=['GET', 'POST'])
@login_required
def files_func():
    form = UploadFileForm()
    if form.validate_on_submit():
        uploaded_file = form.myfile.data
        file_bytes = BytesIO()
        uploaded_file.save(file_bytes)

        # Create a ZipFile object and add the uploaded file to it
        with zipfile.ZipFile(file_bytes, mode='w') as zip_file:
            zip_file.writestr(uploaded_file.filename, file_bytes.getvalue())
        
        
        key = Fernet.generate_key()
        fernet = Fernet(key)
        encrypted_bytes = fernet.encrypt(file_bytes.getvalue())

        # Save the encrypted zip file to a specific directory
        random_hex = secrets.token_hex(8)
        zip_path = os.path.join(app.root_path, 'static', 'files', f'{random_hex}.zip')
        with open(zip_path, mode='wb') as zip_file:
            zip_file.write(encrypted_bytes)
        
        file = File(your_name=form.nof.data, filename=zip_path, data=encrypted_bytes, owner_id=current_user.id, key=key)
        db.session.add(file)
        db.session.commit()
        key_string = base64.urlsafe_b64encode(key).decode()
        flash("Your file has been saved!", 'success')
        flash(f"Please note down the key: {key_string}", 'info')
        return redirect(url_for('users.account'))
    files_ = File.query.filter_by(owner_id=current_user.id)
    return render_template('files.html', files=files_, form=form, title="Your Files")


@files.route('/download/<int:user_id>/<int:file_id>', methods=['GET', 'POST'])
@login_required
def download_func(user_id, file_id):
    file = File.query.get(file_id)
    form = DownloadFileForm()
    if user_id != current_user.id or user_id != file.owner_id:
        return render_template('errors/403.html', title="Error 403")
    if form.validate_on_submit():
        key_string = form.file_key.data
        padding = len(key_string) % 4
        key_string += '=' * padding
        print(key_string)
        key = base64.b64decode(key_string)
        if key == file.key:
            fernet = Fernet(file.key)
            with open(file.filename, mode='rb') as encrypted_file:
                encrypted_bytes = encrypted_file.read()
            decrypted_bytes = fernet.decrypt(encrypted_bytes)
            
            new_name = f"{file.your_name}.zip"
            return send_file(BytesIO(decrypted_bytes), as_attachment=True, download_name=new_name)
        else:
            flash("Wrong Key Entered! Try Again!", "danger")
            return redirect(url_for('files.download_func', file_id=file.id, user_id=current_user.id))
    return render_template('download.html', form=form, title="Download")


@files.route('/delete/<int:file_id>', methods=['GET', 'POST'])
@login_required
def delete_file(file_id):
    file = File.query.get(file_id)
    if file.owner_id != current_user.id:
        abort(403)
    db.session.delete(file)
    db.session.commit()
    os.remove(f"{file.filename}")
    flash('Your file has been deleted!', 'success')
    return redirect(url_for('files.files_func'))