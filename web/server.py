from flask import Flask, render_template, request, send_file
import os
import sys


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.file_crypto import FileCrypto

app = Flask(__name__)
file_crypto = FileCrypto()
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        password = request.form['password']
        action = request.form['action']
        
        if file.filename == '':
            return 'No selected file'
            
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        
        try:
            if action == 'encrypt':
                out_path = file_crypto.encrypt_file(filepath, password)
            else:
                out_path = file_crypto.decrypt_file(filepath, password)
            
            return send_file(out_path, as_attachment=True)
        except Exception as e:
            return f"Error: {str(e)}"
            
    return '''
    <!doctype html>
    <title>Sentinel Web</title>
    <style>body{font-family:sans-serif; max-width:600px; margin:50px auto; background:#222; color:#fff; padding:20px;} input, select {width:100%; padding:10px; margin:10px 0;}</style>
    <h1>Sentinel Web Crypt</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=password name=password placeholder="Password">
      <select name=action>
        <option value="encrypt">Encrypt</option>
        <option value="decrypt">Decrypt</option>
      </select>
      <input type=submit value=Process style="background:green; color:white; border:none; cursor:pointer;">
    </form>
    '''

if __name__ == '__main__':
    app.run(debug=True, port=5000)