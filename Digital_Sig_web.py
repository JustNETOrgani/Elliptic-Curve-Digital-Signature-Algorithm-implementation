# An implementation of Digital Signature using user's file as Message or Data.

from hashlib import sha256
import ecdsa
import os
import sys
from ecdsa import SigningKey, VerifyingKey
import sqlite3
import appDb


#  Imports for the ECDSA ends here.

#  Flask imports begins.
import os
from flask import Flask, render_template, request, redirect, flash, url_for
from werkzeug.utils import secure_filename
import appDb
#  Flask imports ends. 

uploads = 'C:/users/signit/source/repos/Digital_Sig_web/uploads'  # The path to the directory to hold files uploaded.
ALLOWED_EXTENSIONS = set(['txt'])         #  File extensions to be accepted by the app.

app = Flask(__name__)


app.config['UPLOAD_FOLDER'] = uploads
app.secret_key = os.urandom(24)   #  To keep session secured.


def permited_fileExt(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
   return render_template('register.html')


#@app.route('/')
#def index():
#   return render_template('landingPage.html')

@app.route('/sendToLogin')
def sendUserToLoginPage():
   return render_template('loginPage.html')

@app.route('/sendToRegister')
def sendUserToRegistPage():
   return render_template('register.html')


@app.route('/uploader', methods = ['GET', 'POST'])
def upload_file():
   error = None

   if request.method == 'POST':
        # Verify that the post request has the file part with it.
         if 'file' not in request.files:
            error = ('Sorry! File part missing.')
            return redirect(request.url)
         file = request.files['file']
         # When a user does not select file, the browser would also submit an empty part without filename.
         if file.filename == '':
            error = ('No file selected.')
            return redirect(request.url)
         if file and not permited_fileExt(file.filename):
            error = ('File type not allowed.')
         if file and permited_fileExt(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('Thank you. File uploaded successfully.')
            return redirect(url_for('uploadSuccess'))   #  A redirect added. 
            
   
   return render_template('landingPage.html', error=error)


@app.route('/uploadSuccess', methods=['GET', 'POST'])
def uploadSuccess():
   return render_template('uploadSuccess.html')


#  ECDSA implementation for Signing the file begins here.

#  Globals begin.
hmsg=''
ds =''
pvk = ''
pbk = ''
#  Globals end.

@app.route('/fileSigning/')
   #  Consultations time oooo. Tying something.
def SignUserFile():
    #   User's file or Data acceptance begins.
   with open('C:/users/signit/source/repos/Digital_Sig_web/uploads/justTesting.txt', 'r') as Ufile:   
   #  This line of code just above needs to be dynamic. Possibly pass the filename as variable from "POST" or DB.             
   #  'r' opens the file in read mode.
   #  Reading couldn't be done on .docx, .xlsx, .pdf files. So far, only .txt is successful. 
      global hmsg, ds, pvk, pbk
      dataFile = Ufile.read()
      hashedFile = (sha256(dataFile.encode())).hexdigest()    #   Encode and Hash the file.
      hmsg = hashedFile
     


#def keyPairGenerator():
    #   Very easy way to derive private and public keys from ecdsa beigns.

   private_key = SigningKey.generate(curve=ecdsa.SECP256k1)
   string_private_key = private_key.to_string()
   pvk = string_private_key

    #   Now derive the public key from the Private Key
   public_key = private_key.get_verifying_key()    # This verifying key is the public key.
   string_public_key = public_key.to_string()
   pbk = string_public_key
    #print('')
    #print("The Private key is: ", string_private_key)
   

   


    #   Generation of Private and Public keys ends. 

#def signFile(string_private_key, hashedFile):
    #   Signing of the Message/Data using Private key and Hashed Message begins. 

   sgkey = ecdsa.SigningKey.from_string(string_private_key, curve=ecdsa.SECP256k1)
   

   digitalSig = sgkey.sign(hashedFile.encode()) # This throws error if not encoded.
   ds = digitalSig
   
   return redirect(url_for('SigningSuccess'))   #  A redirect added. 
  
    #   Signing of the Message/Data using Private key and Hashed Message ends here.

#  Creating getters.
def gethmsg():
   return hmsg

def getDS():
   return ds

def getpvk():
   return pvk

def getpbk():
   return pbk

#  Getters end.

@app.route('/signSuccess/')
   #  Consultations time oooo. Tying something.
def SigningSuccess():
   return render_template('SigningSuccess.html')
    

#
# I am thinking of signing on a page then verifying at a differnt page.
# 
@app.route('/fileVerifier')
def verifyFile():
    #   Now the verification phase begins.

    #   Hash of the data/message is already done and stored in hashedMsg so only decryption to be done. 

   verificationKey = ecdsa.VerifyingKey.from_string(getpbk(), curve=ecdsa.SECP256k1)

    # To convert verificationkey to string to see correctly. Next line of code can be activated and printed if needed.

   string_verificationkey = verificationKey.to_string()
   

   assert  verificationKey.verify(getDS(), gethmsg().encode()), "Sorry! Verification failed."
   #  The code just above needs to be edited to make room for failed verification.
  
   return redirect(url_for('verifySuccess'))   #  A redirect added.
   #   Verification phase ends here.


@app.route('/vSuccess/')
   #  Consultations time oooo. Tying something.
def verifySuccess():
   return render_template('successfulV.html')


#  Improvements to be done.
#  At the verification page, user should enter public key acquired from sender, DS and Hash of File.
#  Consider use of Database for storage and retrieval of needed data.  

# DB issues for testing purposes.
DBNAME = 'DigiSign.db'
conn = sqlite3.connect(DBNAME)
conn = sqlite3.connect(DBNAME, check_same_thread=False)


#   A method to handle user registration.

@app.route('/registerHandler', methods = ['GET', 'POST']) 
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = conn
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif db.execute(
            'SELECT id FROM users WHERE username = ?', (username,)
        ).fetchone() is not None:
            error = 'User {} is already registered.'.format(username)

        if error is None:
            db.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (username, password)
            )
            db.commit()
            return redirect(url_for('sendUserToLoginPage'))

        flash(error)

    return render_template('register.html')



#   Method to handle user login.
@app.route('/loginAccess', methods = ['GET', 'POST'])      
def login():
      if request.method == 'POST':
         username = request.form['username']
         password = request.form['password']
        #hpassword = sha256(password.encode())
         db = conn
         error = None
         user = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
         ).fetchone()

         if user is None:
            error = 'Incorrect username.'
         elif ((user[2]) != password):
            error = 'Incorrect password.'

         flash(error)

      return render_template('landingPage.html')


#   Method to handle logout.
@app.route('/logout')        #   Rewrite this code.
def logout():
    return redirect(url_for('sendUserToLoginPage'))

#conn.close()



if __name__ == '__main__':
   app.debug = True
   app.run()
   app.run(debug=True)
