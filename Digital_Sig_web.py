# Simple implementation of Digital Signature using user's file as Message or Data.

from hashlib import sha256
import ecdsa
import os
import sys
from ecdsa import SigningKey, VerifyingKey

#  Imports for the ECDSA ends here.

#  Flask imports begins.
import os
from flask import Flask, render_template, request, redirect, flash, url_for
from werkzeug.utils import secure_filename

#  Flask imports ends. 

uploads = 'C:/users/signit/source/repos/Digital_Sig_web/uploads'  # The path to the directory to hold files uploaded.
ALLOWED_EXTENSIONS = set(['txt'])         #  File extensions to be accepted by the app.

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = uploads
app.secret_key = 'random string'    #  Verification technique.


def permited_fileExt(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
   return render_template('landingPage.html')


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
   with open('C:/users/signit/source/repos/Digital_Sig_web/uploads/runmatlib.txt', 'r') as Ufile:   
   #  This line of code just above needs to be dyname. Possibly pass the filename as variable from "POST"             
   #  'r' opens the file in read mode.
   #  Reading couldn't be done on .docx, .xlsx, .pdf files. So far, only .txt is successful.
      global hmsg, ds, pvk, pbk
      dataFile = Ufile.read()
      hashedFile = (sha256(dataFile.encode())).hexdigest()    #   Encode and Hash the file.
      hmsg = hashedFile
      #return hashedFile


#def keyPairGenerator():
    #   Very easy way to derive private and public keys from ecdsa beigns.
    #   Another way to generate the private and public keys. Private key gotten but Public. 

   private_key = SigningKey.generate(curve=ecdsa.SECP256k1)
   string_private_key = private_key.to_string()
   pvk = string_private_key

    #   Now derive the public key from the Private Key
   public_key = private_key.get_verifying_key()    # This verifying key is the public key.
   string_public_key = public_key.to_string()
   pbk = string_public_key
    #print('')
    #print("The Private key is: ", string_private_key)
   print('')
   print("The Public key is: ", string_public_key)

   #return string_private_key, string_public_key


    #   Generation of Private and Public keys ends. 

#def signFile(string_private_key, hashedFile):
    #   Signing of the Message/Data using Private key and Hashed Message begins. 

   sgkey = ecdsa.SigningKey.from_string(string_private_key, curve=ecdsa.SECP256k1)
   print('')
   print("The Signing Key is: ", sgkey)

   digitalSig = sgkey.sign(hashedFile.encode()) # This throws error if not encoded.
   ds = digitalSig
   print('')
   print("The Digital Signature is: ", digitalSig)

   #return ('Signing successfully completed.')   # This works but I want to implement the verification phase.
   return redirect(url_for('SigningSuccess'))   #  A redirect added. 
   #return digitalSig
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
   print('')
   print("The Verification Key is: ", verificationKey) 
   print('')
   print("The String Verification Key is: ", string_verificationkey)

   assert  verificationKey.verify(getDS(), gethmsg().encode()), "Sorry! Verification failed."
   #  The code just above needs to be edited to make room for failed verification.
   print('')
   print("Congratulations! Verification was successful. Thank you.")

   return redirect(url_for('verifySuccess'))   #  A redirect added.
   #   Verification phase ends here.


@app.route('/vSuccess/')
   #  Consultations time oooo. Tying something.
def verifySuccess():
   return render_template('successfulV.html')


#  Improvements to be done.
#  At the verification page, user should enter public key acquired from sender, DS and Hash of File.
#  Consider use of Database for storage and retrieval of needed data.  


if __name__ == '__main__':
   app.debug = True
   app.run()
   app.run(debug=True)
