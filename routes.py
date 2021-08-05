from flask import render_template
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from aes128ecb import app
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256


//flask form to take user input
class aesForm(FlaskForm):
    encrypt = StringField('Encryption IP')
    keyEncrypt = StringField('Key Encrypt')
    submitEncrypt = SubmitField('Submit')

    decrypt = StringField('Decryption IP')
    keyDecrypt = StringField('Key Decrypt')
    submitDecrypt = SubmitField('Submit')

    
//function to hash the key and add padding to input text to make its length in multiple of 16
def hashPad(ip, key):
    hashedKey = SHA256.new(key.encode()).digest()   //hashing the key
    addExtra = (16 - len(ip)) % 16
    pad = ip + addExtra * "."                       //adding . at last on input to make its length in multiple of 16
    return hashedKey, pad


def encryptText(ip, key):
    encryptRequired = hashPad(ip, key)
    encryptedCipher = AES.new(encryptRequired[0], AES.MODE_ECB)
    encrypted = encryptedCipher.encrypt(encryptRequired[1].encode("utf-8")) //encrypting the padded input with the key
    # print(encrypted)
    return encrypted


def decryptText(ip, key):
    decryptRequired = hashPad(ip, key)
    decryptedCipher = AES.new(decryptRequired[0], AES.MODE_ECB)
    decrypted = decryptedCipher.decrypt(decryptRequired[1].encode("utf-8")) //decrypting the padded input with the key
    # print(decrypted)
    return decrypted


@app.route('/', methods=['GET', 'POST'])
def aes_ecb():
    form = aesForm()
    userEncryptIp = form.encrypt.data
    keyEncryptIp = form.keyEncrypt.data
    submitEncryptIp = form.submitEncrypt.data

    userDecryptIp = form.decrypt.data
    keyDecryptIp = form.keyDecrypt.data
    submitDecryptIp = form.submitDecrypt.data

    if submitEncryptIp:
        encrypted = encryptText(userEncryptIp, keyEncryptIp)
        return render_template('aes.html', title='AES 128 ECB', form=form, enc_result=encrypted)

    if submitDecryptIp:
        decrypted = decryptText(userDecryptIp, submitDecryptIp)
        return render_template('aes.html', title='AES 128 ECB', form=form, dec_result=decrypted)

    return render_template('aes.html', title='AES 128 ECB', form=form)
