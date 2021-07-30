from flask import render_template
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from aes128ecb import app
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256


class AESForm(FlaskForm):
    encrypt = StringField('Encryption IP')
    key_enc = StringField('Key Encrypt')
    submit_enc = SubmitField('Submit')

    decrypt = StringField('Decryption IP')
    key_dec = StringField('Key Decrypt')
    submit_dec = SubmitField('Submit')


def hash_pad(ip, key):
    hashed_key = SHA256.new(key.encode()).digest()
    print(hashed_key)
    extra = (16 - len(ip)) % 16
    pad = ip + extra * "."
    return hashed_key, pad


def encrypt_text(ip, key):
    enc_req = hash_pad(ip, key)
    enc_cipher = AES.new(enc_req[0], AES.MODE_ECB)
    encrypted = enc_cipher.encrypt(enc_req[1].encode("utf-8"))
    # print(encrypted)
    return encrypted


def decrypt_text(ip, key):
    dec_req = hash_pad(ip, key)
    de_cipher = AES.new(dec_req[0], AES.MODE_ECB)
    decrypted = de_cipher.decrypt(dec_req[1].encode("utf-8"))
    # print(decrypted)
    return decrypted


@app.route('/', methods=['GET', 'POST'])
def aes_ecb():
    form = AESForm()
    user_ip_enc = form.encrypt.data
    key_enc = form.key_enc.data
    submit_enc = form.submit_enc.data

    user_ip_dec = form.decrypt.data
    key_dec = form.key_dec.data
    submit_dec = form.submit_dec.data

    if submit_enc:
        encrypted = encrypt_text(user_ip_enc, key_enc)
        return render_template('aes.html', title='AES 128 ECB', form=form, enc_result=encrypted)

    if submit_dec:
        decrypted = decrypt_text(user_ip_dec, key_dec)
        return render_template('aes.html', title='AES 128 ECB', form=form, dec_result=decrypted)

    return render_template('aes.html', title='AES 128 ECB', form=form)