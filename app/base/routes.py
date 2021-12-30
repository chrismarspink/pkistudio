# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask import jsonify, render_template, redirect, request, url_for
from flask_login import (
    current_user,
    login_required,
    login_user,
    logout_user
)
from flask import flash

from app import db, login_manager
from app.base import blueprint
from app.base.forms import LoginForm, CreateAccountForm
from app.base.models import User

from app.base.util import verify_pass

import sys


########## Crypto Module
from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from os.path import exists, join

from datetime import datetime, timedelta
import subprocess

import base64

from OpenSSL._util import (ffi as _ffi, lib as _lib)

from werkzeug.utils           import secure_filename

from flask import send_file
import re, os, time, string, random

from io import StringIO
from flask import Response

import app
import logging

from config import config_dict, config

# WARNING: Don't run with debug turned on in production!
DEBUG = config('DEBUG', default=True, cast=bool)
# The configuration
get_config_mode = 'Debug' if DEBUG else 'Production'
app_config = config_dict[get_config_mode.capitalize()]



def do_openssl(pem, *args):
    """
    Run the command line openssl tool with the given arguments and write
    the given PEM to its stdin.  Not safe for quotes.
    """
    proc = subprocess.Popen([b"openssl"] + list(args), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    proc.stdin.write(pem)
    proc.stdin.close()
    output = proc.stdout.read()
    proc.stdout.close()
    proc.wait()
    return output
##########


def run_cmd(cmd, input=None):
    process = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate(input=input)

    if process.returncode:
        raise Exception(stderr, cmd)

    return stdout

@blueprint.route('/')
def route_default():
    return redirect(url_for('base_blueprint.login'))

## Login & Registration

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)
    if 'login' in request.form:
        
        # read form data
        username = request.form['username']
        password = request.form['password']

        # Locate user
        user = User.query.filter_by(username=username).first()
        
        # Check the password
        if user and verify_pass( password, user.password):

            login_user(user)
            return redirect(url_for('base_blueprint.route_default'))

        # Something (user or pass) is not ok
        return render_template( 'accounts/login.html', msg='Wrong user or password', form=login_form)

    if not current_user.is_authenticated:
        return render_template( 'accounts/login.html', form=login_form)
    return redirect(url_for('home_blueprint.index'))

@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    login_form = LoginForm(request.form)
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:

        username  = request.form['username']
        email     = request.form['email'   ]

        # Check usename exists
        user = User.query.filter_by(username=username).first()
        if user:
            return render_template( 'accounts/register.html', 
                                    msg='Username already registered',
                                    success=False,
                                    form=create_account_form)

        # Check email exists
        user = User.query.filter_by(email=email).first()
        if user:
            return render_template( 'accounts/register.html', 
                                    msg='Email already registered', 
                                    success=False,
                                    form=create_account_form)

        # else we can create the user
        user = User(**request.form)
        db.session.add(user)
        db.session.commit()
        
        
        return render_template( 'accounts/register.html', 
                                msg='User created please <a href="/login">login</a>', 
                                success=True,
                                form=create_account_form)

    else:
        return render_template( 'accounts/register.html', form=create_account_form)

    cert_pem="""-----BEGIN CERTIFICATE-----
MIICIjCCAYsCAgPoMA0GCSqGSIb3DQEBBQUAMFkxCzAJBgNVBAYTAktSMQ8wDQYD
VQQKDAZFUm1pbmQxFjAUBgNVBAsMDVdlYiBJc29sYXRpb24xITAfBgNVBAMMGGpr
a2ltdWktTWFjQm9va1Byby5sb2NhbDAeFw0yMTExMjYwODA2MjJaFw0zMTExMjQw
ODA2MjJaMFkxCzAJBgNVBAYTAktSMQ8wDQYDVQQKDAZFUm1pbmQxFjAUBgNVBAsM
DVdlYiBJc29sYXRpb24xITAfBgNVBAMMGGpra2ltdWktTWFjQm9va1Byby5sb2Nh
bDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAunuyXMXefQzCKxBSzYFOwNKC
2IMfxPLcX8dAXR092mQewsKEonHyc66deUC6Nrpn3CAyHSOVKv1mD/PL3UDxCF3b
ptfvDiVlXUklxS0+++KM7Fa8MA1/FdfreO5ArZezJw3y0WtUv5BrOAnhkPe/YF4Q
M2rNTj5xIVuacjkC6f8CAwEAATANBgkqhkiG9w0BAQUFAAOBgQB7xoYasTRMd2SP
uUAuOJsAy7+jFGKQMpprrZqBQTGjdVchCocxRfCJYknevTQeq+knTJhkhy9BH1F7
T3MO4n9jdTs+CzLqUn4PXN3EO6nI4MqZ3o9EHyW2kpd9UpGiZmv9nSH247INA0ss
IsS+BdFLnH/bvGz61jTF8cYLqC/YdA==
-----END CERTIFICATE-----
"""



@blueprint.route('/analyzer-asn1.html', methods=['GET', 'POST'])
def analyzer_asn1():

    cert_pem="""-----BEGIN CERTIFICATE-----
MIICIjCCAYsCAgPoMA0GCSqGSIb3DQEBBQUAMFkxCzAJBgNVBAYTAktSMQ8wDQYD
VQQKDAZFUm1pbmQxFjAUBgNVBAsMDVdlYiBJc29sYXRpb24xITAfBgNVBAMMGGpr
a2ltdWktTWFjQm9va1Byby5sb2NhbDAeFw0yMTExMjYwODA2MjJaFw0zMTExMjQw
ODA2MjJaMFkxCzAJBgNVBAYTAktSMQ8wDQYDVQQKDAZFUm1pbmQxFjAUBgNVBAsM
DVdlYiBJc29sYXRpb24xITAfBgNVBAMMGGpra2ltdWktTWFjQm9va1Byby5sb2Nh
bDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAunuyXMXefQzCKxBSzYFOwNKC
2IMfxPLcX8dAXR092mQewsKEonHyc66deUC6Nrpn3CAyHSOVKv1mD/PL3UDxCF3b
ptfvDiVlXUklxS0+++KM7Fa8MA1/FdfreO5ArZezJw3y0WtUv5BrOAnhkPe/YF4Q
M2rNTj5xIVuacjkC6f8CAwEAATANBgkqhkiG9w0BAQUFAAOBgQB7xoYasTRMd2SP
uUAuOJsAy7+jFGKQMpprrZqBQTGjdVchCocxRfCJYknevTQeq+knTJhkhy9BH1F7
T3MO4n9jdTs+CzLqUn4PXN3EO6nI4MqZ3o9EHyW2kpd9UpGiZmv9nSH247INA0ss
IsS+BdFLnH/bvGz61jTF8cYLqC/YdA==
-----END CERTIFICATE-----
"""

    #output = do_openssl(cert_pem, b"x509", b"-text", b"-noout")
    #cert_pem_parsed = output

    flash(' ASN.1 PASING ')      
    flash(' 2nd Flash Message... ')      
    result=cert_pem
    return render_template( '/analyzer-asn1.html', result=result)



@blueprint.route('/generator-privatekey.html', methods=['GET', 'POST'])
def generator_privatekey():

    algorithm_name="RSA"
    #alg="no algorithm selected..."
        
    if request.method == 'POST':

        name = request.form.get('alg')

        if name == "RSA":
            algorithm_name="ECDSA"
        if name == "ECCDSA":
            algorithm_name="RSA"

        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 1024)
        priv_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
        message=priv_key.decode('utf-8')
        alg=name
    
        return render_template( '/generator-privatekey.html', algorithm_name=algorithm_name, message=message)
    message="GET"
    return render_template( '/generator-privatekey.html', algorithm_name=algorithm_name, message=message)


@blueprint.route('/analyzer-pkcs12.html', methods=['GET', 'POST'])
def analyzer_pkcs12():

    userkey_pem = usercert_pem = cacert_pem = None
    inpass = outpass = None
    result = "GET"
    if request.method == 'POST':
        flash('POST')          
        #result = "this is pkcs12... & post"

        mode = request.form.get("inpass")

        f = request.files.get('pkcs12file', None)
        if not f:
            print("file not found", file=sys.stderr)
            return render_template( '/analyzer-pkcs12.html', result=result)
            
        infile = os.path.join(app_config.UPLOAD_DIR, f.filename)
        f.save(infile)
        inpass = request.form.get("inpass").encode('utf-8')
        p12 = crypto.load_pkcs12(open(infile, 'rb').read(), inpass)
        if not p12:
            flash("Cannot parse pkcs12 file.")
            return render_template( '/analyzer-pkcs12.html', result=result)

        usercert = p12.get_certificate()  # (signed) certificate object
        if usercert:
            usercert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, usercert)
            usercert_pem = usercert_pem.decode('utf-8')
     
        userkey = p12.get_privatekey()      # private key.
        if userkey:
            userkey_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, userkey)
            userkey_pem = userkey_pem.decode('utf-8')

        cacert = p12.get_ca_certificates() # ca chain.
        if cacert:
            cacert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cacert).decode('utf-8')

        #usercert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_certificate()).decode('utf-8')
        #userkey_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey()).decode('utf-8')
        #cacert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_ca_certificates()).decode('utf-8')
        
        return render_template( '/analyzer-pkcs12.html', userkey_pem=userkey_pem, usercert_pem=usercert_pem, cacert_pem = cacert_pem)    
    
    flash('GET') 
    return render_template( '/analyzer-pkcs12.html', result=result)


@blueprint.route('/analyzer-pem.html', methods=['GET', 'POST'])
def analyzer_pem():

    result = "GET"
    if request.method == 'POST':
        pem_type = request.form.get("pem_type")
        result = "pem type: " + pem_type
        return render_template( '/analyzer-pem.html', result=result)    
    
    return render_template( '/analyzer-pem.html', result=result)

@blueprint.route('/cipher-encrypt.html', methods=['GET', 'POST'])
def cipher_encrypt():

        
    if request.method == 'POST':

        flash("POST cipher: encrypt file")
        #f = request.files['plainfile']
        f = request.files.get('plainfile', None)
        enc_alg = request.form.get("enc_alg")

        if not f:
            flash("No file selected")    
        else:
            #filename = secure_filename(f.filename)
            
            infile = os.path.join(app_config.UPLOAD_DIR, f.filename)
            outfile = os.path.join(app_config.DOWNLOAD_DIR, f.filename + "." + "enc")
          
            f.save(infile)
            flash( "POST " + infile + ": 입력")
            
            cipher = request.form.get("cipher")
            if cipher == "enc":
                #cmd = 'openssl enc -aes-256-cbc  -in {in} -out {out} -pass pass:1234'.format(in=infile, out=outfile)
                outfile = os.path.join(app_config.DOWNLOAD_DIR, f.filename + "." + enc_alg)
                cmd = 'openssl enc -%s  -in \"%s\" -out \"%s\" -pass pass:1234' % (enc_alg, infile, outfile)
                print('form:cipher: enc', file=sys.stderr)
                print('command: ', cmd,  file=sys.stderr)
            elif cipher == "dec":
                outfile = os.path.join(app_config.DOWNLOAD_DIR, f.filename + "." + "org")
                ##extension is encryption alg name
                ##TODO : check algo list 
                ##TODO : send algo list to cipher-encrypt.html
                extension = os.path.splitext(f.filename)[1][1:]

                cmd = 'openssl enc -d  -in \"%s\" -out \"%s\" -pass pass:1234 -%s' % (infile, outfile, extension)
                print('form:cipher: dec', file=sys.stderr)
                print('command: ', cmd,  file=sys.stderr)
            else:
                flash("error: invalid command!")
                return render_template( '/cipher-encrypt.html')

            error = run_cmd(cmd)

            if os.path.isfile(outfile):
                return send_file(outfile, as_attachment=True)

        
        
        flash("POST cmd: " + cmd)
        return render_template( '/cipher-encrypt.html')

    flash("GET cipher: encrypt file")
    

    return render_template( '/cipher-encrypt.html')


@blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('base_blueprint.login'))

## Errors

@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('page-403.html'), 403

@blueprint.errorhandler(403)
def access_forbidden(error):
    return render_template('page-403.html'), 403

@blueprint.errorhandler(404)
def not_found_error(error):
    return render_template('page-404.html'), 404

@blueprint.errorhandler(500)
def internal_error(error):
    return render_template('page-500.html'), 500
