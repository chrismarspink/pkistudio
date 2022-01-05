# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""
from flask import Flask
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
import logging.handlers

from config import config_dict, config

# WARNING: Don't run with debug turned on in production!
DEBUG = config('DEBUG', default=True, cast=bool)
# The configuration
get_config_mode = 'Debug' if DEBUG else 'Production'
app_config = config_dict[get_config_mode.capitalize()]

#logger = logging.getLogger().addHandler(logging.StreamHandler(sys.stderr))
#consoleHandler = logging.StreamHandler(sys.stderr)
#logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")

#logger = logging.getLogger()
#logger.addHandler(consoleHandler)
aes_alg_list = ["aes128", "aes192", "aes256", 
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", 
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", 
    "aes-128-cfb1", "aes-192-cfb1", "aes-256-cfb1",
    "aes-128-cfb8", "aes-192-cfb8", "aes-256-cfb8",
    "aes-128-ofb", "aes-192-ofb", "aes-256-ofb",
    "aes-128-ecb", "aes-192-ecb", "aes-256-ecb",
    "aes-128-cbc", "aes-192-cbc", "aes-256-cbc"]

rsabits = [1024, 2048, 4096, 8192, 16384]											

app = Flask(__name__)

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


@blueprint.route('/analyzer-asn1.html', methods=['GET', 'POST'])
def analyzer_asn1():
    app.logger.info("analyzer_asn1...")
    msg=None
    curves=[]

    if request.method == 'POST':
        action = request.form.get('action')
        ##app.logger.info("action --> " + action)
        
        if action == "ecc_curves":
            for curve in crypto.get_elliptic_curves():
                app.logger.info(curve.name)
                curves.append(curve.name)

        
        return render_template( '/analyzer-asn1.html', ecc_curves=curves)    

    
    return render_template( '/analyzer-asn1.html', result=msg)



@blueprint.route('/generator-privatekey.html', methods=['GET', 'POST'])
def generator_privatekey():

    algorithm_name="RSA"
    #alg="no algorithm selected..."
    curves=[]
    

    for curve in crypto.get_elliptic_curves():
        app.logger.info(curve.name)
        curves.append(curve.name)

        
    if request.method == 'POST':

        name = request.form.get('alg')

        if name == "RSA":
            algorithm_name="ECDSA"
        if name == "ECCDSA":
            algorithm_name="RSA"

        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 1024)
        priv_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
        prikey_pem=priv_key.decode('utf-8')

        #pubkey = key.get_pubkey()
        pubkey_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, key)
        pubkey_pem = pubkey_pem.decode('utf-8')
        alg=name

        ## expect 'enc'
        encopt_checked = request.form.get("encrypt_option")
        if encopt_checked:
            app.logger.info("generate_privatekey: encopt_checked: " + encopt_checked)

        else:
            app.logger.info("generate_privatekey: encopt_checked: disabled(None)")

    
        return render_template( '/generator-privatekey.html', prikey_pem=prikey_pem, pubkey_pem=pubkey_pem, ecc_curves=curves, rsa_param=rsabits, aes_alg_list=aes_alg_list)

    message="GET"
    return render_template( '/generator-privatekey.html', ecc_curves=curves, rsa_param=rsabits, aes_alg_list=aes_alg_list)


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

PEM_TYPE_LIST = [
    { 'type': 'rsapubkey',  'tag': 'RSA PUBLIC KEY', 'desc': 'RSA Public Key' },
    { 'type': 'encrypted_rsapribkey', 
                            'tag': 'RSA PRIVATE KEY', 'desc': 'Encrypted RSA Private Key', 'proc-type':'Proc-Type: 4,ENCRYPTED'},
    { 'type': 'rsapribkey', 'tag': 'RSA PRIVATE KEY', 'desc': 'RSA Private Key'},
    { 'type': 'crl',        'tag': 'X509 CRL', 'desc': 'X.509 CRL' },
    { 'type': 'certificate','tag': 'CERTIFICATE', 'desc': 'X.509 Certificate' },

    { 'type': 'csr',        'tag': 'CERTIFICATE REQUEST', 'desc': 'Certificate Request' },
    { 'type': 'newcsr',     'tag': 'NEW CERTIFICATE REQUEST', 'desc': 'New Certificate Request' },

    { 'type': 'pkcs7',      'tag': 'PKCS7', 'desc': 'PKCS7' },
    { 'type': 'dsaprikey',  'tag': 'PRIVATE KEY', 'desc': 'DSA Private Key' },
    { 'type': 'dsaprikey',  'tag': 'DSA PRIVATE KEY', 'desc': 'DSA Private Key' },

    { 'type': 'ecprikey',   'tag': 'EC PRIVATE KEY', 'desc': 'EC PRIVATE KEY' },
    { 'type': 'pkcs7',      'tag': 'PKCS7', 'desc': 'PKCS7' }
]


def get_pem_type(pemstr):
    
    app.logger.info(dict['type'] + ", " + dict['tag'] + ", " + dict['desc'])
    if pemstr and pemstr.startswith("-----BEGIN"):
        for dict in PEM_TYPE_LIST:      
            header = footer = proctype = None
            header = "-----BEGIN " + dict['tag'] + "-----"
            footer = "-----END " + dict['tag'] + "-----"
            proctype = dict['proc-type']
            line2 = pemstr.splitlines()[2]

            app.logger.info(dict['type'] + ", " + dict['tag'] + ", " + dict['desc'])

            if pemstr.startswith(header)  and footer in pemstr:
                if proctype and line2 == dict['proc-type']:
                    return dict['type']
                return dict['type']
        return None
    else:
        return None

@blueprint.route('/analyzer-pem.html', methods=['GET', 'POST'])
def analyzer_pem():

    app.logger.info('>>>>> Analyzer_pem START...')
    result = "GET"
    intext = None
    #infile = None
    intext_pem = None
    errmsg = None
    
    for dict in PEM_TYPE_LIST:
        app.logger.info(dict['type'] + ", " + dict['tag'] + ", " + dict['desc'])

    
    
    if request.method == 'POST':

        dict = request.form
        for key in dict:
            app.logger.info('form key '+ dict[key])

        intype = request.form.get("intype")
        inputtext = request.form.get("inputtext", None)
        inputfile = request.form.get("inputfile", None)
        action = request.form.get("action") ##analyze
        
        if action: app.logger.info("ation ==>  " + action)
        
        app.logger.info("inputtext ==>  " + inputtext)

        if action == "analyze":
            app.logger.info("intype=" + intype)
   
        if inputtext and inputtext.startswith("-----BEGIN"):
            intext_pem = inputtext
            app.logger.info("intext ==> " + intext_pem)

#		RSA Public Key
           
        if inputtext.startswith("-----BEGIN"):
            cert_pem = do_openssl(inputtext, b"x509", b"-text", b"-noout")
            result = cert_pem.decode('utf-8')
            return render_template( '/analyzer-pem.html', result=result) 
        elif inputfile:
            flash("inputfile...")
        else:
            flash("error: no input data")
            return render_template( '/analyzer-pem.html', result=None, errmsg=errmsg)    

        #input1 = intext_pem.encode()
        #cert_pem = do_openssl(input1, b"x509", b"-text", b"-noout")
        result = cert_pem.decode('utf-8')
        
        return render_template( '/analyzer-pem.html', result=result)    

    ##GET    
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
