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
import mimetypes
import tempfile


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

##pyjks 모듈: JKS(java key store) 파일 파싱
import jks , textwrap

import app
import logging
import logging.handlers

from config import config_dict, config


from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


##########
## DOCKER 
##########
import docker

Version="0.1"
Version_Date="2022-01-10"
App_Name="PKI.STUDIO"

# WARNING: Don't run with debug turned on in production!
DEBUG = config('DEBUG', default=True, cast=bool)
# The configuration
get_config_mode = 'Debug' if DEBUG else 'Production'
app_config = config_dict[get_config_mode.capitalize()]

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


@blueprint.route('/docker-main.html', methods=['GET', 'POST'])
def docker_main():

    client = docker.from_env()
    result = "GET"
    containerList = []

    #for container in client.containers.list():
    for container in client.containers.list():
        app.logger.info("ID: " + container.id)
        containerList.append(container.id)
        

    images =  client.images.list()
    for image in images:
        app.logger.info("ImageID: " + container.id)

    configs =  client.configs.list()
    for config in configs:
        app.logger.info("Configs: " + config.id)



    if request.method == 'POST':
        flash("POST Docker main...")
        return render_template( '/docker-main.html', containerList = client.containers.list())    
    
    flash('GET Docker-Main') 
    return render_template( '/docker-main.html', containerList=client.containers.list(), images=images, configs=configs)


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



def generate_pem_format_string(der_bytes, types):
    header = "-----BEGIN %s-----\r\n" % types
    body = "\r\n".join(textwrap.wrap(base64.b64encode(der_bytes).decode('ascii'), 64))
    footer = "\r\n-----END %s-----\r\n" % types
    return header + body + footer

@blueprint.route('/analyzer-jks.html', methods=['GET', 'POST'])
def analyzer_jks():

    userkey_pem = usercert_pem = cacert_pem = ""
    inpass = None
    errtype = None
    result = "GET"

    if request.method == 'POST':
        flash('POST')          
        
        inpass = request.form.get("inpass", None)
        if not inpass:
            errtype = "inpass"
            return render_template( '/analyzer-jks.html', errtype=errtype)

        app.logger.info("inpass: %s" % inpass)
        f = request.files.get('inputfile', None)
        if not f:
            print("file not found", file=sys.stderr)
            return render_template( '/analyzer-jks.html', result=result)
            
        infile = os.path.join(app_config.UPLOAD_DIR, f.filename)
        f.save(infile)
        
        app.logger.info("infile: %s" % infile)
        
        ks = jks.KeyStore.load(infile, inpass)
        

        for alias, pk in ks.private_keys.items():
            app.logger.info("Private key: %s" % pk.alias)
            if pk.algorithm_oid == jks.util.RSA_ENCRYPTION_OID:
                userkey_pem = generate_pem_format_string(pk.pkey, "RSA PRIVATE KEY")
            else:
                userkey_pem = generate_pem_format_string(pk.pkey_pkcs8, "PRIVATE KEY")

            for c in pk.cert_chain:
                #app.logger.info("Certicicate Chain: %s" % c.alias)
                usercert_pem += generate_pem_format_string(c[1], "CERTIFICATE")
            

        for alias, c in ks.certs.items():
            app.logger.info("Certificate: %s" % c.alias)
            usercert_pem = generate_pem_format_string(c.cert, "CERTIFICATE")
            
        
        for alias, sk in ks.secret_keys.items():
            app.logger.info("Secret key: %s" % sk.alias)
            app.logger.info("  Algorithm: %s" % sk.algorithm)
            app.logger.info("  Key size: %d bits" % sk.key_size)
            app.logger.info("  Key: %s" % "".join("{:02x}".format(b) for b in bytearray(sk.key)))
        
        
        return render_template( '/analyzer-jks.html', userkey_pem=userkey_pem, usercert_pem=usercert_pem, cacert_pem = cacert_pem)    
    
    flash('GET') 
    return render_template( '/analyzer-jks.html', result=result)    

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


def get_pem_typeXXX(pemstr):
    
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

def read_pem_file(filename):
    with open(filename, "r") as f:
        pem_str = f.read()
        if pem_str.startswith("-----BEGIN"):
            return pem_str
    return None

def get_pem_type(inputtext):
    pemtype = None

    if   inputtext.startswith("-----BEGIN CERTIFICATE-----"): pemtype = "crt"
    elif inputtext.startswith("-----BEGIN CERTIFICATE REQUEST-----"): pemtype = "csr"
    elif inputtext.startswith("-----BEGIN PUBLIC KEY-----"): pemtype = "rsapubkey"
    elif inputtext.startswith("-----BEGIN RSA PRIVATE KEY-----"): pemtype = "rsaprikey"
    elif inputtext.startswith("-----BEGIN RSA ENCRYPTED PRIVATE KEY-----"): pemtype = "enc_rsaprikey"
    elif inputtext.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----"): pemtype = "enc_rsaprikey"
    elif inputtext.startswith("-----BEGIN PKCS7-----"): pemtype = "pkcs7"
    elif inputtext.startswith("-----BEGIN X509 CRL-----"): pemtype = "crl"
    elif inputtext.startswith("-----BEGIN CMS-----"): pemtype = "cms"
    else: pemtype = None 

    return pemtype
    

def is_binary(filename):
    cmd = "file -b " + filename.decode('utf-8')
    app.logger.info("is_binary():cmd: " + cmd)
    f = os.popen(cmd, 'r')
    if f:
        rs = f.read() 
        app.logger.info("is_binary():read(): " + rs)
        if rs.startswith("DER Encoded Certificate request"):
            app.logger.info('is binary csr file')
            return True
        if rs.startswith("DER Encoded Key Pair"):
            app.logger.info('is binary private key file')
            return True

        if rs.startswith("DER Encoded"):
            app.logger.info('is binary/DER-Encoded file')
            return True

        if rs.endswith("data") or rs.startswith("data"):
            app.logger.info('is binary data file')
            return True

        ####
        #### if unknown and not ascii text and not binary ==> crl.der
        ####
    return False



def get_pki_file_type(filename):

    #cmd = "file -b " + filename.decode('utf-8')
    cmd = "file -b " + filename
    f = os.popen(cmd, 'r')
    if f:
        rs = f.read() 

        app.logger.info("get_pki_file_type: " + rs)
        
        if rs.endswith("PEM certificate"):
            return "crt"
        elif rs.endswith("PEM certificate request"):
            return "csr"
        elif rs.endswith("ASCII text") and filename.endswith(".crl"):
            return "crl"
        elif rs.endswith("ASCII text") :
            return "text"
    ##BINARY
        elif rs.startswith("DER Encoded Certificate request"):
            return "csr"
        elif rs.startswith("Certificate"):
            return "crt"
        elif rs.startswith("Certificate"):
            return "crt"
        elif rs.startswith("DER Encoded Key Pair"):
            return "rsaprikey"
        elif rs.startswith("data"):
            return "data"

    
    return False


@blueprint.route('/analyzer-pem.html', methods=['GET', 'POST'])
def analyzer_pem():

    app.logger.info('>>>>> Analyzer_pem START...')
    result = None
    inputtext = intext = intext_pem = None
    errmsg = errtype = None
    dataType = True
    inType = "text" ##file
    fileMode = "text" ##bin
    informArg = "PEM"
    asn1mode = False
    
    ###DEBUG
    ##for dict in PEM_TYPE_LIST: app.logger.info(dict['type'] + ", " + dict['tag'] + ", " + dict['desc'])
    
    if request.method == 'POST':

        dict = request.form
        for key in dict: app.logger.info('form key '+ dict[key])

        intype = request.form.get("intype")
        inputtext = request.form.get("inputtext", None)
        inputfile = request.form.get("inputfile", None)
        action = request.form.get("action") ##analyze

        if action =="clear":
            return render_template( '/analyzer-pem.html', result=None, errmsg=None, errtype=None, inputtext="")    

        asn1mode_checked = request.form.get("asn1mode")
        if asn1mode_checked:
            asn1mode = True
            app.logger.info("asn1 mode: True")
        else:
            app.logger.info("asn1 mode: False")
        
        f = request.files.get('inputfile', None)
                
        if action: app.logger.info("ation ==>  " + action)
        app.logger.info("inputtext ==>  " + inputtext)

        if action == "analyze": app.logger.info("analyze button pressed...")

   
        if inputtext and inputtext.startswith("-----BEGIN"):
            inType = "text"
            intext_pem = inputtext
            app.logger.info("** intext ==> " + intext_pem)

            dataType = get_pem_type(inputtext)
            app.logger.info("input format(PEM TEXT): " + dataType)

        elif f:
            infile = os.path.join(app_config.UPLOAD_DIR, f.filename)
            f.save(infile)
            inType = "file"

            formInFormat = request.form.get("informat")
            fileMode = "text"

            app.logger.info("input format(FILE): " + infile)

            if True == is_binary(infile.encode('utf-8')):
                fileMode = "binary"
                inForm = "DER"
            else:
                fileMode = "text"
                inForm = "PEM" ## SMIME??

            app.logger.info( "Filename: " + infile)
            app.logger.info( "File Parsing: " + formInFormat + ", inType: " + inType + ", fileMode: " + fileMode + ", inForm: " + inForm)

            if fileMode == "text":
                inputtext = read_pem_file(infile)
                
                dataType = get_pem_type(inputtext)
                if not dataType:
                    dataType = formInFormat

                inType = "text" ##로 변경
                app.logger.info( "TEXT FILE MODE: format: " + dataType + ", fmode: " + fileMode + ", inType(changed): " + inType )
            
            elif fileMode =="binary":
                if "data" == get_pki_file_type(infile):
                    dataType = formInFormat
                else:
                    #바이너리, crt. csr 아닌 경우는 사용자 입력에 의존한다. 
                    dataType = formInFormat
                app.logger.info( "BINARY FILE MODE" + ", dataType: " + dataType + ", fileMode: " + fileMode)
                app.logger.info( "BINARY FILE MODE" + ", inType: " + inType)

        else: 
            errtype = "error"
            errmsg = "error: No Input Data(Text/File)"
            flash(errmsg)
            return render_template( '/analyzer-pem.html', result=None, errmsg=errmsg, errtype=errtype)    

        
        
#Certificate
        try:
            #if textmode and inputtext.startswith("-----BEGIN CERTIFICATE-----"):
            if asn1mode == True:
                if inType == "file":
                    cmd = "openssl asn1parse -inform %s -in %s " % (inForm, infile)
                elif inType == "text":
                    pemstr = do_openssl(inputtext.encode('utf-8'), b"asn1parse", b"-inform", b"PEM")

                result = pemstr.decode('utf-8')
                app.logger.info("Result sring: " + result)

                if result.startswith("Error") or result.startswith("error"):
                    errtype="error"
                    errmsg="invalid asn.1 message"
                    return render_template( '/analyzer-pem.html', result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    
                
                return render_template( '/analyzer-pem.html', result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    

            elif dataType == "crt":
                
                if inType == "file":
                    cmd = "openssl x509 -text -noout -inform DER -in %s " % infile
                    app.logger.info("binary command : " + cmd)
                    pemstr = run_cmd(cmd)
                elif inType == "text":
                    pemstr = do_openssl(inputtext.encode('utf-8'), b"x509", b"-text", b"-noout", b"-inform", b"PEM")
                
                result = pemstr.decode('utf-8')
                app.logger.info("Result sring: " + result)
                
                if not result.startswith("Certificate:"):
                    errtype, errmsg = "error", "error: Invalid X509 Certificate"
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-pem.html', result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    

            #elif textmode and inputtext.startswith("-----BEGIN CERTIFICATE REQUEST-----"):
            elif dataType == "csr":
                if inType == "file":
                    cmd = "openssl req -text -noout -inform DER -in " + infile
                    app.cmd = "openssl req -text -noout -inform DER -in " + infile
                    app.logger.info("binary command for Certificate Signing Request: " + cmd)
                    pemstr = run_cmd(cmd)
                    
                else:
                    pemstr = do_openssl(inputtext.encode('utf-8'), b"req", b"-text", b"-noout", b"-inform", b"PEM")
                result = pemstr.decode('utf-8')
                
                if not result.startswith("Certificate Request:"):
                    errmsg = "error: invalid CSR"
                    app.logger.info(errmsg)
                
            ##openssl rsa -in test.pub -text -noout -pubin
            #elif inputtext.startswith("-----BEGIN PUBLIC KEY-----"):
            elif dataType == "rsapubkey":
                if inType == "file":
                    cmd = "openssl ras -pubin -noout -text -inform DER -in " + infile
                    app.logger.info("binary command for RSA PUBKEY : " + cmd)
                    pemstr = run_cmd(cmd)
                else:
                    pemstr = do_openssl(inputtext.encode('utf-8'), b"rsa", b"-pubin", b"-text", b"-noout", b"-inform", b"PEM")
                result = pemstr.decode('utf-8')
                
                if not result.startswith("RSA Public-Key:"):
                    errtype = "error"
                    errmsg = "error: invalid RSA public key" 
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-pem.html', result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    

            #elif inputtext.startswith("-----BEGIN RSA PRIVATE KEY-----"):
            elif dataType == "rsaprikey":

                if inType == "file":
                    cmd = "openssl rsa -text -noout -inform DER -in " + infile
                    app.logger.info("binary command for RSA Private Key : " + cmd)
                    pemstr = run_cmd(cmd)
                else:
                    pemstr = do_openssl(inputtext.encode('utf-8'), b"rsa", b"-text", b"-noout", b"-inform", b"PEM")
                result = pemstr.decode('utf-8')
                
                if not result.startswith("RSA Private-Key:"):
                    errtype = "error"
                    errmsg = "error: invalid RSA Private Key" 
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-pem.html', result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    

            #elif inputtext.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----"):
            elif dataType == "enc_rsaprikey":
                inpass = request.form.get("inpass", None)
                if not inpass:
                    errtype = "inpass"
                    errmsg = "error: no input password"
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-pem.html', result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    
                else:
                    passin_arg = "pass:" + inpass

                if inType == "file":
                    cmd = "openssl rsa -text -noout -inform DER -in " + infile + "  -passin " + passin_arg
                    app.logger.info("binary command for Encrypted RSA Private Key : " + cmd)
                    pemstr = run_cmd(cmd)
                else: 
                    pemstr = do_openssl(inputtext.encode('utf-8'), b"rsa", b"-text", b"-noout", b"-inform", b"PEM", b"-passin", passin_arg)

                result = pemstr.decode('utf-8')
                
                if not result.startswith("RSA Private-Key:"):
                    errtype = "error"
                    errmsg = "error: invalid encrypted RSA Private Key"
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-pem.html', result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    
            
            ##ermind@rbrowser:/tmp$ openssl pkcs7 -in test.p7b -text  -print -noout
            #elif inputtext.startswith("-----BEGIN PKCS7-----"):
            elif dataType == "pkcs7":
                if inType == "file":
                    cmd = "openssl pkcs7 -text -noout -print -inform DER -in " + infile
                    app.logger.info("binary file parsing, type=PKCS7 : " + cmd)
                    pemstr = run_cmd(cmd)
                else: 
                    pemstr = do_openssl(inputtext.encode('utf-8'), b"pkcs7", b"-text", b"-noout", b"-inform", b"PEM", b"-print")
                result = pemstr.decode('utf-8')
                
                if not result.startswith("PKCS7:"):
                    errtype = "error"
                    errmsg = "error: invalid pkcs7 message"
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-pem.html', result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    
            
            ##openssl crl -in test.crl -text -noout
            #elif inputtext.startswith("-----BEGIN X509 CRL-----"):
            elif dataType == "crl":
                if inType == "file":
                    cmd = "openssl crl  -in " + infile + " -text -noout -inform DER"
                    app.logger.info("binary file parsing, type=X509 CRL : " + cmd)
                    pemstr = run_cmd(cmd)
                else:
                    pemstr = do_openssl(inputtext.encode('utf-8'), b"crl", b"-text", b"-noout", b"-inform", b"PEM")
                result = pemstr.decode('utf-8')
                
                if not result.startswith("Certificate Revocation List (CRL):"):
                    errtype = "error"
                    errmsg = "error: invalid certificate revocation list"
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-pem.html', result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    

            ##ppenssl cms -cmsout -in plain.txt.cms -print -noout -inform PEM
            #elif inputtext.startswith("-----BEGIN CMS-----"):
            elif dataType == "cms":
                if inType == "file":
                    cmd = "openssl cms -cmsout -print -inform DER -noout -in " + infile
                    app.logger.info("binary file parsing, type=X509 CRL : " + cmd)
                    pemstr = run_cmd(cmd)
                else:
                    pemstr = do_openssl(inputtext.encode('utf-8'), b"cms", b"-cmsout", b"-print", b"-noout", b"-inform", b"PEM")

                result = pemstr.decode('utf-8')
                app.logger.info(result)
                
                if not result.startswith("CMS_ContentInfo:"):
                    errtype = "error"
                    errmsg = "error: invalid CMS(Cryptographic Message Syntax) message"
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-pem.html', result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    

            else:
                flash("error: no input data")
                return render_template( '/analyzer-pem.html', result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    
        except:
            flash("Exception: Invalid data or type...")
            errtype = "error"
            errmsg = "error: Fail to parse data, Please check Data/File valid or file type"
            return render_template( '/analyzer-pem.html', result=None, errmsg=errmsg, errtype=errtype) 
        
        return render_template( '/analyzer-pem.html', result=result)    

    ##GET    
    return render_template( '/analyzer-pem.html', result=result)

#######################
## ENCRYPT 
#######################
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


def RSA_encrypt(message, pub_key):
    #RSA encryption protocol according to PKCS#1 OAEP
    #cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(message)


#######################
# Role: Encrypt with RSA Public Key
# in: inputtext
# public key from : X509 Certificate 
#######################
@blueprint.route('/cipher-pubkey_encrypt.html', methods=['GET', 'POST'])
def cipher_pubkey_encrypt():

    infile = None
    cmd = ""
    app.logger.info(">>> cipher: public key encrypt file")

    if request.method == 'POST':
        
        f = request.files.get('inputfile', None)
        if not f:
            errtype, errmsg = "fileerror", "no input file"
            return render_template( '/cipher-pubkey_encrypt.html', errtype=errtype, errmsg=errmsg)

        

        inform = request.form.get("inform")
        inpass = request.form.get("inpass", None)
        action = request.form.get("action")

        infile = os.path.join(app_config.UPLOAD_DIR, f.filename)
        f.save(infile)

        kf = request.files.get("keyfile", None)
        if not kf:
            errtype, errmsg = "keyfileerror", "no certinput file"
            return render_template( '/cipher-pubkey_encrypt.html', errtype=errtype, errmsg=errmsg)
        keyfile = os.path.join(app_config.UPLOAD_DIR, kf.filename)
        kf.save(keyfile)

        app.logger.info("message file: " + infile)
        app.logger.info("key     file: " + keyfile)
        app.logger.info("key format  : " + inform)
        app.logger.info("action      : " + action)
            
        if action == "enc":

            outfile = os.path.join(app_config.DOWNLOAD_DIR, f.filename + "." + "enc")
          
            #derstr = do_openssl(inputtext.encode('utf-8'), b"rsautl", b"-encrypt", b"-certin", b"-inkey", infile, b"-keyform", inform)
            cmd = 'openssl rsautl -encrypt -pkcs -certin -in \"%s\" -inkey \"%s\" -out \"%s\"' % (infile, keyfile, outfile)
            app.logger.info('enc.command: %s' % cmd)
            
        elif action == "dec":

            outfile = os.path.join(app_config.DOWNLOAD_DIR, f.filename + "." + "org")
            extension = os.path.splitext(f.filename)[1][1:]

            cmd = 'openssl rsautl -decrypt -in \"%s\" -out \"%s\" -inkey \"%s\" -keyform %s -pkcs' % (infile, outfile, keyfile, inform)

            if inpass:
                passin = " -passin pass:%s" % inpass
                cmd = cmd + passin 
            
            app.logger.info('dec.command: %s' % cmd)
            
        else:
            flash("error: invalid command!")
            return render_template( '/cipher-pubkey_encrypt.html')

        result = run_cmd(cmd)

        outputtext = result

        if os.path.isfile(outfile):
            return send_file(outfile, as_attachment=True)

        return render_template( '/cipher-pubkey_encrypt.html', outputtext=outputtext)

   
    return render_template( '/cipher-pubkey_encrypt.html')


@blueprint.route('/generator-base64.html', methods=['GET', 'POST'])
def generator_base64():

    app.logger.info("Generate BASE64 >>>>> ")
        
    if request.method == 'POST':

        
        inputtext = request.form.get('inputtext', None)
        alg = request.form.get("alg", "b64")
        action = request.form.get("action")
                
        app.logger.info("action ==> " + action)
        app.logger.info("alg ==> " + alg)
        app.logger.info("inputtext ==> " + inputtext)

        result = None

        #ENCODE_FUNC = {"b64":base64.b64encode, "b16":base64.b16encode, "b32":base64.b32encode, "a85":base64.a85encode, "b85":base64.b85encode}
        #DECODE_FUNC = {"b64":base64.b64decode, "b16":base64.b16decode, "b32":base64.b32decode, "a85":base64.a85decode, "b85":base64.b85decode}
        ENCODE_FUNC = {"b64":base64.b64encode}
        DECODE_FUNC = {"b64":base64.b64decode}

        try:
            if action == "encode":
                pemstr = ENCODE_FUNC[alg](inputtext.encode('utf-8'))
                result = pemstr.decode()
                app.logger.info("result ==> " + result)
                
            elif action == "decode":
                pemstr = DECODE_FUNC[alg](inputtext.encode('utf-8'))
                #pemstr = DECODE_FUNC[alg](inputtext)
                result = pemstr.decode('utf-8')
                app.logger.info("result ==> " + result)
            else:
                flash("error: invalid command!")
                result ="error"
                
            return render_template( '/generator-base64.html', result=result, inputtext=inputtext)
        except:
            ##error
            result = "error"
            return render_template( '/generator-base64.html', result=result)
        
    return render_template( '/generator-base64.html', result="input text")


@blueprint.route('/generator-digest.html', methods=['GET', 'POST'])
def generator_digest():

    app.logger.info("Generate Digest >>>>> ")
        
    if request.method == 'POST':

        
        inputtext = request.form.get('inputtext', None)
        dgst_alg = request.form.get("dgst_alg", None)
        action = request.form.get("action")
        hmac_checked = request.form.get("hmac_checked")
        

        if not dgst_alg:
            dgst_alg = "sha256"
        
        ##dgst_alg = dgst_alg.decode('utf-8')

        app.logger.info("action ==> " + action)
        app.logger.info("dgst_alt ==> " + dgst_alg)
        app.logger.info("inputtext ==> " + inputtext)

        try:
            if action == "encode":
                alg="-" + dgst_alg
                app.logger.info("alg ==> " + alg)
                
                if hmac_checked:
                    inpass = request.form.get('inpass')
                    if not inpass:
                        errtype="inpass"
                        errmsg="invalid passphrase"
                        return render_template( '/generator-digest.html', errtype=errtype)
                    
                    pemstr = do_openssl(inputtext.encode('utf-8'), b"dgst", b"-hmac", inpass)
                else:
                    pemstr = do_openssl(inputtext.encode('utf-8'), b"dgst", alg)

                result = pemstr.decode('utf-8')
                app.logger.info("result ==> " + result)
            elif action == "decode":
                
                #print('command: ', cmd,  file=sys.stderr)
                result = "not yet"
            else:
                flash("error: invalid command!")
                result ="error"
                
            if result.startswith('(stdin)='):
                result = result.split('=')[1]
            
            return render_template( '/generator-digest.html', result=result)
        except:
            ##error
            result = "error"
            return render_template( '/generator-digest.html')
        
    return render_template( '/generator-digest.html')


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
