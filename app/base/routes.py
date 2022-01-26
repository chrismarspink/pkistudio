#dp -*- encoding: utf-8 -*-
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

from werkzeug.utils import secure_filename

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
#from Crypto.PublicKey import RSA
#from Crypto.Cipher import PKCS1_OAEP

##########
## DOCKER SDK
##########
#import docker

##########
## 쿠버네티스 SDK
##########
#from kubernetes import client, config
"""
import kubernetes
import kubernetes.config as konfig
import kubernetes.client as klient

from kubernetes import dynamic
from kubernetes.client import api_client
"""

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

dgst_alg_list = ["blake2b512", "blake2s256", "md4", "md5", "md5-sha1", "mdc2",                     
    "ripemd", "ripemd160", "rmd160", "sha1", "sha224", "sha256",                    
    "sha3-224", "sha3-256", "sha3-384", "sha3-512", "sha384", "sha512", "sha512-224", 
    "sha512-256", "shake128", "shake256", "sm3", "ssl3-md5", "ssl3-sha1", "whirlpool"]

rsabits = [1024, 2048, 4096, 8192, 16384]											

env = {
    "textarea_style" : "font-family:Consolas,Monaco,Lucida Console,Liberation Mono,DejaVu Sans Mono,Bitstream Vera Sans Mono,Courier New, monospace;white-space:pre-wrap"
}

app = Flask(__name__)

def do_openssl(pem, *args):
    """
    Run the command line openssl tool with the `g`iven arguments and write
    the given PEM to its stdin.  Not safe for quotes.
    """
    proc = subprocess.Popen([b"openssl"] + list(args), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    proc.stdin.write(pem)
    proc.stdin.close()
    output = proc.stdout.read()
    proc.stdout.close()
    proc.wait()
    return output

def do_openssl2(pem, *args):
    """
    Run the command line openssl tool with the `g`iven arguments and write
    the given PEM to its stdin.  Not safe for quotes.
    """
    proc = subprocess.Popen([b"openssl"] + list(args), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdin.write(pem)
    proc.stdin.close()
    err = proc.stderr.read()
    proc.stderr.close()

    output = proc.stdout.read()
    proc.stdout.close()
    
    proc.wait()
    return err, output
##########

def do_openssl3(cmd):
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate(input=input)

    if process.returncode:
        app.logger.info("do_openssl3: returncode: " + process.returncode)
        raise Exception(stderr, cmd)

    return stdout, stder


def run_cmd(cmd, input=None):
    process = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate(input=input)

    if process.returncode:
        
        raise Exception(stderr, cmd)

    return stdout
"""
@blueprint.route('/')
def route_default():
    return redirect(url_for('base_blueprint.login'))
"""

@blueprint.route('/')
def route_default():
    return render_template( '/index.html' )

## Login & Registration
"""
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
"""

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
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


def get_elliptic_curve_list():
    #일부 커브의 경우 openssl 오류 발생, 예를들어 Oakley-EC2N-4
    #확인된 알고리즘으로 다시 리스트 작성
    curves = []
    for curve in crypto.get_elliptic_curves():
        if curve.name in ("Oakley-EC2N-3", "Oakley-EC2N-4") :
            pass
        else:
            curves.append(curve.name)

    return curves


@blueprint.route('/generator-ecc_test_key.html', methods=['GET', 'POST'])
def generator_ecc_test_key():

    curves = get_elliptic_curve_list()

    ec_test_key = {}
    if request.method == 'POST':
        action = request.form.get('action')
        keylen = request.form.get("keylen")
        app.logger.info("action, name = %s, %s" % (action, keylen))
        if action == "generate_all":
            for name in curves:
                cmd = "openssl ecparam -genkey -name %s" % name
                key_pem = run_cmd(cmd)
                ec_test_key[name] = key_pem.decode()
        
            return render_template( '/generator-ecc_test_key.html', env=env, ec_test_key=ec_test_key, ecc_curves=curves)
        elif action == "generate_one":
            #name = request.form.get("keylen")
            cmd = "openssl ecparam -genkey -name %s" % keylen
            key_pem = run_cmd(cmd)
            ec_key = key_pem.decode()
            return render_template( '/generator-ecc_test_key.html', env=env, name=keylen, ec_key=ec_key, ecc_curves=curves)

    return render_template( '/generator-ecc_test_key.html', env=env, ec_test_key=None, ecc_curves=curves)

@blueprint.route('/generator-privatekey.html', methods=['GET', 'POST'])
def generator_privatekey():

    #curves = curves = get_elliptic_curve_list()

    if request.method == 'POST':
        action = request.form.get('action')
        if action == "generate":
            keylen = request.form.get('keylen')

            app.logger.info("action: %s, key length: %s" % (action, keylen))


            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, int(keylen))
            priv_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
            prikey_pem=priv_key.decode('utf-8')

            #pubkey = key.get_pubkey()
            pubkey_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, key)
            pubkey_pem = pubkey_pem.decode('utf-8')
            

            ## expect 'enc'
            encopt_checked = request.form.get("encrypt_option")
            if encopt_checked:
                app.logger.info("generate_privatekey: encopt_checked: " + encopt_checked)

            else:
                app.logger.info("generate_privatekey: encopt_checked: disabled(None)")

        
            return render_template( '/generator-privatekey.html', 
                env=env,
                prikey_pem=prikey_pem, 
                pubkey_pem=pubkey_pem, 
                rsa_param=rsabits, 
                aes_alg_list=aes_alg_list)
    
        elif action == "download_prikey":
            prikey_pem = request.form.get("prikey_pem")
            app.logger.info("private key(pem): %s", prikey_pem)

            generator = (cell for row in prikey_pem for cell in row)

            return Response(generator,
                mimetype="text/plain", headers={"Content-Disposition":"attachment;filename=rsa_privatekey.pem"})
            #if os.path.isfile(outfile):
            #    return send_file(outfile, as_attachment=True)

            return render_template( '/generator-privatekey.html', env=env, rsa_param=rsabits, aes_alg_list=aes_alg_list)

        elif action == "download_pubkey":
            pubkey_pem = request.form.get("pubkey_pem")
            app.logger.info("publice key(pem): %s", pubkey_pem)
            generator = (cell for row in pubkey_pem for cell in row)

            return Response(generator,
                mimetype="text/plain", headers={"Content-Disposition":"attachment;filename=rsa_publickey.pem"})

    return render_template( '/generator-privatekey.html', env=env, rsa_param=rsabits, aes_alg_list=aes_alg_list)

@blueprint.route('/generator-ecc_privatekey.html', methods=['GET', 'POST'])
def generator_ecc_privatekey():

    pubkey_pem = None
    curves = get_elliptic_curve_list()

    if request.method == 'POST':
        action = request.form.get('action')
        keylen = request.form.get('keylen')

        if action == "generate":
        
            app.logger.info("action: %s, key length: %s" % (action, keylen))

            #key = crypto.PKey()
            #key.generate_key(crypto.TYPE_RSA, int(keylen))
            #priv_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
            cmd = "openssl ecparam -genkey -name %s" % (keylen)
            pemstr = run_cmd(cmd)
            prikey_pem=pemstr.decode('utf-8')

            app.logger.info("cmd: %s" % cmd)
            app.logger.info("generated private key: %s" % pemstr)
            #pubkey_pem = pubkey_pem.decode('utf-8')

            pubkey_bytes = do_openssl(prikey_pem.encode(), b"pkey", b"-text_pub")
            pubkey_pem = pubkey_bytes.decode()

            ## expect 'enc'
            encrypt_option = request.form.get("encrypt_option", None)
            if encrypt_option:
                inpass = request.form.get("inpass", None)
                enc_alg = request.form.get("enc_alg", None)
                app.logger.info("inpass:%s, alg:%s" % (inpass, enc_alg))
                if not inpass:

                    return render_template( '/generator-ecc_privatekey.html', 
                        env=env, ecc_curves=curves, aes_alg_list=aes_alg_list, errtype="inpass", errmsg="암호화에 사용될 패스워드를 입력하세요.")
                encrypted_str = do_openssl(pubkey_bytes, "pkey", "-passin", "pass:%s" % inpass, "-%s" % enc_alg)
                prikey_pem = encrypted_str.decode('utf-8')

            else:
                app.logger.info("generate_privatekey: encopt_checked: disabled(None)")

        
            return render_template( '/generator-ecc_privatekey.html', 
                env=env,
                prikey_pem=prikey_pem, 
                pubkey_pem=pubkey_pem, 
                ecc_curves=curves, 
                aes_alg_list=aes_alg_list,
                keylen=keylen)
    
        elif action == "download_prikey":
            prikey_pem = request.form.get("prikey_pem")
            filename="ecc_%s_privatekey.pem" % request.form.get("ecparam").strip()
            app.logger.info("private key(pem): %s", prikey_pem)
            app.logger.info("filename: [%s]", filename)

            generator = (cell for row in prikey_pem for cell in row)

            return Response(generator, mimetype="text/plain", headers={"Content-Disposition":"attachment;filename=%s" % filename})
            #if os.path.isfile(outfile):
            #    return send_file(outfile, as_attachment=True)

            return render_template( '/generator-ecc_privatekey.html', env=env, ecc_curves=curves, rsa_param=rsabits, aes_alg_list=aes_alg_list)

        elif action == "download_pubkey":
            pubkey_pem = request.form.get("pubkey_pem")
            app.logger.info("publice key(pem): %s", pubkey_pem)
            
            filename="ecc_%s_prublickey.pem" % request.form.get("ecparam").strip()

            generator = (cell for row in pubkey_pem for cell in row)
            return Response(generator,
                mimetype="text/plain", headers={"Content-Disposition":"attachment;filename=%s" % filename})

    return render_template( '/generator-ecc_privatekey.html', env=env, ecc_curves=curves, aes_alg_list=aes_alg_list)



@blueprint.route('/pkix-generate_csr.html', methods=['GET', 'POST'])
def pkix_generate_csr():

    result = None
    is_encrypted=False
    filename = None
    csr_pem = csr_pem_text = cert_pem = cert_pem_text = None

    if request.method == 'POST':

        action = request.form.get('action')
        app.logger.info("action   : %s", action)
        
        if action == "download_csr_pem":
            data = request.form.get("csr_pem", None)
            generator = (cell for row in data for cell in row)
            return Response(generator, mimetype="text/plain", headers={"Content-Disposition":"attachment;filename=csr.pem"})
        elif action == "download_csr_pem_text":
            data = request.form.get("csr_pem_text", None)
            generator = (cell for row in data for cell in row)
            return Response(generator, mimetype="text/plain", headers={"Content-Disposition":"attachment;filename=csr.txt"})
        elif action == "download_cert_pem":
            data = request.form.get("cert_pem", None)
            generator = (cell for row in data for cell in row)
            return Response(generator, mimetype="text/plain", headers={"Content-Disposition":"attachment;filename=cert.pem"})
        elif action == "download_csr_pem_text":
            data = request.form.get("cert_pem_text", None)
            generator = (cell for row in csr_pem for cell in row)
            return Response(generator, mimetype="text/plain", headers={"Content-Disposition":"attachment;filename=cert.txt"})

        #개인키
        f = request.files.get('inputfile', None)
        if not f:
            app.logger.info("file not found")
            return render_template( '/pkix-generate_csr.html'
                , errtype="inputfile"
                , errmsg="Invalid file name"
                ,env=env, csr_pem=csr_pem, csr_pem_text=csr_pem_text, cert_pem=cert_pem, cert_pem_text=cert_pem_text)
            
        infile = os.path.join(app_config.UPLOAD_DIR, f.filename)
        f.save(infile)
        #DN
        subj = request.form.get("subj", None)
        #inform der/pem
        inform = request.form.get("inform", "PEM")
        #is Encrypted
        if request.form.get("encrypt_option"):
            is_encrypted=True

        
        ##정수여부는 .isdigit()로도 확인 가능
        value = request.form.get("days", None)
        try: 
            days = int(value)
        except:            
            days = 30

        san = request.form.get('san', None)
        inpass = request.form.get('inpass', None)
        version = request.form.get('version')
        subjectaltname = request.form.get('subjectaltname', None)
        
        app.logger.info("key file : %s", infile)
        app.logger.info("dn       : %s", subj)
        app.logger.info("inform   : %s", inform)
        app.logger.info("inpass   : %s", inpass)
        app.logger.info("days     : %d", days)
        app.logger.info("san      : %s", san)
        app.logger.info("version  : %s", version)
         

        cmd = "openssl req "
        if action == "csr":
            cmd = cmd + " -new"
        if action == "certificate":
            cmd = cmd + " -new -x509 "

        cmd = cmd + " -utf8 -sha256 -batch -key %s -keyform %s -days %d -subj \"%s\"" % (infile, inform, days, subj)

        if subjectaltname:
            cmd = cmd + " -addext \"subjectAltName=%s\"" % subjectaltname
        
        if is_encrypted:
                if not inpass:
                    return render_template( '/pkix-generate_csr.html', errtype="inpass", errmsg="Invalid private key passphrase")
                cmd = cmd + " -passin pass:%s" % inpass

        try:
            output_pem = run_cmd(cmd)
        except:
            return render_template( '/pkix-generate_csr.html', errtype="error", errmsg="fail to generate csr/certificate")

        ###csr_pem = csr_pem_text = cert_pem = cert_pem_text = None

        if output_pem.decode().startswith("-----BEGIN") and action == "csr":
            output_pem_text = do_openssl(output_pem, b"req", b"-text", b"-noout")
            csr_pem = output_pem.decode()
            csr_pem_text = output_pem_text.decode()
            cert_pem = cert_pem_text = None
        elif output_pem.decode().startswith("-----BEGIN") and action == "certificate":
            output_pem_text = do_openssl(output_pem, b"x509", b"-text", b"-noout")
            cert_pem = output_pem.decode()
            cert_pem_text = output_pem_text.decode()
            csr_pem = csr_pem_text = None
        else:
            return render_template( '/pkix-generate_csr.html', errtype="error", errmsg="Fail to generate CSR/Certificate!")

        return render_template( '/pkix-generate_csr.html', env=env, csr_pem=csr_pem, csr_pem_text=csr_pem_text, cert_pem=cert_pem, cert_pem_text=cert_pem_text)   

        

    return render_template( '/pkix-generate_csr.html', env=env)




@blueprint.route('/pkix-verify_csr.html', methods=['GET', 'POST'])
def pkix_verify_csr():

    result = None
    is_encrypted=False
    filename = None
    csr_pem = verify_result = output = None

    if request.method == 'POST':

        action = request.form.get('action')
        app.logger.info("action   : %s", action)
        
        #개인키
        csr_pem = request.form.get('inputtext', None)
        app.logger.info("csr-pem   : %s", csr_pem)
        
        if not csr_pem:
            app.logger.info("Invalid CSR: %s" % csr_pem)
            return render_template( '/pkix-verify_csr.html', errtype="inputfile", errmsg="NO CSR MESSAGE", env=env)

        if not csr_pem.startswith("-----BEGIN CERTIFICATE REQUEST-----"):
            app.logger.info("Invalid CSR: %s" % csr_pem)
            return render_template( '/pkix-verify_csr.html', errtype="inputfile", errmsg="INVALID FORMAT CSR MESSAGE", env=env)

        try:
            verify_result, output = do_openssl2(csr_pem.encode('utf-8'), b"req", b"-noout", b"-text", b"-verify")
            #cmd = 'openssl req -verify -text -noout -in $(echo %s)' % csr_pem
            #verify_result = run_cmd(cmd)
            app.logger.info("verify_result: %s" % verify_result)    
        except:
            #app.logger.info("verify_result: %s" % verify_result)    
            return render_template( '/pkix-verify_csr.html', errtype="error", errmsg="FAIL TO VERIFY CSR MESSAGE")

        result = verify_result.decode()
        details = None
        show = request.form.get("show", None)
        app.logger.info("show: %s" % show)
        app.logger.info("output: %s" % output)

        if show == "details" and output:
            details = output.decode()

        return render_template( '/pkix-verify_csr.html', env=env, result=result, inputtext=csr_pem, details=details)   

    return render_template( '/pkix-verify_csr.html', env=env)


@blueprint.route('/pkix-verify_certificate.html', methods=['GET', 'POST'])
def pkix_verify_certificate():

    result = None
    is_encrypted=False
    filename = None
    input_pem = verify_result = output = None

    if request.method == 'POST':

        action = request.form.get('action')
        app.logger.info("action   : %s", action)
        
        #
        input_pem = request.form.get('inputtext', None)
        app.logger.info("input_pem   : %s", input_pem)
        
        if not input_pem:
            app.logger.info("Invalid Certificate: %s" % input_pem)
            return render_template( '/pkix-verify_certificate.html', errtype="inputfile", errmsg="NO CERTIFICATE", env=env)

        if not input_pem.startswith("-----BEGIN CERTIFICATE-----"):
            app.logger.info("Invalid CSR: %s" % input_pem)
            return render_template( '/pkix-verify_certificate.html', errtype="inputfile", errmsg="INVALID FORMAT CERTIFICATE", env=env)

        f = request.files.get("cafile", None)
        if not f:
            app.logger.info("file not found")
            return render_template( '/pkix-verify_certificate.html', errtype="cafileerror", errmsg="INVALID CA CERTIFICATES FILE")
            
        cafile = os.path.join(app_config.UPLOAD_DIR, f.filename)
        f.save(cafile)

        app.logger.info("CAfile: %s" % cafile)    

        try:
            ##verify_result, output = do_openssl2(input_pem.encode('utf-8'), b"verify", b"-CAfile", b"-text", b"-verify")
            #cmd = 'openssl req -verify -text -noout -in $(echo %s)' % csr_pem
            #verify_result = run_cmd(cmd)
            options = ""
            if request.form.get("check_ss_cert", None):
                verify_result = do_openssl(input_pem.encode('utf-8'), b"verify", "-check_ss_cert", "-show_chain",  b"-CAfile", cafile)
            else:
                verify_result = do_openssl(input_pem.encode('utf-8'), b"verify", "-show_chain",  b"-CAfile", cafile)

            #verify_result = do_openssl(input_pem.encode('utf-8'), b"verify", options,  b"-CAfile", cafile)

            app.logger.info("verify_result: %s" % verify_result)    
        except:
            #app.logger.info("verify_result: %s" % verify_result)    
            return render_template( '/pkix-verify_certificate.html', errtype="error", errmsg="FAIL TO VERIFY CERTIFICATE")

        result = verify_result.decode()
        details = None
        show = request.form.get("show", None)
        app.logger.info("show: %s" % show)
        app.logger.info("output: %s" % output)

        #if show == "details" and output:
        #    details = output.decode()

        return render_template( '/pkix-verify_certificate.html', env=env, result=result, inputtext=input_pem) #, details=details)   

    return render_template( '/pkix-verify_csr.html', env=env)



@blueprint.route('/ssl-getcert.html', methods=['GET', 'POST'])
def ssl_getcert():
    result = None
    is_encrypted=False
    filename = None
    csr_pem = csr_pem_text = cert_pem = cert_pem_text = None

    if request.method == 'POST':

        action = request.form.get('action') ##extract/download
        app.logger.info("action   : %s", action)
        
        if action == "download":
            data = request.form.get("cert_txt", None)
            generator = (cell for row in data for cell in row)
            return Response(generator, mimetype="text/plain", headers={"Content-Disposition":"attachment;filename=cert.info"})

        url = request.form.get("url", None)
        port = request.form.get("port",  None)
        
        app.logger.info("url  : %s", url)
        app.logger.info("port : %s", port)

        cmd = "openssl s_client -showcerts -servername %s -connect %s:%s </dev/null" % (url, url, port)
        try:
            cert_txt = run_cmd(cmd)
        except:
            return render_template( '/ssl-getcert.html', env=env, errtype="error", errmsg="fail to extract ssl certificate")

        return render_template( '/ssl-getcert.html', env=env, cert_txt=cert_txt.decode('utf-8'))   

    return render_template( '/ssl-getcert.html', env=env)


@blueprint.route('/pkix-encrypt_privatekey.html', methods=['GET', 'POST'])
def pkix_enrypt_privatekey():
    result = None
    is_encrypted=False
    filename = None
    key_pem = None

    if request.method == 'POST':

        action = request.form.get('action') ##extract/download
        app.logger.info("action   : [%s]", action)

        if action == "generate_rsa" or action == "generate_ecc":
            pass


        ## generate_rsa/ecc
        
        if action == "download":
            data = request.form.get("key_pem", None)
            generator = (cell for row in data for cell in row)
            return Response(generator, mimetype="text/plain", headers={"Content-Disposition":"attachment;filename=key.pem"})

        inputtext = request.form.get("inputtext", None)
        inpass = request.form.get("inpass",  None)
        outpass = request.form.get("outpass",  None)
        cipher = request.form.get("cipher",  "aes256")
        
        app.logger.info("inputtext: %s", inputtext)
        app.logger.info("inpass   : %s", inpass)
        app.logger.info("outpass  : %s", outpass)
        app.logger.info("cipher   : %s", cipher)
        
        try: 
            if action == "enc":
                app.logger.info("encrypt >>>")
                key_pem = do_openssl(inputtext.encode('utf-8'), b'pkey', "-%s" % cipher, b'-passout',  "pass:%s" % outpass)
            elif action == "dec":
                app.logger.info("decrypt >>>")
                key_pem = do_openssl(inputtext.encode('utf-8'), b'pkey', b'-passin', "pass:%s" % inpass)
            elif action == "reenc":
                app.logger.info("decrypt & encrypt >>>")
                key_pem = do_openssl(inputtext.encode('utf-8'), b'pkey',  "-%s" % cipher, b'-passin',  "pass:%s" % inpass, b'-passout', "pass:%s" % outpass)

            app.logger.info("KEY PEM: %s" % key_pem.decode('utf-8'))
        except:
            return render_template( '/pkix-encrypt_privatekey.html', env=env, aes_alg_list=aes_alg_list, errtype="error", errmsg="fail to en/dercypt private key")

        return render_template( '/pkix-encrypt_privatekey.html', env=env, aes_alg_list=aes_alg_list, key_pem=key_pem.decode('utf-8'))   

    return render_template( '/pkix-encrypt_privatekey.html', env=env, aes_alg_list=aes_alg_list)


"""
@blueprint.route('/docker-main.html', methods=['GET', 'POST'])
def docker_main():

    client = docker.from_env()
    result = "GET"
    containerList = []

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


@blueprint.route('/k8s-main.html', methods=['GET', 'POST'])
def k8s_main():

    kConfigList = {}
    konfig.load_kube_config()
    result = "k8s"
    app.logger.info("Supported APIs (* is preferred version):")
    app.logger.info("%-40s %s" % ("core", ",".join(klient.CoreApi().get_api_versions().versions)))

    ##Config
    for api in klient.ApisApi().get_api_versions().groups:
        versions = []
        for v in api.versions:
            name = ""
            if v.version == api.preferred_version.version and len(api.versions) > 1:
                name += "*"
            name += v.version
            versions.append(name)
        
        app.logger.info("%-40s %s" % (api.name, ",".join(versions)))
        v = ",".join(versions)
        kConfigList[api.name] = v


    ##Instance
    api_instance = klient.CoreV1Api()
    body = {
        "metadata": {
            "labels": {
                "foo": "bar",
                "baz": None}
        }
    }
    
    node_list = api_instance.list_node()

    app.logger.info("%s\t\t%s" % ("NAME", "LABELS"))

    for node in node_list.items:
        app_response = api_instance.patch_node(node.metadata.name, body)
        kNodeList[node.metadata.name] = node.metadata.labels
        app.logger.info("%s\t%s" % (node.metadata.name, node.metadata.labels))

    
    ##dynamic client
    dclient = dynamic.DynamicClient( api_client.ApiClient(configuration=konfig.load_kube_config()) )
    api = dclient.resources.get(api_version="v1", kind="Node")

    DynamicNode = []
    app.logger.info("%s\t\t%s\t\t%s" % ("NAME", "STATUS", "VERSION"))
    
    for item in api.get().items:
        node = api.get(name=item.metadata.name)
        
        app.logger.info(
            "%s\t%s\t\t%s\n"
            % (
                node.metadata.name,
                node.status.conditions[3]["type"],
                node.status.nodeInfo.kubeProxyVersion,
            )

        )
        anode = {}
        anode['name'] = node.metadata.name
        anode['status'] = node.status.conditions[3]["type"]
        anode['version'] = node.status.nodeInfo.kubeProxyVersion
        DynamicNode.append(anode)


    kubeConfList = []
    kubeconfig = os.getenv('KUBECONFIG')
    konfig.load_kube_config(kubeconfig)
    v1 = klient.CoreV1Api()
    app.logger.info("Listing pods with their IPs:")
    ret = v1.list_pod_for_all_namespaces(watch=False)
    string = ""
    dic = {}
    for i in ret.items:
        string += "ip: %s</br>ns: %s</br>name: %s</br></br></br>" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name)
        dic["ip"] = i.status.pod_ip
        dic["ns"] = i.metadata.namespace
        dic["name"] = i.metadata.name
        kubeConfList.append(dic)
     
    result=string
    
    return render_template( '/k8s-main.html', kConfigList=kConfigList, kNodeList=kNodeList, kDynamicNode=DynamicNode, result=result, kubeConfList=kubeConfList)
"""

@blueprint.route('/analyzer-pkcs12.html', methods=['GET', 'POST'])
def analyzer_pkcs12():

    userkey_pem = usercert_pem = cacert_pem = None
    inpass = outpass = None

    if request.method == 'POST':

        action = request.form.get("action")
        
        try: 
            if action == "download_usercert":
                data = request.form.get("usercert_pem")
                app.logger.info("usercert(pem): %s", usercert_pem)
                generator = (cell for row in data for cell in row)
                return Response(generator, mimetype="text/plain", headers={"Content-Disposition":"attachment;filename=usercert.pem"})

            if action == "download_userkey":
                data = request.form.get("userkey_pem")
                app.logger.info("download userkey(pem): %s", userkey_pem)
                generator = (cell for row in data for cell in row)
                return Response(generator, mimetype="text/plain", headers={"Content-Disposition":"attachment;filename=userkey.pem"})

            if action == "download_cacert":
                data = request.form.get("cacert_pem")
                app.logger.info("download cacert(pem): %s", cacert_pem)
                generator = (cell for row in data for cell in row)
                return Response(generator, mimetype="text/plain", headers={"Content-Disposition":"attachment;filename=cacert.pem"})
        except: 
            return render_template( '/analyzer-pkcs12.html', errtype="error", errmsg="FAIL TO DOWNLOAD DATA")

        mode = request.form.get("inpass")

        f = request.files.get('pkcs12file', None)
        if not f:
            app.logger.info("file not found")
            return render_template( '/analyzer-pkcs12.html', result=result)
            
        try:
            infile = os.path.join(app_config.UPLOAD_DIR, f.filename)
            f.save(infile)
            inpass = request.form.get("inpass").encode('utf-8')
            p12 = crypto.load_pkcs12(open(infile, 'rb').read(), inpass)
            if not p12:
                return render_template( '/analyzer-pkcs12.html', errtype="error", errmsg="INVALID PKCS12 FILE")

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

        except:
            return render_template( '/analyzer-pkcs12.html', errtype="error", errmsg="FAIL TO PARSE PKCS12 FILE")
        
        
        return render_template( '/analyzer-pkcs12.html', env=env, userkey_pem=userkey_pem, usercert_pem=usercert_pem, cacert_pem = cacert_pem)    
    
    return render_template( '/analyzer-pkcs12.html', env=env)



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
            app.logger.info("file not found")
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
    elif inputtext.startswith("-----BEGIN EC PRIVATE KEY-----"): pemtype = "ecprikey"
    elif inputtext.startswith("-----BEGIN EC PARAMETERS-----"): pemtype = "ecparam"
    else: pemtype = None 

    return pemtype
    

def is_binary(filename):
    cmd = "file -b \"%s\"" % filename.decode('utf-8')
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
    cmd = "file -b \"%s\"" % filename
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
    
    
    if request.method == 'POST':

        dict = request.form
        for key in dict: app.logger.info('form key '+ dict[key])

        intype = request.form.get("intype")
        inputtext = request.form.get("inputtext", None)
        inputfile = request.form.get("inputfile", None)
        action = request.form.get("action") ##analyze

        if action =="clear":
            return render_template( '/analyzer-pem.html', env=env, result=None, errmsg=None, errtype=None, inputtext="")    

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
            if not dataType:
                return render_template( '/analyzer-pem.html', env=env,  result=None, errmsg="unsupport data type", errtype="error") 

            #app.logger.info("input format(PEM TEXT): " + dataType)

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
            return render_template( '/analyzer-pem.html', env=env, result=None, errmsg=errmsg, errtype=errtype)    

        
        
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
                    return render_template( '/analyzer-pem.html', env=env,  result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    
                
                return render_template( '/analyzer-pem.html',env=env,  result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    

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
                    return render_template( '/analyzer-pem.html', env=env,  result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    

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
                    return render_template( '/analyzer-pem.html', env=env, result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    

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
                    return render_template( '/analyzer-pem.html', env=env,  result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    

            elif dataType == "ecprikey":

                if inType == "file":
                    cmd = "openssl ec -text -noout -inform DER -in " + infile
                    app.logger.info("binary command for RSA Private Key : " + cmd)
                    pemstr = run_cmd(cmd)
                else:
                    pemstr = do_openssl(inputtext.encode('utf-8'), b"ec", b"-text", b"-noout", b"-inform", b"PEM")
                
                result = pemstr.decode()
                app.logger.info("result : " + result)
                
                if not result.startswith("Private-Key"):
                    errtype = "error"
                    errmsg = "error: invalid EC Private Key" 
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-pem.html', env=env,  result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    

            #elif inputtext.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----"):
            elif dataType == "enc_rsaprikey":
                inpass = request.form.get("inpass", None)
                if not inpass:
                    errtype = "inpass"
                    errmsg = "error: no input password"
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-pem.html', env=env,  result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    
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
                    return render_template( '/analyzer-pem.html',env=env,  result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    
            
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
                    return render_template( '/analyzer-pem.html', env=env,  result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    
            
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
                    return render_template( '/analyzer-pem.html', env=env, result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    

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
                    return render_template( '/analyzer-pem.html', env=env, result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    

            else:
                flash("error: no input data")
                return render_template( '/analyzer-pem.html', env=env, result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    
        except:
            flash("Exception: Invalid data or type...")
            errtype = "error"
            errmsg = "error: Fail to parse data, Please check Data/File valid or file type"
            return render_template( '/analyzer-pem.html', env=env, result=None, errmsg=errmsg, errtype=errtype) 
        
        return render_template( '/analyzer-pem.html', env=env, result=result)    

    ##GET    
    return render_template( '/analyzer-pem.html',env=env,  result=result)



@blueprint.route('/analyzer-file.html', methods=['GET', 'POST'])
def analyzer_file():

    app.logger.info('>>>>> Analyzer file START...')
    result = None
    inputtext = intext = intext_pem = None
    errmsg = errtype = None
    dataType = True
    inType = "text" ##file
    fileMode = "text" ##bin
    informArg = "PEM"

    isAsn1Mode = False
    isFile = True
    
    if request.method == 'POST':
        
        dataType = request.form.get("intype", None) #crt, crl, csr...
        action = request.form.get("action", None) ##analyze
        if action =="clear":
            return render_template( '/analyzer-file.html', env=env, result=None, errmsg=None, errtype=None, inputtext="")    

        asn1mode_checked = request.form.get("asn1mode", None)
        if asn1mode_checked:
            isAsn1Modee = True
            app.logger.info("asn1 mode: True")
                
        inForm = request.form.get("inform", None) ##PEM/DER
                        
        app.logger.info("action ==>  " + action)
        #app.logger.info("inForm ==>  " + inForm)
        #app.logger.info("intype ==>  " + dataType)

        f = request.files.get('inputfile', None)
        if f:
            infile = os.path.join(app_config.UPLOAD_DIR, f.filename)
            f.save(infile)
            app.logger.info("input format(FILE): " + infile)
        else: 
            errtype = "error"
            errmsg = "error: No Input Data(Text/File)"
            flash(errmsg)
            return render_template( '/analyzer-file.html', env=env, result=None, errmsg=errmsg, errtype=errtype)    

        #if True:
        try:
            #if textmode and inputtext.startswith("-----BEGIN CERTIFICATE-----"):
            if isAsn1Mode:
                cmd = "openssl asn1parse -inform %s -in \"%s\"" % (inForm, infile)
                app.logger.info("cmd sring: " + cmd)
                pemstr = run_cmd(cmd)
                result = pemstr.decode('utf-8')
                if result.startswith("Error") or result.startswith("error"):
                    errtype, errmsg ="error", "FAIL TO ASN1PARSE"
                    return render_template( '/analyzer-file.html', env=env,  result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    
                
                return render_template( '/analyzer-file.html',env=env,  result=result, inputtext=inputtext)    

            if dataType == "crt":
                cmd = 'openssl x509 -text -noout -inform %s -in \"%s\" 2>&1' % (inForm, infile)
                app.logger.info("binary command : " + cmd)
                pemstr = run_cmd(cmd)
                result = pemstr.decode('utf-8')
                
                if not result.startswith("Certificate:"):
                    app.logger.info("error: Invalid X509 Certificate")
                    return render_template( '/analyzer-file.html', env=env,  result=None, errmsg="INVALID CERTIFICATE", errtype="error", inputtext=inputtext)    

            #elif textmode and inputtext.startswith("-----BEGIN CERTIFICATE REQUEST-----"):
            elif dataType == "csr":
                cmd = "openssl req -text -noout -inform %s -in \"%s\"" % (inForm, infile)
                app.logger.info("binary command for Certificate Signing Request: " + cmd)
                pemstr = run_cmd(cmd)
                result = pemstr.decode('utf-8')
                
                if not result.startswith("Certificate Request:"):
                    errmsg = "error: invalid CSR"
                    app.logger.info(errmsg)

            elif dataType == "rsapubkey":
                cmd = "openssl ras -pubin -noout -text -inform %s -in \"%s\"" % (inForm, infile)
                app.logger.info("binary command for RSA PUBKEY : " + cmd)
                pemstr = run_cmd(cmd)
                result = pemstr.decode('utf-8')
                
                if not result.startswith("RSA Public-Key:"):
                    errtype, errmsg = "error", "Invalid RSA public key" 
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-file.html', env=env, result=None, errmsg="INVALID RSA PUBLIC KEY", errtype="error", inputtext=inputtext)    

            elif dataType == "rsaprikey":
                cmd = "openssl rsa -text -noout -inform %s -in \"%s\" " % (inForm, infile)
                app.logger.info("binary command for RSA Private Key : " + cmd)
                pemstr = run_cmd(cmd)
                result = pemstr.decode('utf-8')
                
                if not result.startswith("RSA Private-Key:"):
                    errtype, errmsg = "error", "Invalid RSA Private Key" 
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-file.html', env=env,  result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    

            elif dataType == "ecprikey":
                cmd = "openssl ec -text -noout -inform %s -in \"%s\"" % (inForm, infile)
                app.logger.info("binary command for RSA Private Key : " + cmd)
                pemstr = run_cmd(cmd)
                result = pemstr.decode()
                app.logger.info("result : " + result)
                
                if not result.startswith("Private-Key"):
                    errtype, errmsg = "error", "error: invalid EC Private Key" 
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-file.html', env=env,  result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    

            elif dataType == "enc_rsaprikey":
                inpass = request.form.get("inpass", None)
                if not inpass:
                    errtype, errmsg = "inpass", "error: no input password"
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-file.html', env=env,  result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    
                else:
                    passin_arg = "pass:" + inpass

                cmd = "openssl rsa -text -noout -inform %s -in \"%s\" -passin %s" % (inForm, infile, passin_arg)
                app.logger.info("binary command for Encrypted RSA Private Key : " + cmd)
                pemstr = run_cmd(cmd)

                result = pemstr.decode('utf-8')
                
                if not result.startswith("RSA Private-Key:"):
                    errtype, errmsg = "error", "error: invalid encrypted RSA Private Key"
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-file.html',env=env,  result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    
            
            elif dataType == "pkcs7":
                cmd = "openssl pkcs7 -text -noout -print -inform DER -in " + infile
                app.logger.info("binary file parsing, type=PKCS7 : " + cmd)
                pemstr = run_cmd(cmd)
                result = pemstr.decode('utf-8')
                
                if not result.startswith("PKCS7:"):
                    errtype = "error"
                    errmsg = "error: invalid pkcs7 message"
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-file.html', env=env,  result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    
            
            elif dataType == "crl":
                cmd = "openssl crl  -text -noout -inform %s -in \"%s\"" % (inForm, infile)
                app.logger.info("binary file parsing, type=X509 CRL : " + cmd)
                pemstr = run_cmd(cmd)
                result = pemstr.decode('utf-8')
                
                if not result.startswith("Certificate Revocation List (CRL):"):
                    errtype = "error"
                    errmsg = "error: invalid certificate revocation list"
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-file.html', env=env, result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    

            ##ppenssl cms -cmsout -in plain.txt.cms -print -noout -inform PEM
            #elif inputtext.startswith("-----BEGIN CMS-----"):
            elif dataType == "cms":
                cmd = "openssl cms -cmsout -print -inform %s -noout -in \"%s\"" % (inForm, infile)
                app.logger.info("binary file parsing, type=X509 CRL : " + cmd)
                pemstr = run_cmd(cmd)

                result = pemstr.decode('utf-8')
                app.logger.info(result)
                
                if not result.startswith("CMS_ContentInfo:"):
                    errtype = "error"
                    errmsg = "error: invalid CMS(Cryptographic Message Syntax) message"
                    app.logger.info(errmsg)
                    return render_template( '/analyzer-file.html', env=env, result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    

            else:
                flash("error: no input data")
                return render_template( '/analyzer-file.html', env=env, result=None, errmsg=errmsg, errtype=errtype, inputtext=inputtext)    
        except:
        #else:
            errtype, errmsg = "error", "ERROR: FAIL TO PARSE DATA, PLEASE CHECK FILE"
            return render_template( '/analyzer-file.html', env=env, result=None, errmsg=errmsg, errtype=errtype) 
        
        return render_template( '/analyzer-file.html', env=env, result=result)    

    ##GET    
    return render_template( '/analyzer-file.html',env=env,  result=result)

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
                app.logger.info('form:cipher: enc')
                app.logger.info('command: ', cmd)

            elif cipher == "dec":
                outfile = os.path.join(app_config.DOWNLOAD_DIR, f.filename + "." + "org")
                ##extension is encryption alg name
                ##TODO : check algo list 
                ##TODO : send algo list to cipher-encrypt.html
                extension = os.path.splitext(f.filename)[1][1:]

                cmd = 'openssl enc -d  -in \"%s\" -out \"%s\" -pass pass:1234 -%s' % (infile, outfile, extension)
                app.logger.info('form:cipher: dec')
                app.logger.info('command: ', cmd)
            else:
                flash("error: invalid command!")
                return render_template( '/cipher-encrypt.html')

            error = run_cmd(cmd)

            if os.path.isfile(outfile):
                return send_file(outfile, as_attachment=True)

        return render_template( '/cipher-encrypt.html', aes_alg_list=aes_alg_list)

    return render_template( '/cipher-encrypt.html', aes_alg_list=aes_alg_list)


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


#######################
# Role: Sign/Verify with RSA Public Key
# in: inputtext
# public key from : X509 Certificate / PrivateKey file
#######################
@blueprint.route('/sign-rsa.html', methods=['GET', 'POST'])
def sign_rsa():

    infile = hexdump = None
    cmd = opts = ""
    app.logger.info(">>> cipher: public key encrypt file")

    if request.method == 'POST':
        
        f = request.files.get('inputfile', None)
        if not f:
            errtype, errmsg = "fileerror", "no input file"
            return render_template( '/sign-rsa.html', errtype=errtype, errmsg=errmsg)


        inform = request.form.get("inform")
        inpass = request.form.get("inpass", None)
        action = request.form.get("action")
        verify_opt = request.form.get("verifyopt")

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
        app.logger.info("verifyopt   : " + verify_opt)
        
            
        if action == "sign":

            outfile = os.path.join(app_config.DOWNLOAD_DIR, f.filename + "." + "sign")
            cmd = 'openssl rsautl -sign  -in \"%s\" -inkey \"%s\" -keyform %s -out \"%s\"' % (infile, keyfile, inform, outfile)
            #cmd = 'openssl pkeyutl -sign  -in \"%s\" -inkey \"%s\" -keyform %s -out \"%s\"' % (infile, keyfile, inform, outfile)
            if inpass:
                passin = " -passin pass:%s" % inpass
                cmd = cmd + passin 

            app.logger.info('sign.command: %s' % cmd)
            
        elif action == "verify":

            outfile = os.path.join(app_config.DOWNLOAD_DIR, f.filename + "." + "org")
            extension = os.path.splitext(f.filename)[1][1:]

            if verify_opt == "hexdump":
                opts = " -hexdump"
            elif verify_opt == "file":
                opts = " -out \"%s\"" % outfile
            else:
                opts = " -hexdump"

            cmd = 'openssl rsautl -verify -in \"%s\" -certin -inkey \"%s\" -keyform %s %s'  % (infile, keyfile, inform, opts)

            app.logger.info('verify.command: %s' % cmd)
            
        else:
            flash("error: invalid command!")
            return render_template( '/sign-rsa.html')

        result = run_cmd(cmd)
        app.logger.info("run.command: " + result.decode())

        if action == "verify" and verify_opt == "hexdump":
            hexdump = result
            return render_template( '/sign-rsa.html', hexdump=hexdump.decode())
        elif (action == "verify" and verify_opt == "file") or action == "sign":
            if os.path.isfile(outfile):
                return send_file(outfile, as_attachment=True)
        
        return render_template( '/sign-rsa.html')

   
    return render_template( '/sign-rsa.html')


#######################
# Role: Sign/Verify with RSA/ECC Public Key
# in: inputtext
# signature 파일을 생성하고 검증하는 구조, pkeyutl을 이용한다. dgst -sign/verify는 인증서를 사용할 수 없는 한계가 있음
# public key from : X509 Certificate / PrivateKey file
#######################
@blueprint.route('/sign-pubkey.html', methods=['GET', 'POST'])
def sign_pubkey():

    infile = hexdump = None
    cmd = opts = ""
    app.logger.info(">>> cipher: Sign with public key >>>> ")

    if request.method == 'POST':
        #서명, 검증 모두에 필요하다.
        fin = request.files.get('inputfile', None)
        if not fin:
            errtype, errmsg = "fileerror", "no input file"
            return render_template( '/sign-rsa.html', errtype=errtype, errmsg=errmsg)
        
        infile = os.path.join(app_config.UPLOAD_DIR, fin.filename)
        fin.save(infile)

        inform = request.form.get("inform")
        inpass = request.form.get("inpass", None)
        inform = request.form.get("inform", None)
        action = request.form.get("action")

        app.logger.info("message file: " + infile)
        
        app.logger.info("key format  : " + inform)
        app.logger.info("action      : " + action)
        
        
        #서명, 검증 모두에 필요하다.
        fk = request.files.get("keyfile", None)
        if not fk:
            return render_template( '/sign-pubkey.html', errtype="keyfileerror", errmsg="no certificate/key file")
        keyfile = os.path.join(app_config.UPLOAD_DIR, fk.filename)
        fk.save(keyfile)
        app.logger.info("key     file: " + keyfile)

        dgstfile = infile +".dgst"
        cmd = 'openssl dgst -binary -sha256 %s > %s' % (infile, dgstfile)
        run_cmd(cmd)

        if not os.path.isfile(dgstfile):
            return render_template( '/sign-pubkey.html', errtype="error", errmsg='fail to generate message digest for %s' % os.path.basename(infile))

        if action == "sign":

            outfile = infile + ".sig"
            cmd = 'openssl pkeyutl -sign  -in \"%s\" -inkey \"%s\" -keyform %s -out \"%s\"' % (dgstfile, keyfile, inform, outfile)

            if inpass:
                passin = " -passin pass:%s" % inpass
                cmd = cmd + passin 

            app.logger.info('sign.command: %s' % cmd)
            
        elif action == "verify":

            #outfile = os.path.join(app_config.DOWNLOAD_DIR, f.filename + "." + "org")
            #extension = os.path.splitext(f.filename)[1][1:]

            #검증에 서명파일-sigfile 필요.
            fs = request.files.get("sigfile", None)
            if not fs:
                return render_template( '/sign-pubkey.html', errtype="sigfileerror", errmsg="no signature file to verify")
            sigfile = os.path.join(app_config.UPLOAD_DIR, fs.filename)
            fs.save(sigfile)
            app.logger.info("signature file: " + sigfile)

            """if verify_opt == "hexdump":
                opts = " -hexdump"
            elif verify_opt == "file":
                opts = " -out \"%s\"" % outfile
            else:
                opts = " -hexdump"
            """

            cmd = 'openssl pkeyutl -verify -in \"%s\" -certin -inkey \"%s\" -keyform %s -sigfile %s'  % (dgstfile, keyfile, inform, sigfile)

            app.logger.info('verify.command: %s' % cmd)
            
        else:
            flash("error: invalid command!")
            return render_template( '/sign-pubkey.html')

        result = run_cmd(cmd)
        app.logger.info("run.command: " + result.decode())

        if action == "verify":
            verify_message = result
            return render_template( '/sign-pubkey.html', verify_message=verify_message.decode())
        #elif (action == "verify" and verify_opt == "file") or action == "sign":

        if os.path.isfile(outfile):
            return send_file(outfile, as_attachment=True)
        
        return render_template( '/sign-pubkey.html')

   
    return render_template( '/sign-pubkey.html')



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

        ENCODE_FUNC = {"b64":base64.b64encode, "b16":base64.b16encode, "b32":base64.b32encode, "a85":base64.a85encode, "b85":base64.b85encode}
        DECODE_FUNC = {"b64":base64.b64decode, "b16":base64.b16decode, "b32":base64.b32decode, "a85":base64.a85decode, "b85":base64.b85decode}
        #ENCODE_FUNC = {"b64":base64.b64encode}
        #DECODE_FUNC = {"b64":base64.b64decode}

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
