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

        flash("cheking user...")        
        
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
        flash(' just show it ... ')      
        return render_template( 'accounts/register.html', form=create_account_form)

@blueprint.route('/analyzer-pem.html', methods=['GET', 'POST'])
def analyzer_pem():

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

    flash(' just show it ... ')      
    result=cert_pem
    return render_template( '/analyzer-pem.html', result=result)


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
        return render_template( '/generator-privatekey.html', alg=alg, algorithm_name=algorithm_name, message=message)
    message="GET"
    flash(' just show it ... ')      
    return render_template( '/generator-privatekey.html', alg=alg, algorithm_name=algorithm_name, message=message)

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
