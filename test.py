import jks , sys, base64, textwrap



def print_pem(der_bytes, types):
	print("-----BEGIN %s-----" % types)
	print("\r\n".join(textwrap.wrap(base64.b64encode(der_bytes).decode('ascii'), 64)))
	print("-----END %s-----" % types)


ks = jks.KeyStore.load("STAR.softcamp.co.kr.jks", "softcamp2018@")

for alias, pk in ks.private_keys.items():
    print("Private key: %s" % pk.alias)
    if pk.algorithm_oid == jks.util.RSA_ENCRYPTION_OID:
        print_pem(pk.pkey, "RSA PRIVATE KEY")
    else:
        print_pem(pk.pkey_pkcs8, "PRIVATE KEY")

    for c in pk.cert_chain:
        print_pem(c[1], "CERTIFICATE")
    print()

for alias, c in ks.certs.items():
    print("Certificate: %s" % c.alias)
    print_pem(c.cert, "CERTIFICATE")
    print()

for alias, sk in ks.secret_keys.items():
    print("Secret key: %s" % sk.alias)
    print("  Algorithm: %s" % sk.algorithm)
    print("  Key size: %d bits" % sk.key_size)
    print("  Key: %s" % "".join("{:02x}".format(b) for b in bytearray(sk.key)))
    print()




====
from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from os.path import exists, join

from datetime import datetime, timedelta
import subprocess

import base64

from OpenSSL._util import (ffi as _ffi, lib as _lib)


CERT_FILE="./pySignCert.pem"
KEY_FILE="./pySignKey.pem" 

def create_self_signed_cert(cert_dir):
    k=crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)

    cert=crypto.X509()
    cert.get_subject().C = "KR"
    cert.get_subject().O = "ERmind"
    cert.get_subject().OU = "Web Isolation"
    cert.get_subject().CN = gethostname()
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, "sha1")

    open(join(cert_dir, CERT_FILE), "wt").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(join(cert_dir, KEY_FILE), "wt").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
"""
PKCS12.export([passphrase=None][, iter=2048][, maciter=1]) : Returns a PKCS12 object as a string. The optional passphrase must be a string not a callback.
See also the man page for the C function PKCS12_create().
PKCS12.get_ca_certificates() : Return CA certificates within the PKCS12 object as a tuple. Returns None if no CA certificates are present.
PKCS12.get_certificate() : Return certificate portion of the PKCS12 structure.
PKCS12.get_friendlyname() : Return friendlyName portion of the PKCS12 structure.
PKCS12.get_privatekey() : Return private key portion of the PKCS12 structure
PKCS12.set_ca_certificates(cacerts) : Replace or set the CA certificates within the PKCS12 object with the sequence cacerts. Set cacerts to None to remove all CA certificates.
PKCS12.set_certificate(cert) : Replace or set the certificate portion of the PKCS12 structure.
PKCS12.set_friendlyname(name) : Replace or set the friendlyName portion of the PKCS12 structure.
PKCS12.set_privatekey(pkey)
"""
def generate_pkcs12(cert_pem=None, key_pem=None, ca_pem=None, friendly_name=None):
    p12 = crypto.PKCS12()
    if cert_pem:
        ret = p12.set_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem))
        assert ret == None
    if key_pem:
        ret = p12.set_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem))
        assert ret == None
    if ca_pem:
        ret = p12.set_ca_certificate((crypto.load_certificate(crypto.FILETYPE_PEM, ca_pem),))
        assert ret == None
    if friendly_name:
        ret = p12.set_friendlyname(friendly_name)
        assert ret == None
    return p12


def x509_data():
    """
    Create a new private key and start a certificate request (for a test
    to finish in one way or another).
    """
    # Basic setup stuff to generate a certificate
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 512)
    req = crypto.X509Req()
    req.set_pubkey(pkey)
    # Authority good you have.

    req.get_subject().commonName = "Yoda root CA"
    req.get_subject().C = "CA"
    x509 = crypto.X509()
    subject = x509.get_subject()
    subject.commonName = req.get_subject().commonName
    subject.C = req.get_subject().C
    x509.set_issuer(subject)
    x509.set_pubkey(pkey)
    now = datetime.now()
    expire = datetime.now() + timedelta(days=100)
    x509.set_notBefore(now.strftime("%Y%m%d%H%M%SZ").encode())
    x509.set_notAfter(expire.strftime("%Y%m%d%H%M%SZ").encode())
    #yield pkey, x509
    return pkey, x509

def read_pem_file(filename):
    with open(filename, "r") as f:
        pem_str = f.read()
        if pem_str.startswith("-----BEGIN"):
            return pem_str
    return None
    
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

output = do_openssl(cert_pem, b"x509", b"-text", b"-noout")
print("parseing ==> [%s]" % output)

key_pem="""-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALp7slzF3n0MwisQ
Us2BTsDSgtiDH8Ty3F/HQF0dPdpkHsLChKJx8nOunXlAuja6Z9wgMh0jlSr9Zg/z
y91A8Qhd26bX7w4lZV1JJcUtPvvijOxWvDANfxXX63juQK2XsycN8tFrVL+QazgJ
4ZD3v2BeEDNqzU4+cSFbmnI5Aun/AgMBAAECgYEAozrk++nC/uhtCS7Hm9Rkr8lT
+NqFs2n1VezdvON8oa3jcwy69koRNAsTEfCDTqZJhNe1peXgivm1HZ+Dwc43a2HA
mRPu3uctST8r6AEE5FmZWgnPCPsnmQAMKG6mXb1YBzcZo70B/myLfZzBdST5Db91
pJPkTRAO0dbrBifsc/kCQQDgYzs48xTZxTWIijEogI25w2v4g0+akIj7BLldrztV
sIlkqhg3eWZReWr5MKJgsrduF5U9qL7vaRgOjG4OGagdAkEA1MFnQjcD8pKS08LA
JUOAHorNhIUz0cGSC62cX4P9XChuDHVOWbSthUkEtXqLzYh372g5Yo1n0S5BQ4lZ
qdAXywJAR8w4pO5S26OYj4n4VMddkfUP1ULe88wPqJJIZcuuJqsIK2epvAZiUOuS
6Q1Ax8QnoVh2bnZSMfTkt7MDfAuFmQJADVUtbmXaNnpe/yxGNE+dmMxkArkCPVPf
HiI8GXRBDWRvORKk3VRIR4EC7YiHeFLkCTnD1tw7tE0sw9m4p76lrwJBAKfEOJ86
Lpd/t59da3duisxQfMrc/dm9Miwq8fLFmEaWayxTiRAGB/rPuVSsN0csDHUIqfnD
yMWn0igKT0nkM58=
-----END PRIVATE KEY-----
"""

pkcs7Data = b"""\
-----BEGIN PKCS7-----
MIIDNwYJKoZIhvcNAQcCoIIDKDCCAyQCAQExADALBgkqhkiG9w0BBwGgggMKMIID
BjCCAm+gAwIBAgIBATANBgkqhkiG9w0BAQQFADB7MQswCQYDVQQGEwJTRzERMA8G
A1UEChMITTJDcnlwdG8xFDASBgNVBAsTC00yQ3J5cHRvIENBMSQwIgYDVQQDExtN
MkNyeXB0byBDZXJ0aWZpY2F0ZSBNYXN0ZXIxHTAbBgkqhkiG9w0BCQEWDm5ncHNA
cG9zdDEuY29tMB4XDTAwMDkxMDA5NTEzMFoXDTAyMDkxMDA5NTEzMFowUzELMAkG
A1UEBhMCU0cxETAPBgNVBAoTCE0yQ3J5cHRvMRIwEAYDVQQDEwlsb2NhbGhvc3Qx
HTAbBgkqhkiG9w0BCQEWDm5ncHNAcG9zdDEuY29tMFwwDQYJKoZIhvcNAQEBBQAD
SwAwSAJBAKy+e3dulvXzV7zoTZWc5TzgApr8DmeQHTYC8ydfzH7EECe4R1Xh5kwI
zOuuFfn178FBiS84gngaNcrFi0Z5fAkCAwEAAaOCAQQwggEAMAkGA1UdEwQCMAAw
LAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmljYXRlMB0G
A1UdDgQWBBTPhIKSvnsmYsBVNWjj0m3M2z0qVTCBpQYDVR0jBIGdMIGagBT7hyNp
65w6kxXlxb8pUU/+7Sg4AaF/pH0wezELMAkGA1UEBhMCU0cxETAPBgNVBAoTCE0y
Q3J5cHRvMRQwEgYDVQQLEwtNMkNyeXB0byBDQTEkMCIGA1UEAxMbTTJDcnlwdG8g
Q2VydGlmaWNhdGUgTWFzdGVyMR0wGwYJKoZIhvcNAQkBFg5uZ3BzQHBvc3QxLmNv
bYIBADANBgkqhkiG9w0BAQQFAAOBgQA7/CqT6PoHycTdhEStWNZde7M/2Yc6BoJu
VwnW8YxGO8Sn6UJ4FeffZNcYZddSDKosw8LtPOeWoK3JINjAk5jiPQ2cww++7QGG
/g5NDjxFZNDJP1dGiLAxPW6JXwov4v0FmdzfLOZ01jDcgQQZqEpYlgpuI5JEWUQ9
Ho4EzbYCOaEAMQA=
-----END PKCS7-----
"""


cms_enc_pem="""-----BEGIN CMS-----
MIIBZwYJKoZIhvcNAQcDoIIBWDCCAVQCAQAxgfkwgfYCAQAwXzBZMQswCQYDVQQG
EwJLUjEPMA0GA1UECgwGRVJtaW5kMRYwFAYDVQQLDA1XZWIgSXNvbGF0aW9uMSEw
HwYDVQQDDBhqa2tpbXVpLU1hY0Jvb2tQcm8ubG9jYWwCAgPoMA0GCSqGSIb3DQEB
AQUABIGAKosolA5Hbj/cVpzjV7SgVnhrsB9MrTJTzyQKSwNq7wkR5LDPcOiX07e3
Il4mdw71xyT4RYb2NmacussB/b9qQYuC3UwHHxqA1rIvFG69PPUlcelQnL3mvN3z
hOPUP+GS2KFgUMGpVo1KYg1Jp+m2mdosymi7NpZDLd3/Rq8lDrowUwYJKoZIhvcN
AQcBMBQGCCqGSIb3DQMHBAg5nJs5+6N4XYAwrd5lwv9M55ZUMMjbt0ZeNeAqECPk
M9OGnBby8YrOXPdPFS0y9IAl3DCUJ+fEEEWn
-----END CMS-----"""


##pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_PEM, cms_enc_pem)
pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_PEM, pkcs7Data)
pkcs7.type_is_enveloped()
pkcs7.type_is_signed()

print ("is enveloped %s" % pkcs7.type_is_enveloped() )
print ("is    signed %s" %  pkcs7.type_is_signed() )


str1 = read_pem_file("./pySignCert.pem")
print ("./pySignCert.pem ==> [%s]" % str1)

if key_pem.startswith("-----BEGIN"):
    print("Private key type: PEM")
else:
    print("not a PEM type private key")


##generate_pkcs12(cert_pem="./pySignCert.pem")
pfx=generate_pkcs12(cert_pem=cert_pem, key_pem=None, ca_pem=None, friendly_name="hi there")
print(pfx.get_friendlyname())
cert=pfx.get_certificate()
print(crypto.dump_certificate(crypto.FILETYPE_PEM,cert))
#print(pfx.export()) ## binary data
#create_self_signed_cert("./")

pkey1, cert1 = x509_data()

str_issuer = cert1.get_issuer()
print("cert.get_issuer: %s" % str_issuer.commonName)
print("cert.get_components: %s" % str_issuer.get_components())

class _EllipticCurve(object):
    _curves = None

    def __init__(self, lib, nid, name):
        self._lib = lib
        self._nid = nid
        self.name = name

    @classmethod
    def from_nid(cls, lib, nid):
        """
        Instantiate a new :py:class:`_EllipticCurve` associated with the given
        OpenSSL NID.
        :param lib: The OpenSSL library binding object.
        :param nid: The OpenSSL NID the resulting curve object will represent.
            This must be a curve NID (and not, for example, a hash NID) or
            subsequent operations will fail in unpredictable ways.
        :type nid: :py:class:`int`
        :return: The curve object.
        """
        return cls(lib, nid, _ffi.string(lib.OBJ_nid2sn(nid)).decode("ascii"))

    @classmethod
    def _load_elliptic_curves(cls, lib):
        num_curves = lib.EC_get_builtin_curves(_ffi.NULL, 0)
        builtin_curves = _ffi.new("EC_builtin_curve[]", num_curves)
        lib.EC_get_builtin_curves(builtin_curves, num_curves)
        return set(cls.from_nid(lib, c.nid) for c in builtin_curves)

    @classmethod
    def _get_elliptic_curves(cls, lib):
        """
        Get, cache, and return the curves supported by OpenSSL.
        :param lib: The OpenSSL library binding object.
        :return: A :py:type:`set` of ``cls`` instances giving the names of the
            elliptic curves the underlying library supports.
        """
        if cls._curves is None:
            cls._curves = cls._load_elliptic_curves(lib)
        return cls._curves

def get_elliptic_curve_list():
    return _EllipticCurve._get_elliptic_curves(_lib)

for curve in get_elliptic_curve_list():
    print(curve.name)


## one line cert read
cert2 = crypto.load_certificate(crypto.FILETYPE_PEM, open("./pySignCert.pem", 'r').read())
str2 = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert2)
print("oneline: %s" % str2)
print("issuer.C: %s" % cert2.get_issuer().C)
print("issuer.CN: %s" % cert2.get_issuer().CN)

## base64 encode/decode test