#----------------------------------------------------------------------
# Copyright (c) 1999-2021, Persistent Objects Ltd https://p-o.co.uk/
#
# TLS Client Certificate management
#
# License: BSD 2 Clause
#
#----------------------------------------------------------------------
# -*- coding: utf-8 -*-
"""TLS Certificates management

Request
--request user
Generate an x509 certificate request using information from
Django's User model and organisational settings
Duplicate requests will cause an error
Add --server for a server certificate with TLS Web Server Authentication,
and will not be checked against django users

Sign
--sign user
Sign a client or server certificate request
If a previous certificate exists, it will be revoked

Send OpenVPN config to a client
--send-ovpn [user]
Collating configuration and certificate information to generate a client.ovpn
then sending it to the user.

Renewal
--send-ovpn-all
Periodic renewal of all certificates

Notes:
This ca_tls admin-command has been developed and tested on FreeBSD, it is
likely to work on all the BSDs, Linux and macOS with minimal effort.

This admin-command uses x509 Public Key Infrastructures with OpenSSL
A pre-requisite is that you have a Certificate Authority (ca)
For information on setting up a Certificate Authority, please refer to
https://pki-tutorial.readthedocs.io/en/latest/

This TLS certificate management admin-command is based on the advanced
PKI example:
https://pki-tutorial.readthedocs.io/en/latest/advanced/index.html

The OpenVPN configuration guide:
https://openvpn.net/community-resources/how-to/

Settings:
CA_ROOT_CERTIFICATE = Location of the root certificate
CA_TLS_CERTIFICATE_ROOT = Base certificate firectory
CA_TLS_CONFIG = Location of the openssl tls configuration file
CA_TLS_CERTIFICATES = Location for certificates
CA_TLS_PRIVATE = Private keys and configurations
CA_TLS_CNAME = Your signing certificate
CA_TLS_COUNTRY = Country code
CA_TLS_ORG = Your organisation
CA_TLS_UNIT = Your organisational unit (optional)
CA_TLS_STATE = Your State or province
CA_TLS_LOCALITY = Your Locality
CA_TLS_SIGNING_CRT = Your signing certificate
CA_TLS_SIGNING_KEY = Your signing key
CA_TLS_SIGNING_DAYS = Number of days to certify for
OPENVPN_ROOT = Location of the OpenVPN configuration
OPENVPN_HOST = OpenVPN host
OPENVPN_PORT = OpenVPN port
OPENVPN_AUTH_USER_PASS = OpenVPN requires a username and password

Example settings:
CA_TLS_CERTIFICATE_ROOT = './ca'
CA_ROOT_CERTIFICATE = CA_TLS_CERTIFICATE_ROOT + '/root-ca.crt'
CA_TLS_CONFIG = CA_TLS_CERTIFICATE_ROOT + '/tls-ca.conf'
CA_TLS_CERTIFICATES = CA_TLS_CERTIFICATE_ROOT + '/tls-ca/certs'
CA_TLS_PRIVATE = CA_TLS_CERTIFICATE_ROOT + '/tls-ca/private'
CA_TLS_COUNTRY = "NO"
CA_TLS_ORG = "Green AS"
CA_TLS_UNIT = "Green Certificate Authority"
CA_TLS_NAME = "Green Root CA"
CA_TLS_STATE = ""
CA_TLS_LOCALITY = ""
CA_TLS_SIGNING_CRT = CA_TLS_CERTIFICATE_ROOT + '/tls-ca.crt'
CA_TLS_SIGNING_KEY = CA_TLS_CERTIFICATE_ROOT + '/tls-ca.key'
CA_TLS_SIGNING_DAYS = 380
OPENVPN_ROOT = '/usr/local/etc/openvpn'
OPENVPN_HOST = "example.com"
OPENVPN_PORT = "1194"
OPENVPN_AUTH_USER_PASS = False
"""

import logging
import os
import subprocess

from smtplib import SMTPException
from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import EmailMultiAlternatives
from django.core.management.base import BaseCommand
from django.template import loader

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    """Management Command for Client Certificate management.
    You must have write access to create private certificate requests.
    Create a certificate signing request with --request,
    sign the request with --sign user,
    use --server to generate one with TLS Web Server Authentication,
    then send the OpenVPN configuration to the user with --send-ovpn.
    """
    help = """Client Certificate management.
    You must have write access to create private certificate requests.
    Create a certificate signing request with --request,
    sign the request with --sign,
    use --server to generate one with TLS Web Server Authentication
    then send the OpenVPN configuration to the user with --send-ovpn.
    """

    def __init__(self):
        self.certificate = {}
        self.tls_auth_key = '{}/openvpn-tls-auth.key'.format(
            settings.OPENVPN_ROOT
        )
        self.server = False
        self.user = None
        self.password = None
        super().__init__()

    def add_arguments(self, parser):
        parser.add_argument(
            '--request',
            metavar='user',
            help="Create a certificate request for a user"
        )
        parser.add_argument(
            '--server',
            default=False,
            action="store_true",
            help="Server certificate instead of client"
        )
        parser.add_argument(
            '--revoke',
            metavar='user',
            help="Revoke a certificate for a user"
        )
        parser.add_argument(
            '--send-ovpn',
            metavar='user',
            help="Email an OpenVPN configuration file to a user"
        )
        parser.add_argument(
            '--send-ovpn-all',
            action="store_true",
            help="Email an OpenVPN configuration file to all users"
        )
        parser.add_argument(
            '--sign',
            metavar='user',
            help="Sign a user certificate request"
        )
        parser.add_argument(
            'user',
            action="store_false",
            help="Username"
        )
        parser.add_argument(
            '--password',
            default="",
            help="Password"
        )

    def handle(self, *args, **options):
        if options['password']:
            self.password = options['password']
            msg = "Stored password: {}".format(self.password)
        if options['server']:
            self.server = True
        if options['request']:
            if self._set_user(options['request']):
                self.cert_req()
        if options['revoke']:
            if self._set_user(options['revoke']):
                self.cert_revoke()
        if options['sign']:
            if self._set_user(options['sign']):
                self.cert_sign()
        if options['send_ovpn']:
            if self._set_user(options['send_ovpn']):
                self.cert_send_ovpn()
        if options['send_ovpn_all']:
            msg = "Sending all ovpn renewals"
            logger.info(msg)
            self.cert_send_ovpn_all()

    def cert_req(self):
        """Create a certificate request"""
        msg = 'Creating certificate request for: {}'.format(self.user)
        logger.debug(msg)

        ret = self._generate_request_conf()
        if ret:
            ret = self._generate_certificate_request()

        if ret:
            msg = 'The following files now exist:'
            logger.debug(msg)
            statinfo = os.stat(self.certificate['req'])
            if statinfo.st_size > 0:
                msg = 'Request: {}'.format(self.certificate['req'])
                logger.debug(msg)
            statinfo = os.stat(self.certificate['keyout'])
            if statinfo.st_size > 0:
                msg = 'Private key: {}'.format(self.certificate['keyout'])
                logger.debug(msg)

        return True

    def cert_sign(self):
        """Generate and sign a certificate from a request"""
        msg = 'Sign certificate request: {}'.format(self.certificate['req'])
        logger.debug(msg)
        ret = True

        # Check a signing request exists
        statinfo = os.stat(self.certificate['req'])
        if statinfo.st_size > 0:
            msg = 'Signing request: {}'.format(self.certificate['req'])
            logger.debug(msg)
        else:
            msg = 'Please generate a request first: {}'.format(self.certificate['req'])
            logger.debug(msg)
            return False

        # Revoke a previous certificate if it exists
        try:
            statinfo = os.stat(self.certificate['certificate_chain'])
            msg = 'Revoking previous certificate: {}'.format(self.certificate['certificate_chain'])
            logger.debug(msg)
            ret = self.cert_revoke()
        except FileNotFoundError:
            pass
        if ret:
            ret = self._cert_sign()
        if ret:
            ret = self._cert_output()

        return ret

    def cert_send_ovpn(self):
        """Email a client OpenVPN configuration file to the user"""
        root_certificate = self._get_root_certificate()
        client_certificate = self._get_client_certificate()
        if not client_certificate:
            msg = 'Unable to send user config without a certificate'
            logger.error(msg)
            return False

        client_certificate_enddate = self._get_client_certificate_enddate()
        context = {
            "user": self.user,
            "server": self.server,
            "root_certificate": root_certificate,
            "client_certificate": client_certificate,
            "client_certificate_enddate": client_certificate_enddate,
            "client_key": self._get_client_key(),
            "tls_auth_key": self._get_tls_auth_key(),
            "auth_user_pass": settings.OPENVPN_AUTH_USER_PASS,
            "org": settings.CA_TLS_ORG,
            "remote_host": settings.OPENVPN_HOST,
            "remote_port": settings.OPENVPN_PORT,
        }
        # Load client configuration template
        tpl = loader.get_template('po/management/commands/ca-tls-client.ovpn')
        client_ovpn = tpl.render(context)

        # Load client email template
        tpl = loader.get_template('po/management/commands/ca-tls-ovpn-email.txt')
        text_content = tpl.render(context)
        tpl = loader.get_template('po/management/commands/ca-tls-ovpn-email.html')
        html_content = tpl.render(context)

        # Send client configuration to the user
        if self.server:
            msg = "{} OpenVPN configuration file for {}".format(
                settings.CA_TLS_ORG,
                self.user.username,
            )
        else:
            msg = "{} OpenVPN configuration file for {} {}".format(
                settings.CA_TLS_ORG,
                self.user.first_name,
                self.user.last_name,
            )
        subject = msg
        try:
            msg = EmailMultiAlternatives(
                subject,
                text_content,
                settings.DEFAULT_FROM_EMAIL,
                [self.user.email]
            )
            msg.attach_alternative(html_content, "text/html")
            msg.attach(
                filename='client.ovpn',
                content=client_ovpn,
                mimetype="text/plain"
            )
            msg.send()
        except ValueError as err:
            msg = 'Please check email settings: {}'.format(err)
            logger.debug(msg)
            return False
        except SMTPException as err:
            msg = 'Unable to send email: {}'.format(err)
            logger.debug(msg)
            return False

        return True

    def cert_send_ovpn_all(self):
        """Send renewal OpenVPN configuration emails to all users"""
        users = User.objects.filter(is_active=True)
        for user in users:
            msg = 'Processing user: {}'.format(user.username)
            logger.debug(msg)
            self._set_user(user)
            self.cert_send_ovpn()

    def _set_user(self, user):
        ret = True
        if self.server:
            self.user = User(
                username=user,
                first_name=user,
                last_name="DOMAIN",
                email=settings.SERVER_EMAIL,
            )
        else:
            try:
                self.user = User.objects.get(username=user)
            except ObjectDoesNotExist:
                ret = False
                msg = (
                    'User {} does not exist.\n'
                    'Please check the user name and try again').format(user)
                logger.error(msg)
        if ret:
            self.certificate['config'] = '{}/{}.conf'.format(
                settings.CA_TLS_PRIVATE,
                self.user.username
            )
            self.certificate['keyout'] = '{}/{}.key'.format(
                settings.CA_TLS_PRIVATE,
                self.user.username
            )
            self.certificate['req'] = '{}/{}.csr'.format(
                settings.CA_TLS_PRIVATE,
                self.user.username
            )
            self.certificate['certificate_pem'] = '{}/{}-cert.pem'.format(
                settings.CA_TLS_PRIVATE,
                self.user.username
            )
            self.certificate['certificate_chain'] = '{}/{}.crt'.format(
                settings.CA_TLS_CERTIFICATES,
                self.user.username
            )
        return ret


    def _generate_request_conf(self):
        """Generate a user client certificate request configuration"""
        ret = True
        context = {
            "user": self.user,
            "country": settings.CA_TLS_COUNTRY,
            "state": settings.CA_TLS_STATE,
            "locality": settings.CA_TLS_LOCALITY,
            "org": settings.CA_TLS_ORG,
            "unit": settings.CA_TLS_UNIT,
            "server": self.server,
        }
        # Load certificate request template
        tpl = loader.get_template('po/management/commands/ca-tls-request.conf')
        request_configuration = tpl.render(context)

        try:
            with open(self.certificate['config'], 'x') as file:
                print(request_configuration, file=file)
        except FileExistsError:
            msg = 'Unable to create a duplicate request conf for: {}'.format(self.user)
            logger.warning(msg)
            ret = False
        except OSError:
            msg = 'Unable to create a request conf for: {}: {} {}'.format(
                self.user, OSError.errno, OSError.strerror
            )
            logger.debug(msg)
        return ret

    def _generate_certificate_request(self):
        # Generate certificate request
        ret = True
        cert_extension = 'client_ext'
        if self.server:
            cert_extension = 'server_ext'
        cmd = ('openssl req -verbose'
                ' -new -newkey rsa:2048'
                ' -keyout {}'
                ' -nodes'
                ' -out {}'
                ' -config {}'
                ' -extensions {}'
            ).format(
                self.certificate['keyout'],
                self.certificate['req'],
                self.certificate['config'],
                cert_extension,
            )
        msg = 'Creating key with: {}'.format(cmd)
        logger.debug(msg)

        try:
            output = subprocess.run(
                cmd,
                shell=True,
                check=True,
            )
            msg = output.stdout
            logger.debug(msg)
        except subprocess.CalledProcessError as error:
            ret = False
            msg = 'Unable to generate certificate request: {}'.format(error)
            logger.debug(msg)

        return ret

    def _get_root_certificate(self):
        """Get a root certificate"""
        output = None
        cmd = 'openssl x509 -in "{}"'.format(settings.CA_ROOT_CERTIFICATE)
        msg = 'Getting root certificate: {}'.format(cmd)
        logger.debug(msg)
        try:
            output = subprocess.run(
                cmd,
                shell=True,
                check=True,
                capture_output=True,
                encoding='utf-8'
            )
            ret = output.stdout.split(sep='\n')
        except subprocess.CalledProcessError as error:
            msg = 'Unable to get root certificate: {}'.format(error.stderr)
            logger.debug(msg)
            ret = False

        return ret

    def _get_client_certificate(self):
        """Get a client certificate"""
        # Get client certificate
        output = None
        cmd = 'openssl x509 -in "{}"'.format(self.certificate['certificate_chain'])
        msg = 'Getting client certificate: {}'.format(cmd)
        logger.debug(msg)
        try:
            output = subprocess.run(
                cmd,
                shell=True,
                check=True,
                capture_output=True,
                encoding='utf-8'
            )
            ret = output.stdout.split(sep='\n')
        except subprocess.CalledProcessError as error:
            msg = 'Unable to get client certificate: {}'.format(error.stderr)
            logger.debug(msg)
            ret = False

        return ret

    def _get_client_certificate_enddate(self):
        """Get client certificate end date"""
        output = None
        ret = True
        cmd = 'openssl x509 -in "{}" -noout -enddate'.format(
            self.certificate['certificate_chain']
        )
        msg = 'Getting client certificate end date: {}'.format(cmd)
        logger.debug(msg)
        try:
            output = subprocess.run(
                cmd,
                shell=True,
                check=True,
                capture_output=True,
                encoding='utf-8'
            )
            ret = output.stdout.split(sep='=')[1]
        except subprocess.CalledProcessError as error:
            msg = 'Unable to get client certificate end date: {}'.format(error.stderr)
            logger.debug(msg)
            ret = False

        return ret

    def _get_client_key(self):
        """Get client key"""
        ret = False
        cmd = 'openssl rsa -in "{}"'.format(self.certificate['keyout'])
        msg = 'Getting client key: {}'.format(cmd)
        logger.debug(msg)
        output = None
        try:
            output = subprocess.run(
                cmd,
                shell=True,
                check=True,
                capture_output=True,
                encoding='utf-8'
            )
            ret = output.stdout.split(sep='\n')
        except subprocess.CalledProcessError as error:
            msg = 'Unable to get client key: {}'.format(error.stdout)
            logger.debug(msg)
            ret = False

        return ret

    def cert_revoke(self):
        """Revoke an existing certificate"""
        ret = True
        try:
            os.stat(self.certificate['certificate_chain'])
            msg = 'Revoking previous certificate: {}'.format(self.certificate['certificate_chain'])
            logger.debug(msg)
        except FileNotFoundError:
            msg = 'No certificate to revoke: {}'.format(self.certificate['certificate_chain'])
            logger.debug(msg)
            return False
        if self.password:
            cmd = ('openssl ca'
                ' -config "{ssl_config}"'
                ' -cert "{signing_cert}"'
                ' -keyfile "{signing_key}"'
                ' -batch -key "{password}"'
                ' -revoke "{cert}"'
                ' -crl_reason superseded'
                ).format(
                    signing_cert=settings.CA_TLS_SIGNING_CRT,
                    signing_key=settings.CA_TLS_SIGNING_KEY,
                    password = self.password,
                    ssl_config = settings.CA_TLS_CONFIG,
                    cert = self.certificate['certificate_chain']
                )
        else:
            cmd = ('openssl ca'
                ' -config "{ssl_config}"'
                ' -cert "{signing_cert}"'
                ' -keyfile "{signing_key}"'
                ' -revoke "{cert}"'
                ' -crl_reason superseded'
                ).format(
                    signing_cert=settings.CA_TLS_SIGNING_CRT,
                    signing_key=settings.CA_TLS_SIGNING_KEY,
                    ssl_config = settings.CA_TLS_CONFIG,
                    cert = self.certificate['certificate_chain']
                )
        msg = 'Revoking client certificate with: {}'.format(cmd)
        logger.debug(msg)
        try:
            output = subprocess.run(
                cmd,
                shell=True,
                check=True,
                capture_output=True,
                encoding='utf-8'
            )
            msg = output.stdout
            logger.debug(msg)
            os.remove(self.certificate['certificate_chain'])
            os.remove(self.certificate['certificate_pem'])
            ret = True
        except subprocess.CalledProcessError as error:
            msg = 'Unable to revoke certificate: {}'.format(error.stderr)
            logger.error(msg)
            ret = False
        except OSError:
            msg = 'Unable to delete revoked certificates: {}: {} {}'.format(
                self.user, OSError.errno, OSError.strerror
            )
            logger.error(msg)
            ret = False
        return ret

    def _cert_sign(self):
        """Sign a certificate"""
        msg = 'Signing certificate'
        logger.debug(msg)
        ret = True
        try:
            os.stat(self.certificate['certificate_chain'])
            msg = 'Please revoke and delete existing certificate: {}'.format(
                self.certificate['certificate_chain']
            )
            logger.error(msg)
            return False
        except FileNotFoundError:
            pass
        cert_extension = 'client_ext'
        if self.server:
            cert_extension = 'server_ext'
        try:
            os.stat(self.certificate['req'])
        except FileNotFoundError:
            msg = ('Please create a certificate request '
                'before signing: {}').format(self.certificate['req'])
            logger.error(msg)
            return False
        if self.password:
            cmd = ('openssl ca'
                ' -config "{ssl_config}"'
                ' -cert "{signing_cert}"'
                ' -keyfile "{signing_key}"'
                ' -batch -key {password}'
                ' -out "{certificate_pem}"'
                ' -days {days}'
                ' -extensions {cert_extension}'
                ' -infiles "{req}"'
                ).format(
                    signing_cert = settings.CA_TLS_SIGNING_CRT,
                    signing_key = settings.CA_TLS_SIGNING_KEY,
                    password = self.password,
                    ssl_config = settings.CA_TLS_CONFIG,
                    req = self.certificate['req'],
                    certificate_pem = self.certificate['certificate_pem'],
                    days = settings.CA_TLS_SIGNING_DAYS,
                    cert_extension = cert_extension,
                )
        else:
            cmd = ('openssl ca -batch'
                ' -config "{ssl_config}"'
                ' -cert "{signing_cert}"'
                ' -keyfile "{signing_key}"'
                ' -out "{certificate_pem}"'
                ' -days {days}'
                ' -extensions {cert_extension}'
                ' -infiles "{req}"'
                ).format(
                    signing_cert=settings.CA_TLS_SIGNING_CRT,
                    signing_key=settings.CA_TLS_SIGNING_KEY,
                    ssl_config = settings.CA_TLS_CONFIG,
                    req = self.certificate['req'],
                    certificate_pem = self.certificate['certificate_pem'],
                    days = settings.CA_TLS_SIGNING_DAYS,
                    cert_extension = cert_extension,
                )
        msg = 'Signing certificate with: {}'.format(cmd)
        logger.debug(msg)
        try:
            output = subprocess.run(
                cmd,
                shell=True,
                check=True,
                capture_output=True,
                encoding='utf-8'
            )
            msg = output.stdout
            logger.debug(msg)
        except subprocess.CalledProcessError as error:
            msg = 'Unable to sign certificate: {}'.format(error.stderr)
            logger.error(msg)
            return False
        except OSError:
            msg = 'Unable to sign certificate: {}: {} {}'.format(
                self.user, OSError.errno, OSError.strerror
            )
            logger.error(msg)
            return False
        return ret

    def _cert_output(self):
        msg = 'Outputting certificate'
        logger.debug(msg)
        cmd = 'openssl x509 -in "{certificate_pem}" -out "{certificate}"'.format(
                certificate_pem = self.certificate['certificate_pem'],
                certificate = self.certificate['certificate_chain'],
            )
        try:
            output = subprocess.run(
                cmd,
                shell=True,
                check=True,
                capture_output=True,
                encoding='utf-8'
            )
            msg = output.stdout
            logger.debug(msg)
        except subprocess.CalledProcessError as error:
            msg = 'Unable to output certificate: {}'.format(error.stderr)
            logger.error(msg)
            ret = False
        except OSError:
            msg = 'Unable to output certificate: {}: {} {}'.format(
                self.user, OSError.errno, OSError.strerror
            )
            logger.error(msg)
            return False

        msg = 'Adding certificate chain'
        logger.debug(msg)
        cmd = 'openssl x509 -in "{signing_cert}" >> "{certificate}"'.format(
                signing_cert = settings.CA_TLS_SIGNING_CRT,
                certificate = self.certificate['certificate_chain']
            )
        try:
            output = subprocess.run(
                cmd,
                shell=True,
                check=True,
                capture_output=True,
                encoding='utf-8'
            )
            msg = output.stdout
            logger.debug(msg)
            ret = True
        except subprocess.CalledProcessError as error:
            msg = 'Unable to add certificate chain: {}'.format(error.stderr)
            logger.error(msg)
            ret = False
        except OSError:
            msg = 'Unable to add certificate chain: {}: {} {}'.format(
                self.user, OSError.errno, OSError.strerror
            )
            logger.error(msg)
            raise
        return ret

    def _get_tls_auth_key(self):
        """Get tls auth key"""
        ret = False
        msg = 'Getting the shared server (tls-auth) key: {}'.format(self.tls_auth_key)
        logger.debug(msg)
        try:
            with open(self.tls_auth_key, 'r') as file:
                ret = file.read()
        except FileExistsError:
            msg = 'Unable to open: {}'.format(self.tls_auth_key)
            logger.warning(msg)
            ret =False

        return ret
