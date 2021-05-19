# django-ca
Managing x509 certificates with Django

Managing x509 certificates is repetative and exacting. Thanks to Django, it's possible to
manage certificate creation and signing with ease using custom admin-commands.

Why manage certificates?

Apps such as OpenVPN use certificates for authentication, authorisation and encryption.
By managing your own ca you get to choose who has access to your network.
This app also collates certificates and other settings into a convenient client.ovpn
file.
