rlm_two_factor
==============

rlm_two_factor is a `Freeradius 2`_ module, which implements one-time-password,
`RFC 4226`_, and pass the authentication forward. How does it work?

* on the authorize section, define an authorize type
* on the authenticate section, under the Auth-Type defined, set two_factor and 
  a second module, which the password without the challenge will be passed

The password contains the challenge and the static password:
  $CHALENGE$STATIC

.. contents::

Building
--------
  $ RADIUSDIR=/opt/freeradius-2.1.8 VERS=2.1.8 make

Installation
------------
  $ RADIUSDIR=/opt/freeradius-2.1.8 VERS=2.1.8 make install

Examples
--------
- $RADIUSDIR/etc/modules/two_factor::
    two_factor {
        otpfile = "/etc/otpfile"
        delim = ":"
        challenge_length = 6
        offset = 3
    }

- $RADIUSDIR/etc/raddb/clients.conf::
    client localhost {
        ipaddr = 127.0.0.1
        secret = testing123
        require_message_authenticator = no

        virtual_server = hotp
    }

- $RADIUSDIR/etc/raddb/sites-enabled/hotp::
    server hotp {
        authorize {
            ...
            update control {
                Auth-Type := TwoFactor
            }
            ...
        }
        authenticate {
            ...
            Auth-Type TwoFactor {
                two_factor
                unix
            }
            ...
        }
        ...
    }

.. _Freeradius 2: http://freeradius.org/
.. _RFC 4226: http://www.ietf.org/rfc/rfc4226.txt
