==========================
Python Autograph Utilities
==========================

|pypi| |ci| |coverage|

.. |pypi| image:: https://img.shields.io/pypi/v/autograph-utils.svg
    :target: https://pypi.python.org/pypi/autograph-utils
.. |ci| image::  https://img.shields.io/github/actions/workflow/status/mozilla-services/python-autograph-utils/test.yml?branch=main
    :target: https://github.com/mozilla-services/python-autograph-utils/actions
.. |coverage| image:: https://coveralls.io/repos/github/mozilla-services/python-autograph-utils/badge.svg?branch=main
    :target: https://coveralls.io/github/mozilla-services/python-autograph-utils?branch=main

A library to simplify use of Autograph


* Free software: Apache Software License 2.0
* Documentation: https://python-autograph-utils.readthedocs.io.


Features
--------

SignatureVerifier
=================

The canonical implementation of certificate chain validation. Although
some other implementations seem to exist (such as
https://github.com/river2sea/X509Validation,
https://github.com/alex/x509-validator, and
https://github.com/openstack/cursive), all are marked as
pre-production and/or needing work, so just do it ourselves.

Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
