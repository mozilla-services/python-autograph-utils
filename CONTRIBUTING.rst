.. highlight:: shell

============
Contributing
============

Contributions are welcome, and they are greatly appreciated! Every little bit
helps, and credit will always be given.

You can contribute in many ways:

Types of Contributions
----------------------

Report Bugs
~~~~~~~~~~~

Report bugs at https://github.com/glasserc/python_autograph_utils/issues.

If you are reporting a bug, please include:

* Your operating system name and version.
* Any details about your local setup that might be helpful in troubleshooting.
* Detailed steps to reproduce the bug.

Fix Bugs
~~~~~~~~

Look through the GitHub issues for bugs. Generally speaking, any issue
is open to whoever wants to implement it. If you're interested in
working on an issue, post a comment to let others know not to waste
their time duplicating your effort. Issues tagged "good first bug" are
especially suitable for contribution from new contributors!

Get Started!
------------

Ready to contribute? Here's how to set up `python_autograph_utils` for local development.

1. Fork the `python_autograph_utils` repo on GitHub.
2. Clone your fork locally:

.. code-block:: bash

    $ git clone git@github.com:your_name_here/python_autograph_utils.git

3. Install your local copy into a virtualenv. Assuming you have virtualenvwrapper installed, this is how you set up your fork for local development:

.. code-block:: bash

    $ mkvirtualenv python_autograph_utils
    $ cd python_autograph_utils/
    $ python setup.py develop
    $ pip install -r requirements_dev.txt

4. Create a branch for local development:

.. code-block:: bash

    $ git checkout -b name-of-your-bugfix-or-feature

   Now you can make your changes locally.

5. You might want to run the tests to make sure they're passing before you start work.
   You can run the tests using:

.. code-block:: bash

    $ py.test # or python setup.py test

6. When you're done making changes, check that the tests pass again, including
   testing other Python versions with tox:

.. code-block:: bash

    $ tox

7. When you're ready to commit some changes, be sure to verify the
   cleanliness of the files you're committing. Standards are enforced
   using `pre-commit <https://pre-commit.com/>`_. You can check all
   the files in the project using:

.. code-block:: bash

    $ pre-commit run --all-files

   Or instead you can configure it to run automatically before every
   commit using:

.. code-block:: bash

    $ pre-commit install

8. Commit as normal:

.. code-block:: bash

    $ git add .
    $ git commit -m "Your detailed description of your changes."
    $ git push origin name-of-your-bugfix-or-feature

9. Submit a pull request through the GitHub website.

Pull Request Guidelines
-----------------------

Before you submit a pull request, check that it meets these guidelines:

1. The pull request should include tests, or a good explanation of why
   tests are not practical.
2. If the pull request adds functionality, the docs should be updated. Put
   your new functionality into a function with a docstring, and add the
   feature to the list in README.rst.
3. The pull request should work for Python 2.7, 3.5, 3.6 and 3.7, and
   for PyPy. The CI will automatically run the tests against each of
   those versions using ``tox`` (see above).

Once you submit your PR, the CI will automatically run and will show
the results of the "checks" at the bottom of the PR. Make sure your
checks are green!

Tips
----

To run a subset of tests:

.. code-block:: bash

    $ py.test tests.test_python_autograph_utils


Releasing
---------

We use the ``zest.releaser`` package to manage releases. Install it using:

.. code-block:: bash

    $ pip install "zest.releaser[recommended]"

Before releasing:

- Update ``HISTORY.rst``

To produce a release:

.. code-block:: bash

    $ git checkout -b prepare-X.Y.Z
    $ make test-all
    $ prerelease

- Open a pull-request to release the new version.

.. code-block:: bash

    $ git commit -a --amend
    $ git push origin prepare-X.Y.Z

Once the PR is reviewed and approved, merge it (click the green
button) and do the release.

.. code-block:: bash

    $ git checkout master
    $ git pull
    $ release
    $ postrelease

Finally:

- Add a release on the Github releases page
