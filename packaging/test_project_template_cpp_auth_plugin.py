from __future__ import print_function

import os
import unittest

from . import session
from .. import lib


class test_project_template_cpp_authentication(unittest.TestCase):
	@classmethod
	def setUpClass(self):
		self.admin = session.mkuser_and_return_session('rodsadmin', 'otherrods', 'rods', lib.get_hostname())

		# You will want to set up the test user and other authentication information (e.g. passwords) in the test hook
		# and make reference to these here. Consider checking for the existence of your test users and raising an error
		# if they are missing.
		self.auth_user = "my_auth_user"
		self.auth_pass = "my_auth_pass"

		# This creates a session for the iRODS user to which the external user is mapped.
		self.auth_session = session.mkuser_and_return_session('rodsuser', self.auth_user, self.auth_pass, lib.get_hostname())

	@classmethod
	def tearDownClass(self):
		self.auth_session.__exit__()

		self.admin.assert_icommand(['iadmin', 'rmuser', self.auth_session.username])
		self.admin.__exit__()
		with session.make_session_for_existing_admin() as admin_session:
			admin_session.assert_icommand(['iadmin', 'rmuser', self.admin.username])

	def test_some_cool_authentication_feature(self):
		pass

	def test_some_horrible_authentication_bug_has_been_fixed(self):
		pass
