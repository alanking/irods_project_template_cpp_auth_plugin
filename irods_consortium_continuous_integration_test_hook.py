from __future__ import print_function

import argparse
import glob
import json
import os
import shutil
import textwrap

import irods_python_ci_utilities

def irods_directory():
	return str(os.path.join('/var', 'lib', 'irods'))

def irods_test_log_directory():
	return str(os.path.join(irods_directory(), 'log'))

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--output_root_directory')
	parser.add_argument('--built_packages_root_directory')
	parser.add_argument('--test', metavar='dotted name')
	parser.add_argument('--skip-setup', action='store_false', dest='do_setup', default=True)
	args = parser.parse_args()

	built_packages_root_directory = args.built_packages_root_directory
	package_suffix = irods_python_ci_utilities.get_package_suffix()
	os_specific_directory = irods_python_ci_utilities.append_os_specific_directory(built_packages_root_directory)

	if args.do_setup:
		# Given that this is an authentication plugin, you will probably need to set up some services and test users
		# in the system with which this authentication plugin communicates.

		irods_python_ci_utilities.install_os_packages_from_files(
			glob.glob(os.path.join(os_specific_directory,
					  f'irods-auth-plugin-nop*.{package_suffix}')
			)
		)

	test = args.test or 'test_auth_plugin_project_template_cpp'

	try:
		test_output_file = 'log/test_output.log'
		irods_python_ci_utilities.subprocess_get_output(['sudo', 'su', '-', 'irods', '-c',
			f'python3 scripts/run_tests.py --xml_output --run_s {test} 2>&1 | tee {test_output_file}; exit $PIPESTATUS'],
			check_rc=True)
	finally:
		output_root_directory = args.output_root_directory
		if output_root_directory:
			irods_python_ci_utilities.gather_files_satisfying_predicate(
				irods_test_log_directory(), output_root_directory, lambda x: True)

if __name__ == '__main__':
	main()
