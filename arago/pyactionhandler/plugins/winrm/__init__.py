import gevent
import gevent.subprocess

from arago.pyactionhandler.action import Action
from arago.pyactionhandler.plugins.winrm.auth.kerberos import krb5Session
from arago.pyactionhandler.plugins.winrm.session import Session
#from arago.pyactionhandler.plugins.winrm.auth.basic import basicSession
from arago.pyactionhandler.plugins.winrm.script import Script

import winrm.exceptions
import requests.exceptions
import arago.pyactionhandler.plugins.winrm.exceptions
import logging
import re

from requests_kerberos.exceptions import KerberosExchangeError



class WinRMCmdAction(Action):
	def __str__(self):
		return "cmd.exe command '{cmd}' on '{node}'".format(
			cmd=self.parameters['Command'],
			node=self.parameters['Hostname'])

	@staticmethod
	def init_script(script):
		return Script(
			script=script,
			interpreter='cmd',
			cols=120)

	def parse_krb5_err(self, err):
		result = re.search(r"authGSSClientStep\(\) failed: \(\((?P<q1>'|\")(?P<major_desc>.+)(?P=q1), (?P<major_code>-?[\d]+)\), \((?P<q2>'|\")(?P<minor_desc>.+)(?P=q2), (?P<minor_code>-?[\d]+)\)\)", err)
		return result.group('minor_desc') if result else None

	def winrm_run_script(self, winrm_session, **kwargs):
		script = self.init_script(self.parameters['Command'])
		for i in range(3):
			try:
				script.run(winrm_session, **kwargs)
				self.output, self.error_output = script.get_outputs()
				self.system_rc = script.rs.status_code
				self.success = True
			except KerberosExchangeError as e:
				parsed_err = self.parse_krb5_err(str(e))
				self.statusmsg = str(e)
				self.success = False
				self.system_rc = -1
				if (parsed_err == "Ticket expired"
					or (parsed_err.startswith("Credentials cache file ") and parsed_err.endswith(" not found"))):
					self.logger.warning("[{anum}] No Kerberos ticket for {host}, requesting one ...".format(
						anum=self.num, host=self.parameters['Hostname']))
					self.statusmsg = "Authentication failed."
					try:
						with open(self.parameters['Keytab']):
							pass
						gevent.subprocess.check_output(
							["kinit", "-k", "-t", self.parameters['Keytab'], self.parameters['Username']],
							timeout=30, stderr=gevent.subprocess.STDOUT)
						self.logger.info("[{anum}] Successfully retrieved Kerberos ticket for {host}, retrying command execution.".format(
							anum=self.num, host=self.parameters['Hostname']))
					except gevent.subprocess.CalledProcessError as e:
						self.logger.error("[{anum}] Retrieving Kerberos ticket for {host} failed: {err}".format(
							anum=self.num, host=self.parameters['Hostname'], err=e.output.decode("utf-8")))
					except gevent.subprocess.TimeoutExpired as e:
						self.logger.error("[{anum}] Retrieving Kerberos ticket for {host} timed out!".format(
							anum=self.num, host=self.parameters['Hostname']))
					except FileNotFoundError as e:
						self.logger.error("[{anum}] Retrieving Kerberos ticket for {host} failed: {err}".format(
							anum=self.num, host=self.parameters['Hostname'], err=e))
					except KeyError:
						self.logger.error("[{anum}] Retrieving Kerberos ticket for {host} failed! Credentials missing!".format(
							anum=self.num, host=self.parameters['Hostname']))
					continue
				elif parsed_err:
					self.logger.error("[{anum}] An error occured during command execution on {node}: Kerberos: {err}".format(
						anum=self.num, node=self.node, err=parsed_err))
					self.statusmsg = parsed_err
				else:
					self.logger.error("[{anum}] An error occured during command execution on {node}: Kerberos: {err}".format(
						anum=self.num, node=self.node, err=str(e)))
			except (
					winrm.exceptions.WinRMError,
					winrm.exceptions.WinRMTransportError,
					arago.pyactionhandler.plugins.winrm.exceptions.WinRMError,
					requests.exceptions.RequestException
			) as e:
				self.statusmsg = str(e)
				self.success = False
				self.system_rc = -1
				self.logger.error("[{anum}] An error occured during command execution on {node}: {err}".format(
					anum=self.num, node=self.node, err=str(e)))
			break

	def __call__(self):
		def check_boolean(name):
			if str(self.parameters.get(name)).lower() in ['true', 'yes', 'on', '1', 'enabled']:
				return True
			elif str(self.parameters.get(name)).lower() in ['false', 'no', 'off', '0', 'none', 'disabled']:
				return False
			else:
				raise ValueError

		def check_integer(name, default):
			try:
				return int(self.parameters.get(name))
			except (ValueError, TypeError):
				try:
					return int(default)
				except (ValueError, TypeError):
					raise ValueError

		def check_file(name):
			path = Path(str(self.parameters.get(name)))
			if path.is_file:
				return path
			else:
				raise ValueError

		def check_enum(name, enum=[]):
			par = self.parameters.get(name)
			if par in enum:
				return par
			else:
				raise ValueError

		def check_server(name):
			hostname_regex = re.compile('(?=^.{1,253}$)(^(((?!-)[a-zA-Z0-9-]{1,63}(?<!-))|((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63})$)') # NOQA
			ipv4_regex = re.compile('(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)') # NOQA
			par = self.parameters.get(name)
			if hostname_regex.match(par) or ipv4_regex.match(par):
				return par
			else:
				raise ValueError

		# NOQA Check ReadTimeout
		try:
			READ_TIMEOUT = check_integer('ReadTimeout', default=30)
		except ValueError:
			self.logger.warning(("[{anum}] Parameter 'ReadTimeout'='{val}' cannot be converted to an integer: "
								 "Using default of 30 instead."
			).format(anum=self.num, val=self.parameters.get('ReadTimeout')))
			READ_TIMEOUT = 30

		# NOQA Check OperationTimeout
		try:
			OPERATION_TIMEOUT = check_integer('OperationTimeout', default=20)
		except ValueError:
			self.logger.warning(("[{anum}] Parameter 'OperationTimeout'='{val}' cannot be converted to an "
								 "integer: Using default of 30 instead."
			).format(anum=self.num, val=self.parameters.get('OperationTimeout')))
			OPERATION_TIMEOUT = 30

		# NOQA Check if ReadTimeout > OperationTimeout
		try:
			assert READ_TIMEOUT > OPERATION_TIMEOUT
		except AssertionError:
			self.logger.warning(("[{anum}] Parameter 'ReadTimeout'='{rval}' must be greater than parameter "
								 "'OperationTimeout'='{oval}': Using 'OperationTimeout' + 10 instead."
			).format(anum=self.num, rval=READ_TIMEOUT, oval=OPERATION_TIMEOUT))
			READ_TIMEOUT = OPERATION_TIMEOUT + 10

		# NOQA Check UseSSL parameter
		try:
			USE_SSL = check_boolean('UseSSL')
		except ValueError:
			self.logger.warning(("[{anum}] Parameter 'UseSSL'='{val}' is not one of 'true', 'false', 'yes', "
								 "'no', 'on', 'off', '1', '0': Using default of 'false' instead."
			).format(anum=self.num, val=self.parameters.get('UseSSL')))
			USE_SSL = False

		# NOQA Check VerifySSL parameter
		try:
			VERIFY_SSL = check_boolean('VerifySSL')
		except ValueError:
			try:
				check_file('VerifySSL')
			except ValueError:
				self.logger.warning(("[{anum}] Parameter 'VerifySSL'='{val}' is not one of 'true' or 'false' "
									 "and it not a path to a file, either: Using default of 'true' instead."
				).format(anum=self.num, val=self.parameters.get('VerifySSL')))
				VERIFY_SSL = True
			except PermissionError as e:
				self.logger.warning(("[{anum}] Cannot open file '{val}' for parameter 'VerifySSL': {err}; "
									 "Using default of 'true' instead."
				).format(anum=self.num, val=self.parameters.get('VerifySSL'), err=e))
				VERIFY_SSL = True

		# NOQA Check DisableTLS12
		try:
			DISABLE_TLS_12 = check_boolean('DisableTLS12')
		except ValueError:
			self.logger.warning(("[{anum}] Parameter 'DisableTLS12'='{val}' is not one of 'true' or 'false': "
								 "Using default of 'false' instead"
				).format(anum=self.num, val=self.parameters.get('DisableTLS12')))
			DISABLE_TLS_12 = False

		kwargs = {
			"read_timeout_sec": READ_TIMEOUT,
			"operation_timeout_sec": OPERATION_TIMEOUT,
			"credssp_disable_tlsv1_2": DISABLE_TLS_12
		}

		# NOQA Check Jumpserver parameter
		try:
			JUMPSERVER = check_boolean('Jumpserver')
		except ValueError:
			try:
				JUMPSERVER = check_server('Jumpserver')
			except ValueError:
				JUMPSERVER = None
				self.logger.warning(("Parameter 'Jumpserver'='{val}' has to be either an IPv4 address,"
				                     "a valid DNS name or one of '0', 'false', 'no', 'none' or 'disabled'."
				                     " Using default of 'none' instead.").format(
					                     val=self.parameters.get('Jumpserver')))

		# NOQA Construct endpoint URL
		if USE_SSL == 'true':
			endpoint = "{protocol}://{hostname}:{port}/wsman".format(
					protocol='https',
					hostname=JUMPSERVER if JUMPSERVER else self.parameters.get('Hostname'),
					port='5986')
			kwargs['server_cert_validation'] = VERIFY_SSL
		else:
			endpoint = "{protocol}://{hostname}:{port}/wsman".format(
					protocol='http',
					hostname=JUMPSERVER if JUMPSERVER else self.parameters.get('Hostname'),
					port='5985')

		# NOQA Check Authentication parameter
		try:
			AUTH_METHODS = ['plaintext', 'ntlm', 'credssp', 'kerberos', 'certificate']
			WINRM_AUTH = check_enum('Authentication', enum=AUTH_METHODS)
			if WINRM_AUTH in ['plaintext', 'ntlm', 'credssp']:
				creds = self.parameters['Username'], self.parameters['Password']
				winrm_session = Session(target=endpoint, transport=WINRM_AUTH, auth=creds, **kwargs)
			elif WINRM_AUTH == 'kerberos':
				winrm_session = krb5Session(endpoint=endpoint, **kwargs)
			elif WINRM_AUTH == 'certificate':
				self.statusmsg = "Authentication method '{auth}' not yet supported.".format(auth=WINRM_AUTH)
				self.logger.warning(self.statusmsg)
				return
		except ValueError:
			self.statusmsg = (
				"Authentication method '{auth}' unknown. Valid authentication methods are "
				"'plaintext', 'ntlm', 'credssp', 'kerberos' and 'certificate'."
			).format(auth=WINRM_AUTH)
			self.logger.warning(self.statusmsg)
			return
		self.winrm_run_script(winrm_session, **kwargs)


class WinRMPowershellAction(WinRMCmdAction):
	def init_script(self, script):
		return Script(
			script=script,
			interpreter='ps',
			cols=120)

	def __str__(self):
		return "powershell.exe command '{cmd}' on '{node}'".format(
			cmd=self.parameters['Command'],
			node=self.parameters['Hostname'])
