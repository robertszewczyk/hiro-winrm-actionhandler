import gevent

from arago.pyactionhandler.action import Action
from arago.pyactionhandler.plugins.winrm.auth.kerberos import krb5Session
from arago.pyactionhandler.plugins.winrm.session import Session
#from arago.pyactionhandler.plugins.winrm.auth.basic import basicSession
from arago.pyactionhandler.plugins.winrm.script import Script

from pathlib import Path
import winrm.exceptions
import requests.exceptions
import arago.pyactionhandler.plugins.winrm.exceptions
import logging



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

	def winrm_run_script(self, winrm_session, **kwargs):
		script = self.init_script(self.parameters['Command'])
		try:
			script.run(winrm_session, **kwargs)
			self.output, self.error_output = script.get_outputs()
			self.system_rc = script.rs.status_code
			self.success = True
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
			elif par is None:
				raise NameError
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

		# NOQA Check MessageEnryption parameter

		try:
			MSG_ENC_VALS = ['always', 'never', 'auto']
			MSG_ENC = check_enum('MessageEncryption', enum=MSG_ENC_VALS)
		except ValueError:
			self.logger.warning(("[{anum}] Parameter 'MessageEncryption'='{val}' must be 'always', 'never' or 'auto'! "
			                     "Using default of 'auto'."
			).format(anum=self.num, val=self.parameters.get('MessageEncryption')))
			MSG_ENC = 'auto'
		except NameError:
			self.logger.warning(("[{anum}] Parameter 'MessageEncryption' is missing! Please check "
			                     "/opt/autopilot/conf/external_actionhandlers/capabilities/winrm-actionhandler.yaml. "
			                     "Using default of 'auto'."
			).format(anum=self.num, val=self.parameters.get('MessageEncryption')))
			MSG_ENC = 'auto'

		# NOQA Check VerifySSL parameter
		try:
			VERIFY_SSL = check_boolean('VerifySSL')
		except ValueError:
			try:
				VERIFY_SSL = check_file('VerifySSL')
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
			"credssp_disable_tlsv1_2": DISABLE_TLS_12,
			"message_encryption": MSG_ENC,
			"service": "WSMAN"
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
		if USE_SSL:
			endpoint = "{protocol}://{hostname}:{port}/wsman".format(
					protocol='https',
					hostname=JUMPSERVER if JUMPSERVER else self.parameters.get('Hostname'),
					port='5986')
			if VERIFY_SSL == True:
				kwargs['server_cert_validation'] = 'validate'
			elif VERIFY_SSL == False:
				kwargs['server_cert_validation'] = 'ignore'
			elif VERIFY_SSL:
				kwargs['server_cert_validation'] = 'validate'
				kwargs['ca_trust_path'] = VERIFY_SSL
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
				winrm_session = krb5Session(endpoint=endpoint, username=self.parameters['Username'], keytab=self.parameters['Keytab'], num=self.num, **kwargs)
			elif WINRM_AUTH == 'certificate':
				self.statusmsg = "Authentication method '{auth}' not yet supported.".format(auth=WINRM_AUTH)
				self.logger.warning(self.statusmsg)
				return
		except ValueError:
			self.statusmsg = (
				"Authentication method '{auth}' unknown. Valid authentication methods are "
				"'plaintext', 'ntlm', 'credssp', 'kerberos' and 'certificate'."
			).format(auth=WINRM_AUTH)
			self.logger.error(self.statusmsg)
			return
		except NameError as e:
			print(e)
			self.statusmsg = (
				"Parameter 'Authentication' is missing. Please check "
				"/opt/autopilot/conf/external_actionhandlers/capabilities/winrm-actionhandler.yaml")
			self.logger.error(self.statusmsg)
			return
		kwargs = {}
		if JUMPSERVER:
			kwargs['target'] = self.parameters.get('Hostname')
			if (WINRM_AUTH in ['plaintext', 'ntlm']
				and self.parameters.get('Username')
				and self.parameters.get('Password')):
				kwargs['creds'] = self.parameters.get('Username'), self.parameters.get('Password')
			elif (WINRM_AUTH in ['plaintext', 'ntlm']
				  and not (self.parameters.get('Username') and self.parameters.get('Password'))):
				self.logger.error("mist!")
				return
			if USE_SSL:
				kwargs['use_ssl'] = True

			self.logger.debug("[{anum}] Connecting to '{target}' via jumpserver '{jmp}'".format(
				anum=self.num,
				target=self.parameters['Hostname'],
				jmp=self.parameters['Jumpserver']
			))
		else:
			self.logger.debug("[{anum}] Executing directly on '{target}'".format(
				anum=self.num, target=self.parameters['Hostname']))
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
