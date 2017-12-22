import winrm
import base64
import urllib.parse as urlparse

import arago.pyactionhandler.plugins.winrm.exceptions
import requests.exceptions
import logging

class Session(winrm.Session):
	def __init__(self, *args, **kwargs):
		self.logger = logging.getLogger('root')
		return super().__init__(*args, **kwargs)

	def run_ps(self, script, target=None, use_ssl=False, creds=None):
		"""base64 encodes a Powershell script and executes the powershell encoded script command"""

		script_bytes = script.encode('utf-8')
		packed_expression = base64.b64encode(script_bytes).decode('cp850')
		expression_template = (
			'iex $(' +
			"[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{0}'))".format(packed_expression)
			+ ')')
		if target:
			if creds:
				username, password = creds
			expression_template = "{gencreds}icm {cmpname}{creds}{usessl}-Command {{{expr}}}".format(
				gencreds=("$u='{usr}'; $p=ConvertTo-SecureString '{passwd}' -AsPlainText "
						  '-Force; $c = new-object -Typename System.Management.Automation.PSCredential '
						  '-Args $u,$p;').format(usr=username, passwd=password) if creds else "",
				cmpname="-Cn {target} ".format(target=target) if target else "",
				creds="-Credential $c " if creds else "",
				usessl="-UseSSL " if use_ssl else "",
				expr=expression_template
			)
		command = '$OutputEncoding=[console]::OutputEncoding=[console]::InputEncoding=[system.text.encoding]::GetEncoding([System.Text.Encoding]::Default.CodePage);' + expression_template
		exe = 'mode con: cols=1052 & powershell -NoProfile -command "{0}"'.format(command)
		rs = self.run_cmd(exe)
		if rs.std_err:
			raise arago.pyactionhandler.plugins.winrm.exceptions.WinRMError(rs.std_err.decode('cp850'))
		return rs
