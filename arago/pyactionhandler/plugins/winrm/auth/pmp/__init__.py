from arago.pyactionhandler.plugins.winrm.session import Session
import winrm


class PMPSession(Session):
	def __init__(self, endpoint, auth, target=None, target_auth=None,
				 transport='ssl', validation='ignore', **kwargs):
		username = auth.AccountName
		password = auth.passwd()
		self.protocol = winrm.Protocol(
			endpoint=endpoint,
			transport=transport,
			username=username,
			password=password,
			server_cert_validation=validation,
			**kwargs
		)
		self.target = target
		self.target_auth = (target_auth.WindowsUserName, target_auth.passwd())
