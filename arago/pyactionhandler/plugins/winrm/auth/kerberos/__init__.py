from arago.pyactionhandler.plugins.winrm.session import Session
import winrm, logging


class krb5Session(Session):
	def __init__(self, endpoint, target=None, *args, **kwargs):
		self.protocol = winrm.Protocol(
			endpoint=endpoint,
			transport='kerberos',
			kerberos_delegation=True,
			**kwargs)
		self.target = target
		self.logger = logging.getLogger('root')
