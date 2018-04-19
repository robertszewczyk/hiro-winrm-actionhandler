from arago.pyactionhandler.plugins.winrm.session import Session
import gevent
import gevent.subprocess
import winrm, logging
import re
import xml.etree.ElementTree as ET

from requests_kerberos.exceptions import KerberosExchangeError


class krb5Session(Session):
	def __init__(self, endpoint, username, keytab, num=1, target=None, *args, **kwargs):
		self.num=num
		for i in range(3):
			try:
				self.protocol = winrm.Protocol(
					endpoint=endpoint,
					transport='kerberos',
					kerberos_delegation=True,
					**kwargs)
				self.target = target
				self.logger = logging.getLogger('root')
				test_msg = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>"""
				test_resp = self.protocol.send_message(test_msg)
				#print(test_resp)
				test_resp_xml = ET.fromstring(test_resp.decode('utf-8'))
				self.logger.debug(
					"[{anum}] Connected to WSMAN service at {host}, Vendor: {ven}, Version: {ver}".format(
						anum=num, host=endpoint,
						ven=test_resp_xml.findtext(
							".//{http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd}ProductVendor"),
						ver=test_resp_xml.findtext(
							".//{http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd}ProductVersion")
					))
				break
			except KerberosExchangeError as e:
				parsed_err = self.parse_krb5_err(str(e))
				if (parsed_err == "Ticket expired"
					or (parsed_err.startswith("Credentials cache file ") and parsed_err.endswith(" not found"))):
					self.logger.warning("[{anum}] No Kerberos ticket for {host}, requesting one ...".format(
						anum=self.num, host=endpoint))
					try:
						with open(keytab):
							pass
						gevent.subprocess.check_output(
							["kinit", "-k", "-t", keytab, username],
							timeout=30, stderr=gevent.subprocess.STDOUT)
						self.logger.info("[{anum}] Successfully retrieved Kerberos ticket for {host}, retrying command execution.".format(
							anum=self.num, host=endpoint))
					except gevent.subprocess.CalledProcessError as e:
						self.logger.error("[{anum}] Retrieving Kerberos ticket for {host} failed: {err}".format(
							anum=self.num, host=endpoint, err=e.output.decode("utf-8")))
					except gevent.subprocess.TimeoutExpired as e:
						self.logger.error("[{anum}] Retrieving Kerberos ticket for {host} timed out!".format(
							anum=self.num, host=endpoint))
					except FileNotFoundError as e:
						self.logger.error("[{anum}] Retrieving Kerberos ticket for {host} failed: {err}".format(
							anum=self.num, host=endpoint, err=e))
					except KeyError:
						self.logger.error("[{anum}] Retrieving Kerberos ticket for {host} failed! Credentials missing!".format(
							anum=self.num, host=endpoint))
					continue
				elif parsed_err:
					self.logger.error("[{anum}] An error occured during command execution on {node}: Kerberos: {err}".format(
						anum=self.num, node=self.node, err=parsed_err))
					self.statusmsg = parsed_err
				else:
					self.logger.error("[{anum}] An error occured during command execution on {node}: Kerberos: {err}".format(
						anum=self.num, node=self.node, err=str(e)))


	def parse_krb5_err(self, err):
		result = re.search(r"authGSSClientStep\(\) failed: \(\((?P<q1>'|\")(?P<major_desc>.+)(?P=q1), (?P<major_code>-?[\d]+)\), \((?P<q2>'|\")(?P<minor_desc>.+)(?P=q2), (?P<minor_code>-?[\d]+)\)\)", err)
		return result.group('minor_desc') if result else None
