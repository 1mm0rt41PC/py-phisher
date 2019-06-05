#!/usr/bin/env python
#coding: utf8
# 
# Py-Phisher - A simple script for basic phishing by https://github.com/1mm0rt41PC
#
# Filename: Utils.py
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
import csv,sys,sqlite3,json,re;


class hexProtect:
	_inp = list('0123456789abcdef');
	_out = list('_rtyuiopqsghjklm');
	@staticmethod
	def enc(payload):
		# On encode le payload:
		for i in xrange(0,len(hexProtect._inp)):
			payload = payload.replace(hexProtect._inp[i],hexProtect._out[i]);
		return payload;
	@staticmethod
	def dec(payload):
		# On decode le payload:
		for i in xrange(0,len(hexProtect._inp)):
			payload = payload.replace(hexProtect._out[i],hexProtect._inp[i]);
		return payload;


def parseHostname( host, date='' ):
	log.debug('Parsing DNS log...');
	host	   = host.split('.');
	msg		   = '';
	campaignId = '';
	email	   = '';
	type       = host[0];
	try:
	
		if type == 'open':
			# open.hex.hex....evildomain.fr
			# hex = _campaignId $ EmailAddress
			campaignId, email = hexProtect.dec(''.join(host[1:-2])).decode('hex').split('$');
			if not os.path.exists(G_Work+'/'+campaignId+'/emails.db'):
				raise Exception('Invalid campaignId: '+campaignId);
			msg = 'opened email';
		elif type == 'ropen':
			# open.hex.hex....responder.evildomain.fr
			# hex = _campaignId $ EmailAddress
			campaignId, email = hexProtect.dec(''.join(host[1:-3])).decode('hex').split('$');
			if not os.path.exists(G_Work+'/'+campaignId+'/emails.db'):
				raise Exception('Invalid campaignId: '+campaignId);
			msg = 'opened email';
		elif type == 'vba':
			# vba.hex.hex....evildomain.fr
			# hex = ActiveDocument.Name & "$" & Environ("userdomain") & "\" & Environ("username") &"$" & getFromO365("EmailAddress")
			host  = ''.join(host[1:-2]);
			login = '';
			doc   = '';
			try:
				doc, login, email = host.decode('hex').split('$')
			except:
				doc, login, email = hexProtect.dec(''.join(host[1:-2])).decode('hex').split('$');
			# Concours_xxxxx_${CAMPAIGN_ID}.doc
			campaignId = '.'.join(doc.split('_')[-1].split('.')[:-1]);
			if not os.path.exists(G_Work+'/'+campaignId+'/emails.db'):
				raise Exception('Invalid campaignId: '+campaignId);
				
			if (email == 'unk@unk.unk' or not email) and login:
				email = login;
			updateRow(campaignId, email, 'other', val=login);
			msg = 'executed VBA and has login '+login;
			
		else:
			raise Exception('Invalid type: '+type);
			
		if date:
			updateRow(campaignId, email, type, val=date);
			log.info('[%s] User %s %s at %s', campaignId, email, msg, date);
		else:
			updateRow(campaignId, email, type, func='datetime("now","localtime")');
			log.info('[%s] User %s %s', campaignId, email, msg);
	except Exception as e:
		#log.critical(str(e), exc_info=e);
		log.debug(str(e), exc_info=e);

		
def pretty_csv(filename):
	column_max_width = [];
	with open(filename, "rb") as input: #parse the file and determine the width of each column
		for row in csv.reader(input, delimiter=';'):
			iCol = 0;
			for column in row:
				width = len(column);
				try:
					if width > column_max_width[iCol]:
						column_max_width[iCol] = width
				except:
					column_max_width += [width];
				iCol += 1;

	def drawLine():
		sys.stderr.write('|');
		iCol = 0;
		for col in column_max_width:
			sys.stderr.write('-'*(col+2));
			if len(column_max_width) != iCol+1:
				sys.stderr.write('+');
			iCol += 1;
		sys.stderr.write('|\n');
	out = sys.stdout;
	with open(filename, "rb") as input: #parse the file and determine the width of each column
		drawLine();
		iRow = 0;
		for row in csv.reader(input, delimiter=';'):
			iCol = 0;
			if iRow == 0:
				out = sys.stderr;
			else:
				out = sys.stdout;
			out.write('| ');
			for col in row:
				out.write(('%-'+str(column_max_width[iCol])+'s')%(col));
				if len(column_max_width) != iCol+1:
					out.write(' | ');
				iCol += 1;
			out.write(' |\n');
			out.flush();
			if iRow == 0:
				drawLine();
			iRow += 1;
		drawLine();

		
def updateRow( campaignId, email_id, field, val=None, func=None ):
	if not os.path.exists(G_Work+'/'+campaignId+'/emails.db'):
		raise Exception('Database(%s) not found'%(G_Work+'/'+campaignId+'/emails.db'));
		
	if field not in ['email','lastname','firstname','group1','group2','group3','open','vba','link','form','other']:
		raise Exception('Invalid field value: '+str(field));
		
	if not func and not val:
		raise Exception('updateRow require val or func');
		
	emailField = 'email';
	try:
		int(email_id, 10);
		emailField = 'rowid';
	except:
		pass;
		
	with sqlite3.connect(G_Work+'/'+campaignId+'/emails.db') as con:
		cur = con.cursor();		
		cur.execute('INSERT OR IGNORE INTO db (%s,lastname) VALUES(?,"py-phisher")'%(emailField), [email_id]);
		if field == 'other':
			cur.execute('UPDATE db SET other=(other||"\n"||?) WHERE %s=?;'%(emailField), [val, email_id]);
		elif val:
			cur.execute('UPDATE db SET %s=? WHERE %s=?;'%(field,emailField), [val, email_id]);
		elif func:
			cur.execute('UPDATE db SET %s=%s WHERE %s=?;'%(field, func, emailField), [email_id]);
		
		if field in ['vba','link','form']:
			cur.execute('UPDATE db SET open=%s WHERE %s=? AND (open="" OR open IS NULL);'%(field,emailField), [email_id]);

			
def csvRead( filename, ignoreFirstList=False ):
	with open(filename,'rb') as fp:
		if ignoreFirstList:
			fp.readline();# On supprime la première ligne
		for dr in csv.reader(fp, delimiter=';'): # comma is default
			if not dr or len(dr) == 0 or len(dr) == 1:
				continue;
			yield dr;


def readDB( parsedArg ):
	with sqlite3.connect(G_Work+'/'+parsedArg['campaignId']+'/emails.db') as connection:			
		cur = connection.cursor()
		cur.execute('SELECT rowid,email,lastname,firstname,group1,group2,group3,open,vba,link,form,other FROM db;') # use your column names here
		for row in cur.fetchall():
			row = list(row);
			for i in xrange(0,len(row)):
				if row[i] == None:
					row[i] = '';
			yield {
				'id': row[0],
				'email':row[1],
				'lastname':row[2],
				'firstname':row[3],
				'group1':row[4],
				'group2':row[5],
				'group3':row[6],
				'open':row[7],
				'vba':row[8],
				'link':row[9],
				'form':row[10],
				'other':row[11],
			};
		

def export2CSV( parsedArg ):
	log.info('Export sqlite3 to CSV');
	mFile = G_Work+'/'+parsedArg['campaignId']+'/'+strftime('%Y-%m-%d')+'_PhishingStats_'+parsedArg['client']+'.csv';
	db = G_Work+'/'+parsedArg['campaignId']+'/emails.db';
	if not os.path.exists(db):
		raise Exception('Database(%s) not found'%(db));	
	with sqlite3.connect(db) as connection:
		csvWriter = csv.writer(open(mFile, 'w'), delimiter=';')
		cur = connection.cursor()
		cur.execute('SELECT * FROM db;') # use your column names here
		csvWriter.writerow(['email','lastname','firstname','group1','group2','group3','open','vba','link','form','other']);
		for row in cur.fetchall():
			csvWriter.writerow(row);
			
	log.info('Export saved in '+mFile);
	return mFile;
			

def import4CSV( parsedArg ):
	log.info('Import CSV to sqlite3');
	if 'csvUsers' not in parsedArg or not parsedArg['csvUsers']:
		log.info('Import CSV to sqlite3 ignored with reason "empty csvUsers arguement"');
		return False;
	if os.path.exists(G_Work+'/'+parsedArg['campaignId']+'/emails.db'):
		os.remove(G_Work+'/'+parsedArg['campaignId']+'/emails.db');
	con = sqlite3.connect(G_Work+'/'+parsedArg['campaignId']+'/emails.db');
	cur = con.cursor();
	cur.execute('CREATE TABLE db(email VARCHAR(255) PRIMARY KEY, lastname, firstname, group1, group2, group3, open, vba, link, form, other);') # use your column names here

	if os.path.exists(parsedArg['csvUsers']):
		for row in csvRead(parsedArg['csvUsers'], ignoreFirstList=1):
			try:
				cur.execute('INSERT INTO db (email, lastname, firstname, group1, group2, group3, open, vba, link, form, other) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);', row);
			except:
				try:
					cur.execute('INSERT INTO db (email, lastname, firstname, group1, group2, group3) VALUES (?, ?, ?, ?, ?, ?);', row);
				except Exception as e:
					log.error(str(e));
					log.error('row='+str(row));
	else:
		log.info('Oneshot mode with only one email, making the database...');
		cur.execute('INSERT INTO db (email) VALUES (?);', parsedArg['csvUsers'].split(','))
	con.commit();
	con.close();
	

def getStatsFromDB( parsedArg, retJson=False ):
	if not os.path.exists(G_Work+'/'+parsedArg['campaignId']+'/emails.db'):
		raise Exception('No database for this campaignId !');
	stats = {
		'global' : {
			'nb': 0,
			'open': 0,
			'link': 0,
			'form': 0,
			'vba': 0,
		},
		'group1' : {
			#<groupname>: {
			#	'nb': 0,
			#	'open': 0,
			#	'link': 0,
			#	'form': 0,
			#	'vba': 0,
			#}
		},
		'group2' : {
		},
		'group3' : {
		}
	};
	def gn( groupName ):
		if groupName not in stats[grp]:
			stats[grp][groupName] = {
				'nb': 0,
				'open': 0,
				'link': 0,
				'vba': 0,
				'form': 0,
			};
		return stats[grp][groupName];
	with sqlite3.connect(G_Work+'/'+parsedArg['campaignId']+'/emails.db') as connection:			
		cur = connection.cursor()
		cur.execute('SELECT COUNT(*) FROM db WHERE lastname<>"py-phisher";') # use your column names here
		stats['global']['nb'] = cur.fetchall()[0][0];
		cur.execute('SELECT COUNT(*) FROM db WHERE open<>"";') # use your column names here
		stats['global']['open'] = cur.fetchall()[0][0];
		cur.execute('SELECT COUNT(*) FROM db WHERE link<>"";') # use your column names here
		stats['global']['link'] = cur.fetchall()[0][0];
		cur.execute('SELECT COUNT(*) FROM db WHERE form<>"";') # use your column names here
		stats['global']['form'] = cur.fetchall()[0][0];
		cur.execute('SELECT COUNT(*) FROM db WHERE vba<>"";') # use your column names here
		stats['global']['vba'] = cur.fetchall()[0][0];
		
		for grp in ['group1','group2','group3']:
			cur.execute('SELECT '+grp+',COUNT(*) FROM db WHERE '+grp+' IS NOT NULL AND '+grp+'<>"" GROUP BY '+grp) # use your column names here
			allRows = cur.fetchall();
			if len(allRows) == 1:
				continue;
			for row in allRows:
				groupName,nb = row;
				gn(groupName)['nb'] = nb;
			
			for mType in ['open','link','form','vba']:
				cur.execute('SELECT '+grp+',COUNT(*) FROM db WHERE '+grp+' IS NOT NULL AND '+grp+'<>"" AND '+mType+'<>"" GROUP BY '+grp) # use your column names here
				allRows = cur.fetchall();
				for row in allRows:
					groupName,nb = row;
					gn(groupName)[mType] = nb;
					
					
	statshtml = (open(os.path.dirname(os.path.realpath(__file__))+'/../template/Stats_'+parsedArg['from'].split('@')[1]+'.html','rb').read()
		.replace('"%STATS%"', json.dumps(stats))
		.replace('%client%', parsedArg['client'])
		.replace('%date%', strftime('%Y-%m-%d'))
		.replace('%from%', parsedArg['from'])
	)
	with open(G_Work+'/'+parsedArg['campaignId']+'/'+strftime('%Y-%m-%d')+'_PhishingStats_'+parsedArg['client']+'.html', 'w') as fp:
		fp.write(statshtml);
		log.info('Saving stats in '+G_Work+'/'+parsedArg['campaignId']+'/'+strftime('%Y-%m-%d')+'_PhishingStats_'+parsedArg['client']+'.html');
	if retJson:
		return stats;
	return statshtml;

	
def userEmail( campaignId, uid ):
	with sqlite3.connect(G_Work+'/'+campaignId+'/emails.db') as connection:			
		cur = connection.cursor()
		cur.execute('SELECT email FROM db WHERE rowid=?;', [uid]) # use your column names here
		return cur.fetchall()[0][0];
		

def getUsersInfo( campaignId, uid ):
	with sqlite3.connect(G_Work+'/'+campaignId+'/emails.db') as connection:			
		cur = connection.cursor()
		cur.execute('SELECT email FROM db WHERE rowid=? OR email=?;', [uid,uid]) # use your column names here
		row = cur.fetchall()[0];
		return {
			'id': row[0],
			'email':row[1],
			'lastname':row[2],
			'firstname':row[3],
			'group1':row[4],
			'group2':row[5],
			'group3':row[6],
			'open':row[7],
			'vba':row[8],
			'link':row[9],
			'form':row[10],
			'other':row[11],
		};
	

def urlencode( data ):
	data = list(data);
	for i in xrange(0,len(data)):
		tmp = ord(data[i]);
		if not ((ord('0') <= tmp and tmp <= ord('9')) or (ord('a') <= tmp and tmp <= ord('z')) or (ord('A') <= tmp and tmp <= ord('Z')) or tmp == ord('_')):
			data[i] = '%%%02x'%(tmp);
	return ''.join(data);
	
def urldecode(data):
	def repl(m):
		return m.group(1)[1:].decode('hex');
	return re.sub('(%[a-fA-F0-9]{2})', repl, data);