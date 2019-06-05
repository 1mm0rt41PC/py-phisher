#!/usr/bin/env python
#coding: utf8
# 
# Py-Phisher - A simple script for basic phishing by https://github.com/1mm0rt41PC
#
# Filename: Campaign.py
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
from Mail import Mail;
import os,sys;
import csv, sqlite3, json;
from Utils import import4CSV, csvRead, export2CSV;

def getCampaign(parsedArg):
	ml = None;
	if 'campaignId' not in parsedArg or not parsedArg['campaignId']:
		parsedArg['campaignId'] = strftime('%y%m%d%H%M%S');	
		campaignMkdir(parsedArg, 'www');
		if parsedArg['eml']:
			ml = Mail(parsedArg['campaignId'], parsedArg['eml'], parsedArg['getLastTemplate'], parsedArg['credentialsTheft']);
			parsedArg['from-eml'] = parsedArg['eml'];
		else:
			ml = Mail(parsedArg['campaignId'], getLastTemplate=parsedArg['getLastTemplate'], credentialsTheft=parsedArg['credentialsTheft']).getMail(G_login, G_pass);
		parsedArg['eml'] = None;
		ml.saveEML(G_Work+'/'+parsedArg['campaignId']+'/template.eml');
		with open(G_Work+'/'+parsedArg['campaignId']+'/conf.json', 'wb') as fp:
			fp.write(json.dumps(parsedArg, indent=4));
	else:
		ml = Mail(parsedArg['campaignId'], parsedArg['eml'], parsedArg['getLastTemplate'], parsedArg['credentialsTheft']);
	if ('isCron' not in parsedArg or not parsedArg['isCron']) and 'csvUsers' in parsedArg:
		import4CSV(parsedArg);
	return ml;
	

def loadCampaign( campaignId ):
	confFile = G_Work+'/'+campaignId+'/conf.json';
	if not os.path.exists(confFile):
		print('\033[31mThe campaignId '+str(campaignId)+' doesn\'t exist !');
		raise Exception('');		
	with open(confFile, 'rb') as fp:
		return json.load(fp);


def campaignMkdir( parsedArg, d ):
	mkdir(G_Work+'/');
	mkdir(G_Work+'/'+parsedArg['campaignId']);
	if 'www' in parsedArg and parsedArg['www'] and os.path.exists(parsedArg['www']):
		os.symlink(parsedArg['www'], G_Work+'/'+parsedArg['campaignId']+'/'+d);
		print('\033[31m[+] You can put your HTTP website into this folder: '+parsedArg['www']+'\033[0m');
	else:
		mkdir(G_Work+'/'+parsedArg['campaignId']+'/'+d);
		print('\033[31m[+] You can put your HTTP website into this folder: '+G_Work+'/'+parsedArg['campaignId']+'/'+d+'\033[0m');


def mkdir( d ):
	try:
		os.mkdir(d);
	except:
		pass;

		
def addCronTask( parsedArg, mType ):
	task = 'python '+os.path.realpath(sys.argv[0])+' '+serialiseArgs(parsedArg)+' --isCron';
	try:
		mkdir('/etc/cron.hourly');
		with open('/etc/cron.hourly/py-phisher_'+parsedArg['campaignId']+'_'+mType+'.sh', 'wb') as fp:
			fp.write('#!/bin/bash\n');
			fp.write(task+'\n');
		os.chmod('/etc/cron.hourly/py-phisher_'+parsedArg['campaignId']+'_'+mType+'.sh', 0770);
		if mType == 'stats':
			log.info('You can view statics by running the command /etc/cron.hourly/py-phisher_'+parsedArg['campaignId']+'_'+mType+'.sh');
		return True;
	except Exception as e:
		log.critical('Error when creating the task "/etc/cron.hourly/py-phisher_%s_%s.sh" with the script "%s"', parsedArg['campaignId'], mType, task, exc_info=e);
	return False;

	
def rmCronTask( parsedArg, mType ):
	try:
		mkdir('/etc/cron.hourly');
		os.remove('/etc/cron.hourly/py-phisher_'+parsedArg['campaignId']+'_'+mType+'.sh');
		return True;
	except Exception as e:
		log.critical('Error when removing the task "/etc/cron.hourly/py-phisher_%s_%s.sh"', parsedArg['campaignId'], mType, exc_info=e);
	return False;

	
def serialiseArgs(parsedArg):
	ret = '';
	for key in parsedArg:
		if key.startswith('_') or parsedArg[key] == None:
			continue;
		if type(parsedArg[key]) != type(False):
			if ' ' in parsedArg[key]:
				ret += '"--'+key+'='+parsedArg[key]+'" ';
			else:
				ret += '--'+key+'='+parsedArg[key]+' ';
		elif parsedArg[key]:
			ret += '--'+key+' ';
	return ret;