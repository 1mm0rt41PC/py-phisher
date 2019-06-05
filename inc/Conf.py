#!/usr/bin/env python
#coding: utf8
# 
# Py-Phisher - A simple script for basic phishing by https://github.com/1mm0rt41PC
#
# Filename: Conf.py
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
import logging;
from logging.handlers import RotatingFileHandler;
import os;

G_LogFile   = os.path.realpath('/var/log/py-phisher.log');
G_Work      = os.path.realpath(os.path.realpath(__file__)+'/../../campaign/');
G_HTTP_LOG  = os.path.realpath('/var/log/py-phisher_www.log');
G_HTTP_PORT = 80;
G_USER_UID  = 65534;# nobody (/etc/passwd)
G_USER_GID  = 65534;# nobody (/etc/passwd)


G_login    = None;
if 'o365_login' in os.environ:
	G_login = os.environ['o365_login'];
G_pass     = None;
if 'o365_pass' in os.environ:
	G_pass = os.environ['o365_pass'];


def iniLog( name, logfile ):
	logLevel = logging.INFO;
	lg = logging.getLogger(name);
	lg.setLevel(logLevel);
	stdoutHandler = logging.StreamHandler();
	_formatter = logging.Formatter('[%(asctime)s][%(levelname)s][%(filename)s:%(lineno)3d] %(message)s')
	stdoutHandler.setFormatter(_formatter);
	stdoutHandler.setLevel(logLevel);
	lg.addHandler(stdoutHandler);
	# création d'un handler qui va rediriger une écriture du log vers
	# un fichier en mode 'append', avec 7 backup et une taille max de 10Mo
	fileHandler = RotatingFileHandler( logfile, 'a', 1000000*10, backupCount=7 );
	fileHandler.setFormatter(_formatter);
	lg.addHandler(fileHandler);
	return lg;

log = iniLog(__name__, G_LogFile);
