############################################################################
# Copyright [2012] [Mathew Branyon (mat.branyon@readytalk.com)]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
############################################################################

import sqlite3
import ipaddr
import subprocess
import time
import ConfigParser
import urllib

from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta

configFile = '/var/lib/bath/bath.conf'


##############################################################
# returns a dictonary of the main section in the config file #
##############################################################
def getMainConfig():
	config = ConfigParser.ConfigParser()
	config.read(configFile)

	mainConfig= dict()

	try:
		mainConfig['name'] = config.get('main', 'name')
		mainConfig['db'] = config.get('main', 'db')
		mainConfig['logfile'] = config.get('main', 'logfile')
		mainConfig['sudoCommand'] = config.get('main', 'sudoCommand')
		mainConfig['denyRule'] = config.get('main', 'denyRule')
		mainConfig['insertRule'] = config.get('main', 'insertRule')
		mainConfig['deleteRule'] = config.get('main', 'deleteRule')
		mainConfig['showRule'] = config.get('main', 'showRule')
		mainConfig['userHistoryLimit'] = config.get('main', 'userHistoryLimit')
		mainConfig['adminHistoryLimit'] = config.get('main', 'adminHistoryLimit')
		mainConfig['monitorUser'] = config.get('main', 'monitorUser')
		mainConfig['host'] = config.get('main', 'host')
		mainConfig['port'] = config.getint('main', 'port')
	except ConfigParser.NoOptionError as error:
		print "Error reading config file ({0}): " . format(configFile), error
		sys.exit(1)

	for option in config.options('main'):
		mainConfig[option] = config.get('main', option)
  
	return mainConfig


#############################################
# returns a dictonary of dictionaries       #
# containing the application config options #
#############################################
def getAppConfig(): 
	config = ConfigParser.ConfigParser()
	config.read(configFile)
	appConfig = dict()

	for section in config.sections():
		if section != 'main' and config.getboolean(section, 'enabled'):
			try:
				appConfig[section] = dict()
				appConfig[section]['port'] = config.get(section, 'port')
				appConfig[section]['ttl'] = config.get(section, 'ttl')
			except ConfigParser.NoOptionError as error:
				print "Error reading config file ({0}): " . format(configFile), error
				sys.exit(1)

	if len(appConfig):
		return appConfig
	else:
		print "No applications are defined for use: nothing to do here"
		sys.exit(2)


##########################
# returns remote address #
##########################
def get_client_ip(req):
	req.add_common_vars()
	return req.subprocess_env['REMOTE_ADDR']


#####################################
# returns apache authenticated name #
#####################################
def get_user_name(req):
	mainConfig = getMainConfig()
	req.add_common_vars()
	if  get_client_ip(req) == '127.0.0.1':
		return mainConfig['monitorUser']
	else:
		return req.subprocess_env['AUTHENTICATE_UID']


################################################
# Ensures that the database is set up properly #
################################################
def create_db():
	mainConfig = getMainConfig()
	# db connection stuff
	dbconnection = sqlite3.connect(mainConfig['db'])
	dbcursor = dbconnection.cursor()

	# Create connection databases
	dbcursor.execute('''
		CREATE TABLE IF NOT EXISTS connections (
			id INTEGER PRIMARY KEY, 
			app TEXT NOT NULL,
			user TEXT NOT NULL, 
			firewall_ip TEXT NOT NULL, 
			user_ip TEXT NOT NULL, 
			timestamp TEXT NOT NULL, 
			comment TEXT)''')
	dbcursor.execute('CREATE INDEX IF NOT EXISTS connections_user_idx ON connections (user)')
	dbcursor.execute('CREATE INDEX IF NOT EXISTS connections_firewall_ip_idx ON connections (firewall_ip)')

	# Create ConnectionBlacklist database
	dbcursor.execute('''
		CREATE TABLE IF NOT EXISTS blacklist (
			ip text UNIQUE,
			app text,
			enabled INTEGER)''')

	# Create admin database
	dbcursor.execute('''
		CREATE TABLE IF NOT EXISTS admin (
			user text UNIQUE,
			enabled INTEGER)''')

	# Commit our changes
	dbconnection.commit()
	# Close our cursor and connections
	dbcursor.close()
	dbconnection.close()


##############################################
# Creates firewall rule and logs to database #
##############################################
def create_connection(app, user, firewall_ip, user_ip, comment):
	mainConfig = getMainConfig()

	comment = urllib.unquote_plus(comment)

	# Database connection stuff
	dbconnection = sqlite3.connect(mainConfig['db'])
	dbcursor = dbconnection.cursor()

	# If this ip is blacklisted, ABORT!
	dbcursor.execute('''
		SELECT ip 
		FROM blacklist
		WHERE enabled = 1
			AND (app = ?
				OR app IS NULL)''', (app, ))

	for row in dbcursor.fetchall():
		if ipaddr.IPv4Address(firewall_ip) in ipaddr.IPv4Network(row[0]):
			blacklisted_ip = row[0]
			dbcursor.close()  
			dbconnection.close()
			if user == mainConfig['monitorUser']:
				return "FAIL: BLACKLIST\n"
			else:
				return "BLACKLIST: " + firewall_ip + " matches blacklist entry for" + blacklisted_ip

	# Make sure we don't already have a rule for this ip
	# If we do, fail the process
	if any(connection['ip'] == firewall_ip for connection in get_active_connections(app)):
		if user == mainConfig['monitorUser']:
			return "FAIL: PREVIOUS MONITOR RULE EXISTS\n"
		else:
			return "Active Connection already exists for " + firewall_ip

	timestamp = datetime.now()

	# GREAT SUCCESS: almost
	dbcursor.execute('''
		INSERT INTO connections 
		(app, user, firewall_ip, user_ip, timestamp, comment)
		VALUES (?, ?, ?, ?, ?, ?)''' , (app, user, firewall_ip, user_ip, timestamp, comment))

	appConfig = getAppConfig()
	iptablescomment = "--match comment --comment \"{0}|{1}|{2}|{3}|{4}\"" . format(mainConfig['name'], app, dbcursor.lastrowid, user, timestamp)

	try:
		subprocess.Popen(["{0} {1} {2}/32 {3}" . format(mainConfig['sudoCommand'], str.replace(mainConfig['insertRule'], '?', appConfig[app]['port']), firewall_ip, iptablescomment)], shell=True)
		if user != mainConfig['monitorUser']:
			dbconnection.commit()
	except subprocess.CalledProcessError as error:
		if user == mainConfig['monitorUser']:
			return "FAIL: CANNOT ADD RULE - {0}\n" . format(str(error))
		else:
			dbcursor.close()
			dbconnection.close()
			return "Failed to add " + app + " rule for " + firewall_ip + " " + str(error)
	
	if user == mainConfig['monitorUser']:
		return "SUCCESS: Rule Created\n"
	else:
		dbcursor.close()
		dbconnection.close()
		return app + " Connection Added Successfully: Added " + firewall_ip + ".\nYou have 2 minutes to log in." 


###################################################################
# Returns true if the authenticated user is in the admin database #
###################################################################
def is_admin(user):
	mainConfig = getMainConfig()
	# Database connection stuff
	dbconnection = sqlite3.connect(mainConfig['db'])
	dbcursor = dbconnection.cursor()

	dbcursor.execute('''
		SELECT enabled
		FROM admin
		WHERE user = ?''', (user, ))

	result = dbcursor.fetchone()

	dbcursor.close()
	dbconnection.close()

	if result and result[0] == 1:
		return True
	else:
		return False


##########################################
# returns list of all active connections #
##########################################
def get_all_active_connections():
	appConfig = getAppConfig()
	activeConnections = list()

	for app in appConfig:
		activeConnections += get_active_connections(app)

	return activeConnections


##########################################
# returns list of active connections #
##########################################
def get_active_connections(app):
	mainConfig = getMainConfig()
	appConfig = getAppConfig()

	activeConnections = list()
	try:
		output = subprocess.Popen(["{0} {1}" .format(mainConfig['sudoCommand'], mainConfig['showRule'])], shell=True, stdout=subprocess.PIPE).communicate()[0]
		for line in output.splitlines():
			if line.startswith('ACCEPT'):
				part = line.split()
				if part[10].startswith("{0}|{1}|" . format(mainConfig['name'], app)):
					comment = part[10].split('|')
					appName = comment[1]
					if app == appName:
						ip = part[3]
						name = comment[0]
						port = appConfig[appName].get('port')
						id = comment[2]
						user =comment[3]
						timestamp = "{0} {1}" .format(comment[4], part[11])

						timeleft = 'unknown'
						then = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
						if (datetime.now() - then) > timedelta(minutes=int(appConfig[appName].get('ttl'))):
							timeleft = 'expired'
						else:
							timeleftDate = relativedelta(then + timedelta(minutes=int(appConfig[appName].get('ttl'))), datetime.now())
							timeleft = "{0} min {1} sec" . format(timeleftDate.minutes, timeleftDate.seconds)

						activeConnections.append({'ip':ip, 'port':port, 'comment':comment, 'name':name, 'app':app, 'id':id, 'user':user, 'timestamp':timestamp, 'timeleft':timeleft})
	except subprocess.CalledProcessError as error:
		# probably do something here
		pass

	return activeConnections

##########################################
# Returns Table (html) of previous       # 
# userHistoryLimit connections from user #
##########################################
def get_user_history(user=None):
	mainConfig = getMainConfig()

	# Database connection stuff
	dbconnection = sqlite3.connect(mainConfig['db'])
	dbcursor = dbconnection.cursor()


	table = "<table>"
	if user:
		table += '''
	<caption>Connection History</caption>'''
	else:
		table += '''
	<caption>Admin Connection History</caption>'''
	
	table += """
	<tr>
		<th>App</th>
		<th>IP Request FROM</th>
		<th>IP Request FOR</th>
		<th>Timestamp</th>
		<th>Time Left</th>
		<th>Comment</th>
	</tr>"""

	
	select = 'SELECT app, firewall_ip, user_ip, timestamp, comment FROM connections '
	parameters = list()

	if user:
		select += 'WHERE user=? '  
		parameters.append(user)

	select += 'ORDER BY timestamp DESC LIMIT ?'''

	parameters.append(mainConfig['userHistoryLimit'])
		
	dbcursor.execute(select, parameters)
		
	history = dbcursor.fetchall()
	connections = get_all_active_connections()
	
	for row in history:
		active = False
		timeleft = '-'
		for connection in connections:
			if connection['timestamp'] == row[3]:
				active = True
				break
		if active:
			timeleft = connection['timeleft']
			table += """	
	<tr bgcolor="lightgreen">"""
		else:
			table += """
	<tr>"""
		table += """
		<td>{0}</td>
		<td>{1}</td>
		<td>{2}</td>
		<td>{3}</td>
		<td>{4}</td>
		<td>{5}</td>
	</tr>""" . format(row[0], row[1], row[2], row[3], timeleft, row[4])

	table += "</table><br>"

	dbcursor.close()
	dbconnection.close()
	return table


##########################################################
# returns a table for current connections for admin user #
##########################################################
def admin_get_current_activity():
	appConfig = getAppConfig()

	table = """
<table><caption>Active Connections</caption>
	<tr>
		<th>App</th>
		<th>User</th>
		<th>IP</th>
		<th>Time Left</th>
		<th>Timestamp</th>
	</tr>"""

	for row in get_all_active_connections():
		table += """
	<tr>
		<td>{0}</td>
		<td>{1}</td>
		<td>{2}</td>""" . format(row['app'], row['user'], row['ip'])

		then = datetime.strptime(row['timestamp'], "%Y-%m-%d %H:%M:%S.%f")
		if (datetime.now() - then) > timedelta(minutes=int(appConfig[row['app']].get('ttl'))):
			table += """
		<td style=\"color:red\">expired</td>"""
		else:
			timeleft= relativedelta(then + timedelta(minutes=int(appConfig[row['app']].get('ttl'))), datetime.now())
				
			table += """
		<td>{0} min {1} sec</td>""" . format(timeleft.minutes, timeleft.seconds)

			table += """
		<td>{0}</td>""" . format(row['timestamp'])
		
	table += """
	</tr>
</table><br>"""
	return table

########################################################
# Returns integer of successful connections since time #
########################################################
def connections_since(time=0):
	mainConfig = getMainConfig()
	# Database connection stuff
	dbconnection = sqlite3.connect(mainConfig['db'])
	dbcursor = dbconnection.cursor()

	dbcursor.execute('''
		SELECT COUNT(id) as number
		FROM sshConnection
		WHERE strftime('%s',timestamp) > ?''', (time, ))

	result = dbcursor.fetchone()

	dbcursor.close()
	dbconnection.close()

	return result[0]


###########################################
# returns true if the master rules exists #
###########################################
def verify_master_rules(logger):
	mainConfig = getMainConfig()
	appConfig = getAppConfig()
	for app in appConfig:
		try:
			output = subprocess.Popen([mainConfig['sudoCommand'] + " " + mainConfig['showRule']], shell=True, stdout=subprocess.PIPE).communicate()[0]
		except subprocess.CalledProcessError as error:
			return False

		'''Find master rule. Create if not found'''
		foundMaster = False
		for line in output.splitlines():
			part = line.split()
			if len(part) >= 10 and part[10].startswith('{0}|master|{1}' . format(mainConfig['name'], app)):
				foundMaster = True
	
		if foundMaster is False:
			try:
				logger.info("adding master deny rule: {0}|master|{1}" . format(mainConfig['name'], app))
				subprocess.check_call(["{0} {1} \"{2}|master|{3}\"" . format(mainConfig['sudoCommand'], str.replace(mainConfig['denyRule'], '?', appConfig[app]['port']), mainConfig['name'], app)], shell=True)
			except subprocess.CalledProcessError as error:
				logger.error(str(error))
				return False

		'''find allow rules. create if not found'''
		if 'allowedNetworks' in appConfig[app]:
			for allowRule in appConfig[app]['allowedNetworks'].split(','):
				foundRule = False
				for line in output.splitlines():
					part = line.split()
					if len(part) >= 10 and part[10].startswith("{0}|master|{1}|{2}" . format(mainConfig['name'], app, allowRule)):
						foundRule = True

				if foundRule is False:
					try:
						logger.info("adding master allow rule: {0}|master|{1}|{2}" . format(mainConfig['name'], app, allowRule))
						subprocess.check_call(["{0} {1} {2} --match comment --comment \"{3}|master|{4}|{5}\"" . format(mainConfig['sudoCommand'], str.replace(mainConfig['insertRule'], '?', appConfig[app]['port']), allowRule, mainConfig['name'], app, allowRule)], shell=True)
					except subprocess.CalledProcessError as error:
						logger.error(str(error))
						return False

	return True


#################################################
# returns html and header with css and all that #
#################################################
def get_html_header():
	return """
<html>
	<head>
		<link href="style.css" rel="stylesheet" type="text/css">
	</head>
<body>"""
