import sqlite3
import ipaddr
import subprocess
import time

from datetime import datetime, timedelta
from config import *


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
	req.add_common_vars()
	if  get_client_ip(req) == '127.0.0.1':
		return monitorUser
	else:
		return req.subprocess_env['AUTHENTICATE_UID']


################################################
# Ensures that the database is set up properly #
################################################
def create_db():
	# db connection stuff
	dbconnection = sqlite3.connect(db)
	dbcursor = dbconnection.cursor()

	# Create sshConnection database
	dbcursor.execute('''
		CREATE TABLE IF NOT EXISTS sshConnection (
			id INTEGER PRIMARY KEY, 
			user TEXT NOT NULL, 
			firewall_ip TEXT NOT NULL, 
			user_ip TEXT NOT NULL, 
			timestamp TEXT NOT NULL, 
			comment TEXT, 
			enabled INTEGER)''')
	dbcursor.execute('CREATE INDEX IF NOT EXISTS user_idx ON sshConnection (user)')
	dbcursor.execute('CREATE INDEX IF NOT EXISTS firewall_ip_idx ON sshConnection (firewall_ip)')

	# Create sshConnectionBlacklist database
	dbcursor.execute('''
		CREATE TABLE IF NOT EXISTS blacklist (
			ip text UNIQUE,
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
def create_ssh_connection(user, firewall_ip, user_ip, comment):

	# Database connection stuff
	dbconnection = sqlite3.connect(db)
	dbcursor = dbconnection.cursor()

	# If this ip is blacklisted, ABORT!
	dbcursor.execute('''
		SELECT ip 
		FROM blacklist
		WHERE enabled = 1''')

	for row in dbcursor.fetchall():
		if ipaddr.IPv4Address(firewall_ip) in ipaddr.IPv4Network(row[0]):
			blacklisted_ip = row[0]
			dbcursor.close()  
			dbconnection.close()
			if user == monitorUser:
				return "FAIL: BLACKLIST\n"
			else:
				return "BLACKLIST: " + firewall_ip + " matches blacklist entry for" + blacklisted_ip

	# Make sure we don't already have a rule for this ip
	# If we do, fail the process
	if any(connection['ip'] == firewall_ip for connection in get_active_ssh_connections()):
		if user == monitorUser:
			return "FAIL: PREVIOUS MONITOR RULE EXISTS\n"
		else:
			return "Active Connection already exists for " + firewall_ip

	timestamp = datetime.now()

	# GREAT SUCCESS: almost
	dbcursor.execute('''
		INSERT INTO sshConnection 
		(user, firewall_ip, user_ip, timestamp, comment, enabled)
		VALUES (?, ?, ?, ?, ?, ?)
		''', (user, firewall_ip, user_ip, timestamp, comment, 1))

	iptablescomment = "--match comment --comment \"bath|ssh|{0}|{1}|{2}\"" . format(dbcursor.lastrowid, user, timestamp)

	try:
		subprocess.Popen(["{0} {1}{2}/32 {3}" .format(sudoCommand, sshFirewallCommand, firewall_ip, iptablescomment)], shell=True)
		if user != monitorUser:
			dbconnection.commit()
	except subprocess.CalledProcessError as error:
		if user == monitorUser:
			return "FAIL: CANNOT ADD RULE - {0}\n" . format(str(error))
		else:
			dbcursor.close()
			dbconnection.close()
			return "Failed to add firewall rule for " + firewall_ip + " " + str(error)
	
	if user == monitorUser:
		return "SUCCESS: Rule Created\n"
	else:
		dbcursor.close()
		dbconnection.close()
		return "Connection Added Successfully: Added " + firewall_ip + ".\nYou have 2 minutes to log in." 


###################################################################
# Returns true if the authenticated user is in the admin database #
###################################################################
def is_admin(user):
	# Database connection stuff
	dbconnection = sqlite3.connect(db)
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
# returns list of active ssh connections #
##########################################
def get_active_ssh_connections():
	activeConnections = list()
	try:
		output = subprocess.Popen(["{0} {1}" .format(sudoCommand, firewallShowCommand)], shell=True, stdout=subprocess.PIPE).communicate()[0]
		for line in output.splitlines():
		#for line in output.stdout.readlines():
			if line.startswith('ACCEPT'):
				part = line.split()
				if part[10].startswith("{0}|{1}|" . format(appName, appProto)):
					ip = part[3]
					comment = part[10].split('|')
					app = comment[0]
					if (app == appName):
						proto = comment[1]
						id = comment[2]
						user =comment[3]
						timestamp = "{0} {1}" .format(comment[4], part[11])
						activeConnections.append({'ip':ip, 'comment':comment, 'app':app, 'proto':proto, 'id':id, 'user':user, 'timestamp':timestamp})
	except subprocess.CalledProcessError as error:
		# probably do something here
		pass

	return activeConnections

############################################
# Returns Table (html or text) of previous # 
# userHistoryLimit connections from user   #
############################################
def get_user_history(user, contentType,):
	# Database connection stuff
	dbconnection = sqlite3.connect(db)
	dbcursor = dbconnection.cursor()

	dbcursor.execute('''
		SELECT firewall_ip, user_ip, timestamp, comment 
		FROM sshConnection 
		WHERE user=? 
		ORDER BY timestamp DESC 
		LIMIT ?''', (user, userHistoryLimit))

	history = dbcursor.fetchall()

	if contentType == 'text/html':
		table = """
<table><caption>Connection History</caption>
	<tr>
		<th>IP Request FROM</th>
		<th>IP Request FOR</th>
		<th>Time</th>
		<th>Comment</th>
	</tr>"""

		for row in history:
			table += """
	<tr>
		<td>{0}</td>
		<td>{1}</td>
		<td>{2}</td>
		<td>{3}</td>
	</tr>""" . format(row[0], row[1], row[2], row[3])

		table += "</table>"
	else:
		table = "{0:15}  {1:15}  {2:26}  {3}\n" . format("FROM","FOR","Timestamp","Comment")
		table += "-"*60 + "\n"
		
		for row in history:
			table += "{0:15}  {1:15}  {2:26}  {3}\n" . format(row[0], row[1], row[2], row[3])


	dbcursor.close()
	dbconnection.close()
	return table


############################################
# Returns Table (html or text) of previous # 
# adminHistoryLimit connections from user  #
############################################
def get_all_history(contentType,):
  # Database connection stuff
	dbconnection = sqlite3.connect(db)
	dbcursor = dbconnection.cursor()

	dbcursor.execute('''
	SELECT user, firewall_ip, user_ip, timestamp, comment 
	FROM sshConnection 
	ORDER BY timestamp DESC 
	LIMIT ?''', (adminHistoryLimit,))

	history = dbcursor.fetchall()

	if contentType == 'text/html':
		table = """
<table><caption>All Connection History</caption>
	<tr>
		<th>User</th>
		<th>IP Request FROM</th>
		<th>IP Request FOR</th>
		<th>Time</th>
		<th>Comment</th>
	</tr>"""

		for row in history:
			table += """
	<tr>
		<td>{0}</td>
		<td>{1}</td>
		<td>{2}</td>
		<td>{3}</td>
		<td>{4}</td>
	</tr>""" . format(row[0], row[1], row[2], row[3], row[4])

		table += "</table>"
	else:
		table = "{0:12}  {1:15}  {2:15}  {3:26}  {4}\n" . format("User","FROM","FOR","Timestamp","Comment")
		table += "-"*60 + "\n"
    
		for row in history:
			table += "{0:12}  {1:15}  {2:15}  {3:26}  {4}\n" . format(row[0], row[1], row[2], row[3], row[4])


	dbcursor.close()
	dbconnection.close()
	return table


##########################################################
# returns a table for current connections for admin user #
##########################################################
def admin_get_current_activity():
	table = """
<table><caption>Active SSH Connections</caption>
	<tr>
		<th>user</th>
		<th>ip</th>
		<th>time left</th>
		<th>timestamp</th>
	</tr>"""

	for row in get_active_ssh_connections():
		table += """
	<tr>
		<td>{0}</td>
		<td>{1}</td>""" . format(row['user'], row['ip'])

		then = datetime.strptime(row['timestamp'], "%Y-%m-%d %H:%M:%S.%f")
		if (datetime.now() - then) > timedelta(minutes=firewall_rule_ttl):
			table += """
		<td style=\"color:red\">expired</td>"""
		else:
			timeleft = (datetime.strptime(row['timestamp'], "%Y-%m-%d %H:%M:%S.%f") + timedelta(minutes=firewall_rule_ttl) - datetime.now()).seconds
			table += """
		<td>{0} sec</td>""" . format(timeleft)

			table += """
		<td>{0}</td>""" . format(row['timestamp'])
		
		table += """
	</tr>"""
	
	table += "</table>"
	return table

########################################################
# Returns integer of successful connections since time #
########################################################
def connections_since(time=0):
  # Database connection stuff
  dbconnection = sqlite3.connect(db)
  dbcursor = dbconnection.cursor()

  dbcursor.execute('''
    SELECT COUNT(id) as number
    FROM sshConnection
    WHERE strftime('%s',timestamp) > ?''', (time, ))

  result = dbcursor.fetchone()

  dbcursor.close()
  dbconnection.close()

  return result[0]


##############################################
# returns true if the master ssh rule exists #
##############################################
def verify_master_ssh_rules(logger):
	ruleNum = 0
	try:
		output = subprocess.Popen([sudoCommand + " " + firewallShowCommand], shell=True, stdout=subprocess.PIPE).communicate()[0]
	except subprocess.CalledProcessError as error:
		return False

	'''Find master rule. Create if not found'''
	foundMaster = False
	for line in output.splitlines():
		part = line.split()
		if len(part) >= 10 and part[10].startswith('{0}|master|{1}|{2}' . format(appName, appProto, ruleNum)):
			foundMaster = True

	if foundMaster is False:
		try:
			logger.info("adding master deny rule: {0}|master|{1}|{2}" . format(appName, appProto, ruleNum))
			subprocess.check_call(["{0} {1} \"{2}|master|{3}|{4}\"" . format(sudoCommand, sshFirewallDenyRule, appName, appProto, ruleNum)], shell=True)
		except subprocess.CalledProcessError as error:
			logger.error(str(error))
			return False

	'''find allow rules. create if not found'''
	if sshAllowedNetworks:
		for allowRule in sshAllowedNetworks.split(','):
			ruleNum += 1
			foundRule = False
			for line in output.splitlines():
				part = line.split()
				if len(part) >= 10 and part[10].startswith("{0}|master|{1}|{2}|{3}" . format(appName, appProto, ruleNum, allowRule)):
					foundRule = True

			if foundRule is False:
				try:
					logger.info("adding master allow rule: {0}|master|{1}|{2}|{3}" . format(appName, appProto, ruleNum, allowRule))
					subprocess.check_call(["{0} {1} {2} --match comment --comment \"{3}|master|{4}|{5}|{6}\"" . format(sudoCommand, sshFirewallCommand, allowRule, appName, appProto, ruleNum, allowRule)], shell=True)
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
		<style type="text/css">
			table
			{
				border-collapse:collapse;
			}
			table,th,td
			{
				border:1px solid black;
				padding-left: 5px;
				padding-right: 5px;
			}
			caption
			{
				text-align: left;
				font-weight: bold;
				padding-left: 10px;
		</style>
	</head>
<body>"""
