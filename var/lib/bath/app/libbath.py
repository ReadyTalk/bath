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
	return 'username'
	if  get_client_ip(req) in ('127.0.0.1','192.168.1.15','192.168.6.23','192.168.24.42'):
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
	if user != monitorUser:
		dbcursor.execute('''
			INSERT INTO sshConnection 
			(user, firewall_ip, user_ip, timestamp, comment, enabled)
			VALUES (?, ?, ?, ?, ?, ?)
			''', (user, firewall_ip, user_ip, timestamp, comment, 1))

	iptablescomment = "-m comment --comment \"bath|ssh|{0}|{1}|{2}\"" . format(dbcursor.lastrowid, user, timestamp)

	try:
		subprocess.check_call(["{0} {1}{2}/32 {3}" .format(sudoCommand, sshFirewallCommand, firewall_ip, iptablescomment)], shell=True)
		if user != monitorUser:
			dbconnection.commit()
	except subprocess.CalledProcessError as error:
		if user == monitorUser:
			return "FAIL: CANNOT ADD RULE - {0}\n" . format(str(error))
		else:
			dbcursor.close()
			dbconnection.close()
			return "Unabled to open a connection to " + firewall_ip + " " + str(error)
	
	if user == monitorUser:
		return "SUCCESS: Rule Created\n"
	else:
		dbcursor.close()
		dbconnection.close()
		return "Connection to " + firewall_ip + " successfully initiated.\nThe connection will close in 15 minutes"


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
		output = subprocess.Popen([sudoCommand + " " + firewallShowCommand], shell=True, stdout=subprocess.PIPE).communicate()[0]
		for line in output.splitlines():
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
		pass
	return activeConnections


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
				subprocess.check_call(["{0} {1} {2} -m comment --comment \"{3}|master|{4}|{5}|{6}\"" . format(sudoCommand, sshFirewallCommand, allowRule, appName, appProto, ruleNum, allowRule)], shell=True)
			except subprocess.CalledProcessError as error:
				logger.error(str(error))
				return False

	return True
