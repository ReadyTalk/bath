#!/usr/bin/env python

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

import logging
import datetime
import time
import multiprocessing

from libbath import *
from pwd import getpwnam
from bottle import route, run, request


################################
# Create a rule in the firewall
# On success, return 1
# On failure, return 0
################################
@route('/create/<app>/<user>/<ip>/<user_ip>/<comment>')
def create(app, user, ip, user_ip, comment):
	message = create_connection(app, user, ip, user_ip, comment)
	#message = "Created rule for {0} from {1} with access to {2} on port {3} - {4}" . format(user, user_ip, ip, port, comment)
	return message
	
	
#########################################################
# Return the history of user
#########################################################
@route('/history')
def history(user=None):
	if 'user' in request.query:
		return get_user_history(request.query['user'])
	else:
		return get_user_history()


########################################################
# Returns a list of active connections for a user
########################################################
@route('/active/<user>/<output>')
def active(user, output):
	return #get_active_connections()


########################################################
# Returns a list of active connections for a user
# If port is specified, returns list only for that port
# If the admin flag is set, returns list for all users
#   the supplied user is used to authenticate admin
########################################################
@route('/adminactive/<user>')
def adminactive(user):
	if is_admin(user):
		return admin_get_current_activity()
		
	return


################################################################
# Thread to go through the firewall list and clean up old rules
# Also verifies that the proper whitelist/blacklist and default
#   rules are in place
################################################################
def janitor():
	mainConfig = getMainConfig()
	# set up logging
	logger = logging.getLogger("bathd")
	logger.setLevel(logging.INFO)
	formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
	handler = logging.FileHandler(mainConfig['logfile'])
	handler.setFormatter(formatter)
	logger.addHandler(handler)

	logger.info("Starting Scruffy the Janitor")

	# set up database
	create_db()
	dbconnection = sqlite3.connect(mainConfig['db'])
	dbcursor = dbconnection.cursor()

	# main janitorial loop
	while verify_master_rules(logger):
		appConfig = getAppConfig()
		for rule in get_all_active_connections():
			then = datetime.strptime(rule['timestamp'], "%Y-%m-%d %H:%M:%S.%f")
			if (datetime.now() - then) > timedelta(minutes=int(appConfig[rule['app']].get('ttl'))) or rule['user'] == mainConfig.get('monitorUser') or rule['app'] not in appConfig:
				if rule['user'] != mainConfig.get('monitorUser'):
					logger.info("attempting to remove {0} rule for {1}" . format(rule['app'], rule['ip']))

				try:
					subprocess.check_call(["{0} {1} {2}/32 --match comment --comment \"{3}|{4}|{5}|{6}|{7}\"" . format(mainConfig.get('sudoCommand'), str.replace(mainConfig.get('deleteRule'), '?', rule['port']), rule['ip'], mainConfig['name'], rule['app'], rule['id'], rule['user'], rule['timestamp'])], shell=True)
				except subprocess.CalledProcessError as error:
					logger.error(str(error))

		time.sleep(5)

	dbcursor.close()
	dbconnection.close()

if __name__ == '__main__':
	mainConfig = getMainConfig()
	scruffy = multiprocessing.Process(target=janitor)
	scruffy.start()
	
	manager = multiprocessing.Process(target=run, kwargs={'host': mainConfig['host'], 'port': mainConfig['port'], 'reloader': False, 'server': 'paste'})
	manager.start()
