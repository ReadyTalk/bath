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

from config import *
from libbath import *
from pwd import getpwnam

''' Daemon Functions '''

def do_daemon_main():
	'''Main daemon loop'''

	create_db()
	dbconnection = sqlite3.connect(db)
	dbcursor = dbconnection.cursor()

	while verify_master_ssh_rules(logger):
		for rule in get_active_ssh_connections():
			then = datetime.strptime(rule['timestamp'], "%Y-%m-%d %H:%M:%S.%f")
			if (datetime.now() - then) > timedelta(minutes=firewall_rule_ttl) or rule['user'] == monitorUser:
				if rule['user'] != monitorUser:
					logger.info("attempting to remove {0}" . format(rule['ip']))

				try:
					subprocess.check_call(["{0} {1}{2}/32 --match comment --comment \"{3}|{4}|{5}|{6}|{7}\"" . format(sudoCommand, sshFirewallDeleteCommand, rule['ip'], appName, rule['proto'], rule['id'], rule['user'], rule['timestamp'])], shell=True)
					if rule['user'] != monitorUser:
						dbcursor.execute("""
							UPDATE sshConnection
							SET enabled=0
							WHERE firewall_ip = ?
							AND timestamp = ?
						""", (rule['ip'], rule['timestamp']))
						dbconnection.commit()
				except subprocess.CalledProcessError as error:
					logger.error(str(error))

		time.sleep(5)

	dbcursor.close()
	dbconnection.close()

'''Daemon Config'''

logger = logging.getLogger("bathd")
logger.setLevel(logging.INFO)
formatter = logging.Formatter(
	"%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler = logging.FileHandler(logfile)
handler.setFormatter(formatter)
logger.addHandler(handler)

'''Daemon Start'''
logger.info("Starting service")
do_daemon_main()
