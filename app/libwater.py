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

import ConfigParser
import json
import httplib

configFile = '/var/lib/bath/client.conf'

##############################################################
# returns a dictonary of the main section in the config file #
##############################################################
def getMainConfig():
	config = ConfigParser.ConfigParser()
	config.read(configFile)

	mainConfig= dict()

	try:
		mainConfig['name'] = config.get('main', 'name')
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
			except ConfigParser.NoOptionError as error:
				print "Error reading config file ({0}): " . format(configFile), error
				sys.exit(1)
			for name, value in config.items(section):
				if name not in appConfig[section]:
					appConfig[section][name] = value

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


######################################
# HTTP Get -- returns results of GET #
######################################
def http_get(path):
	mainConfig = getMainConfig()
	connection = httplib.HTTPConnection(mainConfig['host'], mainConfig['port'])
#	connection = httplib.HTTPConnection(mainConfig['host'], mainConfig['port'], mainConfig['cert'])
	connection.request(
		"GET",
		"{0}" . format(path))
	response = connection.getresponse().read()
	connection.close()
	return response
