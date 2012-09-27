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

from libbath import *
from mod_python import apache

import httplib
import urllib
import sqlite3
import ipaddr

#################
# Show me first #
#################
def index(req, time=0, output='html'):
	req.add_common_vars()
	create_db()
	user = get_user_name(req)
	message=""

# Process form data if we have it
	if req.form:
		ip = ''
		if ip in req.form:
			# this module is supposed to have ip_address (to support ipv4 and ipv6)
			# it doesn't
	 		# this code currently only supports ipv4
			try:
				ipaddr.IPv4Address(req.form['ip'])
				ip = req.form['ip']
			except ipaddr.AddressValueError:
				ip = get_client_ip(req)
		else:
			ip = get_client_ip(req)
		
		comment= ''
		if not req.form['comment']:
			comment = None
		else:
			comment = req.form['comment']
			
		connection = httplib.HTTPConnection(HOST, PORT)
		connection.request(
			"GET", 
			"/create/{0}/{1}/{2}/{3}/{4}" . format(user, get_client_ip(req), ip, 22, comment))
		response = connection.getresponse()
		message = str(response.read())
		connection.close()

# proceed with rendering the page
	ip = get_client_ip(req)

	if user == monitorUser:
		req.content_type = 'text/plain'

		connection = httplib.HTTPConnection(HOST, PORT)
		connection.request(
			"GET",
			"/create/{0}/{1}/{2}/{3}/{4}" . format(user, get_client_ip(req), ip, 22, comment))
		response = connection.getresponse()
		req.write("{0}\nconnections={1}\n" . format(str(response.read()), connections_since(time)))
		connection.close()

	else:
		if output == 'html':
			req.content_type = 'text/html'
			req.write(get_html_header())
			req.write("""
		<h3>{0}</h3>
		<h4>Enable service for your current IP Address</h4>
		<form method="POST">
			<table style="border:0">
				<tr style="border:0">
					<td style="border:0">ip:</td>""" . format(message))

			if is_admin(user):
				req.write("""
					<td style="border:0"><input type="text" name="ip" value={0}></td>""" . format(ip))
			else:
				req.write("""
					<td style="border:0"><input type="hidden" name="ip" value={0}>{0}</td>""" . format(ip))

			req.write("""
				</tr>
				<tr style="border:0">
					<td style="border:0">comment:</td>
					<td style="border:0"><input type="text" name="comment"></td>
				</tr>
			</table>
	   	<input type="submit" name="ssh" value="Activate SSH">
	  </form>
		<br><br>
""")

			if is_admin(user):
				connection = httplib.HTTPConnection(HOST, PORT)
				connection.request(
					"GET",
					"/adminactive/{0}/{1}" . format(user, output))
				response = connection.getresponse()
				
				req.write(response.read() + "<br><br>")
				connection.close()

			connection = httplib.HTTPConnection(HOST, PORT)
			connection.request(
				"GET",
				"/history/{0}/{1}" . format(user, output))
			response = connection.getresponse()
			
			req.write(response.read() + "<br><br>")
			connection.close()

			if is_admin(user):
				connection = httplib.HTTPConnection(HOST, PORT)
				connection.request(
					"GET",
					"/adminhistory/{0}/{1}" . format(user, output))
				response = connection.getresponse()
				
				req.write(response.read() + "<br><br>")
				connection.close()

			req.write("""
	<h5><a href="bath.sh">download</a> shell script</h5>
</html>
""")
		else:
			req.content_type = 'text/plain'

			connection = httplib.HTTPConnection(HOST, PORT)
			connection.request(
				"GET",
				"/history/{0}/{1}" . format(user, output))
			response = connection.getresponse()
			req.write(message + "\n" + response.read())
			connection.close()

			if is_admin(user):
				connection = httplib.HTTPConnection(HOST, PORT)
				connection.request(
					"GET",
					"/adminhistory/{0}/{1}" . format(user, output))
				response = connection.getresponse()
				req.write("\n\n" + response.read())
				connection.close()
