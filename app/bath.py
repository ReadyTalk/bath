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

import sqlite3
import socket
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

		message = str(create_ssh_connection(user, ip, get_client_ip(req), req.form['comment']))

# proceed with rendering the page
	ip = get_client_ip(req)

	if user == monitorUser:
		req.content_type = 'text/plain'
		req.write("{0}\nconnections={1}\n" . format(str(create_ssh_connection(user, ip, ip, 'monitoring')), connections_since(time)))

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

			req.write(get_user_history(user, 'text/html')+ "<br><br>")

			if is_admin(user):
				req.write(admin_get_current_activity()+ "<br><br>")
				req.write(get_all_history('text/html')+ "<br><br>")

			req.write("""
	<h5><a href="bath.sh">download</a> shell script</h5>
</html>
""")
		else:
			req.content_type = 'text/plain'
			req.write(message + "\n" + get_user_history(user, 'text/plain'))
			if is_admin(user):
				req.write("\n\n" + get_all_history('text/plain'))
