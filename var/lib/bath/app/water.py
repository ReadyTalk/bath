from libbath import *
from mod_python import apache

import sqlite3
import socket
import ipaddr

def createSshTunnel(req,ip="",comment="none",output=""):
	if output == 'text':
		req.content_type = 'text/plain'
	else:
		req.content_type = 'text/html'

	req.add_common_vars()


	# this module is supposed to have ip_address (to support ipv4 and ipv6)
	# it doesn't
	# this code currently only supports ipv4
	try:
		ipaddr.IPv4Address(ip)
	except ipaddr.AddressValueError:
		ip = get_client_ip(req)

	user = get_user_name(req)

	if output != 'text':
		req.write('<p>')

	create_db()

	req.write(str(create_ssh_connection(user, ip, get_client_ip(req), comment)))

	if output != 'text':
		req.write('</p>')

		if is_admin(user):
			req.write("<table style=\"border-style:solid; border=1\"><th>Active SSH Connections</th>")
			req.write("<tr>")
			req.write("<td>user</td>")
			req.write("<td>ip</td>")
			req.write("<td>time left</td>")
			req.write("<td>timestamp</td>")
			req.write("</tr>")
			for row in get_active_ssh_connections():
				req.write("<tr>")
				req.write("<td>{0}</td>" . format(row['user']))
				req.write("<td>{0}</td>" . format(row['ip']))

				then = datetime.strptime(row['timestamp'], "%Y-%m-%d %H:%M:%S.%f")
				if (datetime.now() - then) > timedelta(minutes=firewall_rule_ttl):
					req.write("<td style=\"color:red\">expired</td>")
				else:
					timeleft = (datetime.strptime(row['timestamp'], "%Y-%m-%d %H:%M:%S.%f") + timedelta(minutes=firewall_rule_ttl) - datetime.now()).seconds
					req.write("<td>{0} sec</td>" . format(timeleft))

				req.write("<td>{0}</td>" . format(row['timestamp']))
				req.write("</tr>")
    
			req.write("</table>")
