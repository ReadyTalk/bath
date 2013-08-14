from libbath import *

def index(req, time=0):
	create_db()
	user = get_user_name(req)
	ip = get_client_ip(req)

	if user == monitorUser:
		req.content_type = 'text/plain'
		req.write("{0}connections={1}\n" . format(str(create_ssh_connection(user, ip, ip, 'monitoring')), connections_since(time)))

	else:
		req.content_type = 'text/html'
		req.write("""
<html>
  <h2>Enable service for your customer's IP Address</h2>
	<p> 
""")
		req.write("Enter the IP address that the customer reads to you.<br>")
		req.write("This will authenticate them to run networking tests against our LA server for the next 15 minutes<br>")
		req.write("""
	 	<form action="water.py/createSshTunnel" method="POST">""")

		req.write("""
			<table>
				<tr>
					<td>IP:</td>
					<td><input type="text" name="ip"></td>
				</tr>
			</table>""" . format(ip))

		req.write("""
    	<input type="submit" name="ssh" value="Authenticate IP">
  	</form>
	</p>
""")

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

		
