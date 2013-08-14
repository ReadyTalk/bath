appName = 'bath'
appProto='ssh'
db = '/var/lib/bath/bath.db'
sudoCommand = "/usr/bin/sudo"
sshFirewallDenyRule = "/sbin/iptables -A INPUT -p tcp -m tcp --dport 22 -m state --state NEW -j REJECT -m comment --comment"
sshAllowedNetworks="216.52.219.96/28,63.251.200.0/27,66.151.54.0/26,66.35.33.16/28,66.35.37.128/25,66.35.50.128/25,216.52.219.192/26,192.168.0.0/16,216.66.77.0/27,184.105.250.192/26"
sshFirewallCommand = "/sbin/iptables -I INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT -s "
sshFirewallDeleteCommand = "/sbin/iptables -D INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT -s "
firewallShowCommand = "/sbin/iptables -n -L INPUT"

# firewall_rule_ttl is in minutes
firewall_rule_ttl=15

# log file for daemon
logfile="/var/lib/bath/bath.log"

monitorUser = 'monitor'
