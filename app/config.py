appName = 'bath'
appProto='ssh'
db = '/var/lib/bath/bath.db'
sudoCommand = "/usr/bin/sudo -n"
sshFirewallDenyRule = "/sbin/iptables --append INPUT --protocol tcp --dport 22 --match state --state NEW --jump REJECT --match comment --comment"
sshAllowedNetworks=""
sshFirewallCommand = "/sbin/iptables --insert INPUT --protocol tcp --dport 22 --match state --state NEW --jump ACCEPT --source "
sshFirewallDeleteCommand = "/sbin/iptables --delete INPUT --protocol tcp --dport 22 --match state --state NEW --jump ACCEPT --source "
firewallShowCommand = "/sbin/iptables --numeric --list INPUT"

# firewall_rule_ttl is in minutes
firewall_rule_ttl=2

# lines of history to show for user
userHistoryLimit=5
adminHistoryLimit=15

# log file for daemon
logfile="/var/lib/bath/bath.log"

monitorUser = 'monitor'


HOST = '0.0.0.0'
PORT = 8274
