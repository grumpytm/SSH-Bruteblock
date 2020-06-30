In a nutshell this is a piece of code written in Perl to parse auth.log file for SSH bruteforce attempts, basically looking for the following messages:
```
Connection closed by
error: Received disconnect from
Did not receive identification string from
Key exchange negotiation failed
Could not write ident string to
not allowed because not listed in AllowUsers
invalid user
Bad protocol version identification
error: maximum authentication attempts exceeded for invalid user
Protocol major versions differ for
fatal: Unable to negotiate with
authentication failure
ssh_dispatch_run_fatal
Could not write ident string to
Failed keyboard-interactive
ssh_dispatch_run_fatal: Connection from
```
that are then stored in a sqlite3 database and blocked via an ipset IP set:

> ipset create blacklist hash:net

and a simple iptables rule:

> iptables -I PREROUTING -t raw -m set --match-set blacklist src,dst -j DROP

I basically null route the IP's with 3 or multiple events in the last 6 months.

To filter out junk and have the information I want in the /var/log/auth.log file my /etc/rsyslog.d/50-default.conf looks like this:
```
#auth,authpriv.*                        /var/log/auth.log
:msg, contains, "pam_unix(cron:session)" ~
:msg, contains, "pam_unix(samba:session)" ~
:msg, contains, "pam_unix(sudo:session)" ~
:msg, contains, "pam_unix(su:session)" ~
:msg, contains, "input_userauth_request" ~
:msg, contains, "+ ??? root:nobody" ~
:msg, contains, "Successful su for nobody by root" ~
:msg, contains, "warning: /etc/hosts.deny" ~
:msg, contains, "systemd-logind" ~
:msg, contains, "pam_unix(sshd:session)" ~
:msg, contains, "fatal: Read from socket failed:" ~
:msg, contains, "root:www-data" ~
:msg, contains, "www-data by root" ~
auth,authpriv.*                 /var/log/auth.log
```
