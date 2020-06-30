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
I then store the events log as it is in a sqlite3 database to report (feature has been taken out for now but will get it back soon) and via an ipset IP set

> ipset create blacklist hash:net

and a simple iptables rule

> iptables -I PREROUTING -t raw -m set --match-set blacklist src,dst -j DROP

I basically null route the IP's with 3 or multiple events in the last 6 months.
