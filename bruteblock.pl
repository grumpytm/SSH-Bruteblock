#!/usr/bin/perl
#
# Script to catch authentication failures in auth.log.
#
# version 0.8 by cezarica01@yahoo.com
# last update: 2020-03-26 10:06:06 GMT +2

#
## Required packages:
# libdbi-perl
# libnetaddr-ip-perl
# libjson-perl
# libdbd-sqlite3-perl

use warnings;
use strict;
use IO::Uncompress::Gunzip qw(gunzip);
use DBI;
use Date::Parse;
use NetAddr::IP;
use HTTP::Tiny;
use JSON qw( decode_json );
use Data::Dumper;

# define the errors
my @err = (
 "Connection closed by",
 "Received disconnect from",
 "Did not receive identification string from",
 "Key exchange negotiation failed",
 "Could not write ident string to",
 "not allowed because not listed in AllowUsers",
 "invalid user",
 "Bad protocol version identification",
 "refused connect from",
 "error: maximum authentication attempts exceeded for invalid user",
 "Protocol major versions differ for",
 "fatal: Unable to negotiate with",
 "authentication failure",
 "ssh_dispatch_run_fatal",
 "Could not write ident string to",
 "Failed keyboard-interactive",
 "ssh_dispatch_run_fatal: Connection from"
);

my $setup = {
	# server name
	name => 'Delta',

	# used subnet
	netAddr => '192.168.0.1/24',
	
	# own ip
	myip => '1.2.3.4',
	
	# where to save the sqlite database
	db => '/root/coding/failed_ssh_logins.db',
	
	# path to hosts.deny
	deny => '/etc/hosts.deny',

	# ipv4 regexp match
	ipv4 => '(?:\d{1,3}\.){3}\d{1,3}',

	# null routing table and file
        filter => "blacklist",
        file => "blacklist.txt",
	
	# files to be read (set this to 'auth.*' to parse all files including archives, for example
	# auth.log, auth.log.1, auth.log.2.gz, auth.log.3.gz and auth.log.4.gz)
	logs => '/var/log/auth.log',
	#logs => 'auth.*',
};

#
# Don't edit past this line!
#

# exclude own network messages
my $network  = NetAddr::IP->new($setup->{netAddr});

# fetch log lines and insert in sqlite database
sub fetchLines {
        my @matches;
        my @files = split / /, $_[0];
        my $pattern = $_[1];

        # Read from files (even archives)
        for my $file (@files) {
		if (-e $file) {
	                # regular log files
        	        unless($file =~ /\.gz$/i) {
                	        open (DATA, '<', $file) or die "$!";
                        	while (<DATA>) {
                                	push(@matches, $_) if grep {/$pattern/} $_;
	                        }
        	        } else {
                	        # compressed log files
                        	my $data = new IO::Uncompress::Gunzip($file) or die "$!";
	                        while (<$data>) {
        	                        push(@matches, $_) if grep {/$pattern/} $_;
	                        }
        	        }
	        }
	}

	# make array
	my @arr;
	for (@matches) {
		next if ($_ !~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
		my $date = str2time(substr($_, 0, (index $_, $setup->{name})));
		my $msg = substr($_, (index $_, ']')+3, length($_));
		my $ip = $1 if $_ =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s/;
		if (defined $ip) {
			my $ipAddr = NetAddr::IP->new($ip);
			if ($ipAddr->within($network)) {
				print "Warning! Caught attempt from $ip on $date\n";
			} else {
				if ($ip ne $setup->{myip}) {
					chomp $msg;
					push(@arr, [$date, $ip, $msg]);
				}
			}
		}
	}
	return @arr;
}

sub getBklacklist {
	my @blacklist;
	my @list = `ipset list blacklist`;
	foreach (@list) {
		if ($_ =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {
			push @blacklist, $_;
		}
	}
	return @blacklist;
}

my $count = {
	deny => 0,
	null => 0,
	black => 0,
	skip => 0
};

# Open connection to sqlite database
my $dbh = DBI->connect("dbi:SQLite:dbname=$setup->{db}", "","",{ RaiseError => 1, AutoCommit => 1},) or die $DBI::errstr;

# Create used tables
$dbh->do("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, date INTEGER, ip TEXT, msg TEXT, UNIQUE(date, ip, msg))");

# fresh stuff
$dbh->do("CREATE TABLE IF NOT EXISTS blacklist (ip TEXT NOT NULL UNIQUE, last INTEGER)");

# Define log files to be parsed
my @allFiles = glob $setup->{logs};
@allFiles = sort {$b cmp $a} @allFiles;

# Define pattern for regular expression (regex) match
my $pattern = join('|', @err);

# define used variables
my @arr = fetchLines(@allFiles, $pattern);

# insert new events into database
my $max = 500;
while (my @cut = splice @arr, 0, $max) {
	my $start=0;
	my $query = qq{INSERT OR IGNORE INTO events (date, ip, msg) VALUES};
        for (@cut) {
        	$query .= ',' if $start++;
       		$query .= '('.(join (",", map{$dbh->quote($_)} @$_)).')';
       	}
	$dbh->do($query) or die $dbh->errstr;
}

#
# Blackhole (null routing)
#

my $sth = $dbh->prepare("INSERT OR REPLACE INTO blacklist (ip, last) SELECT ip, last FROM (WITH list AS (SELECT ip FROM (SELECT ip, COUNT(ip) AS number FROM events GROUP BY ip HAVING Number >= 3)) SELECT ip, MAX(date) AS last FROM events WHERE events.ip IN list GROUP BY ip)");
$sth->execute or die $DBI::errstr;

my @fresh;
$sth = $dbh->prepare("SELECT ip FROM blacklist WHERE strftime('%Y-%m-%d', datetime(last, 'unixepoch', 'localtime')) >= date('now','start of month','-6 months')");
$sth->execute or die $DBI::errstr;

while (my @row = $sth->fetchrow_array) {
       push @fresh, $row[0];
       #$count->{deny}++;
}

if (@fresh)
{
        open(my $fh, '>', $setup->{file});
        print $fh "create $setup->{filter} hash:net family inet hashsize 8192 maxelem 65536\n";
        foreach my $ip ( @fresh )
        {
                print $fh "add $setup->{filter} $ip\n";
        }
        close $fh;
        system(`ipset flush $setup->{filter}`);
        system(`ipset restore -! < $setup->{file}`);
}

#
# stats of the day/month
#

my $stats = {
	1 => $dbh->selectrow_array("SELECT COUNT(ip) FROM events WHERE strftime('%Y-%m-%d', datetime(date, 'unixepoch', 'localtime')) = date('now','localtime','start of day')"),
	2 => $dbh->selectrow_array("SELECT COUNT(ip) FROM blacklist WHERE strftime('%Y-%m-%d', datetime(last, 'unixepoch', 'localtime')) = date('now','localtime','start of day')"),
	3 => $dbh->selectrow_array("SELECT count(ip) FROM events WHERE strftime('%Y-%m-%d', datetime(date, 'unixepoch', 'localtime')) BETWEEN datetime('now', 'start of month') AND datetime('now', 'localtime', 'start of day')"),
	4 => $dbh->selectrow_array("SELECT count(ip) FROM blacklist WHERE strftime('%Y-%m-%d', datetime(last, 'unixepoch', 'localtime')) BETWEEN datetime('now', 'start of month') AND datetime('now', 'localtime', 'start of day')"),
};

#
# close database connection
#

$sth->finish;
$dbh->disconnect;

print "Today: $stats->{2} blacklisted / $stats->{1} events | Month: $stats->{4} blacklisted / $stats->{3} events\n";
