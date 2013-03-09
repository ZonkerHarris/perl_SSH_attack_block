package sshattackblock_config;

#     by Zonker Harris   23 AUG 2010  (v1.0.7 7 OCT 2010)
## LOCALIZATION for sshattackblock.pl script.
#  Make changes here, specific to your machine... that way, when you load an updated
#   version of the script, your configuration is ready to go. :-)
#  I didn't EXPORT the variables, so that you know (in the main script) which
#    variables are coming from the Config file.)

# --- Contributed by Andy H.
#   included in the config side, in case you need to manually specify the host IP...)
use IO::Socket;
use Sys::Hostname;
# ---

# How many log lines do we look at using 'tail'?
our $LogDepth = "50";

# Normally, we run from Root's crontab, which would put a relative path file in /root
#  BUT, since we may run the script in debug mode, it's best to specify the file path...
# (I normally "touch" the DB filename in new installations)
our $DBfilePath = "/root/attackerIPdb" ;

# Where do we find the log messages? /var/log/messages? /var/adm/auth.log?
our $logfile = "/var/log/messages" ;

#What string do we need to search for? "nvalid"?  "ailed"?
# our grep is Case-Sensitive, so I usually drop the first letter...
our $GetSendLogCmd = "tail -" . $LogDepth . " " . $logfile . " | grep ailed";

#  Our host IP address... we need to specify this as the destination in IPTABLES
#    (If the automation doesn't work, too many interfaces, etc., just specify $hostip manually)
#our $hostip = "192.168.0.11";
# --- Added by Andy H.
# Figure out my own ip  (requires IO::Socket and Sys::Hostname)
our $hostname=hostname();
our ($hostip)=inet_ntoa((gethostbyname($hostname))[4]);
#print "$hostip\n";
# ---

#  Which address should we NOT block with our filters 
#   list the IP's for "trusted hosts" that should not be blocked automatically
# I add comments, so that the admins who come after me will understand. ;-)
#   192.168.0.x are subnet neighbors  172.16.1.x are machines at the data center
our @safety = qw( 192.168.0.11 192.168.0.5 192.168.0.13 );
          
# open our flat logfile, for write, append
# Normally, we run from Root's crontab, which would put a relative path file in /root
#  BUT, since we may run the script in debug mode, it's best to specify the file path...
# (I normally "touch" the long-term log filename in new installations)
open(OUTFILE, ">>/root/chain_changes.txt"); 
#  We print nothing to the outfile, just to mention it again, to suppress errors using strict
print OUTFILE "";

# How many failures in this time span means this is likely an attacker?
# (We don't want to lock out every valid user who forgot their password...)
#  We need to exceed the $FailCount... 
our $FailCount = "6";

# How long do we ban an IP address?
# 10 minutes = 600 seconds. 1 hour = 3600 seconds.  12 hours = 43,200
# 1 day = 86,400.  4 days = 345,600 seconds.  1 week = 604,800 seconds
our $AgeSeconds = "43200";

# How do we list the IPTABLES rules for denied hosts?
our $GetRulesCmd = "/usr/sbin/iptables -L INPUT --line-numbers --numeric | grep DROP | grep tcp";

#  how do we set entries into the Input list (we need the preface for the command)
our $iptableset = "/usr/sbin/iptables -I INPUT -p tcp -s";

#  how do we remove entries from the Input list (we need the preface for the command)
our $iptabledelete = "/usr/sbin/iptables -D INPUT";

## END OF LOCALIZATION!  You shouldn't make changes below this line...

# Finally, because we are "use"ing this package, we must return a TRUE test...
1;
