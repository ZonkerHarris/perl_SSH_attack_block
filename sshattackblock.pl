#! /usr/bin/perl
#
#  sshattackblock.pl
#     by Zonker Harris   11 DEC 2012  (v1.0.9 10 DEC 2012)
#
# Designed to be run manually, or via cron
#   There is normally no output, unless you use the hidden debug flag
## crontab entry: */3 * * * * /root/sshattackblock.pl >/dev/null 2>&1
#
#  Still to do;
#   - we may want to try sending some log info in email, ...
#       (we currently log to syslog, if it's running)
#       "logger -s -p local3.warn -- Trusted host $attackerID attacked me"
#       ( -s sends to syslog AND stderr, -p sets the priority and facility,
#           -- delimits the message)
#       (We also append lines to a flat file, which can be tailed.)

use warnings ;
use strict ;
use diagnostics;

use DB_File ;
our (%bipdb, $runstamp, $badIP) ;

# Starting in v1.0.7, the configuration file is external to the script...
# You may need to change the path for the file...
use sshattackblock_config ;

# open our flat logfile, for write, append
# Normally, we run from Root's crontab, which would put a relative path file in /root
#  BUT, since we may run the script in debug mode, it's best to specify the file path...
# (I normally "touch" the long-term log filename in new installations)
#  Secure Linux wouldn't open the file in the PM, so we're back to opening it here...
open(OUTFILE, ">>/root/chain_changes.txt");
#  We print nothing to the outfile, just to mention it again, to suppress errors using strict
print OUTFILE "";

###  Preset some variables
#  The timestamp when the script is run...
our $timestamp = time;
our @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
# You can use 'gmtime' for GMT/UTC dates instead of 'localtime'
our ($sec, $min, $hour, $day, $month, $y2k) = (localtime($timestamp));
our @corrected = ("00", "01", "02", "03", "04", "05", "06", "07", "08", "09");
our $year = ($y2k += 1900);
if ($month <10)
{
   $month = ($corrected[$month]);
}
if ($day <10)
{
            $day = ($corrected[$day]);
}
if ($min <10)
{
            $min = ($corrected[$min]);
}
# Remove the comment character on the next line to start our logfile with the
# human-readable date and time, other records with will be there regardless...
print OUTFILE "$timestamp : New run started $day $months[$month] $year , $hour:$min \n";
#
our $AgeTime = ( $sshattackblock_config::AgeSeconds / 60 );
our $OldStamp = ( $timestamp - $sshattackblock_config::AgeSeconds );
###  Check for extra data on the command line, and print instructions.
#  (there shouldn't be extra arguments... Except the hidden "-d" debug flag!)
my $DEBUG = "0";
if(scalar( @ARGV) )
{
    my $userinput = $ARGV[0];
    if ($userinput eq "-d")
    { $DEBUG = "1"; }
    else
    { show_usage();
      exit; }
}

##  Initializing or pre-setting the rest of our variables...
#  $SendLogCmd will be used to send a string through the "logger" facility, sending to SNMP
our (@CurrentRules, @LogQuery, @AlertLog );
our ($attacker, $attackStatus, $attackerID, $count, $status, $oldTimestamp, $oldAttacker );
our ($ruleNumber, $AttackerIP, $SendLogCmd );
our %BlockList = ();
our %Blocked = ();
our %AttackCount = ();
our %RuleNumbers = ();
our %DeleteList = ();

#### Here is the meat of the script...

Check_the_log ();

if ( $LogQuery[0] )
{
   Parse_for_attackers();

   my $AttackerCount = scalar keys %BlockList ;
   unless ( $AttackerCount = 0 )
   {
      Grab_the_current_rules();

      Remove_old_Rules ();

      Block_the_attackers( %BlockList );
   }
}
else
{
   if ($DEBUG == 1)
   {  print "* No attackers seen.\n";  }
}

$status = 0;
print "\n";
exit;


##### Subroutines are below...

sub Check_the_log
{
   #  Tail the messages log file for a certain number of lines...
   #   Grep the result for "ailed" to look for only failure messages...
   #   Add them to an attacker array, for line-at-a-time reading...
   @LogQuery = `$sshattackblock_config::GetSendLogCmd`;
   if ($DEBUG == 1)
   {  print "---- Messages Log Data (out of " . $sshattackblock_config::LogDepth . " lines) -------\n";
      #my $logLineCount = @LogQuery;
      #print "  There are $logLineCount Elements in the log query results.\n";
      print @LogQuery;
   }
}

sub Parse_for_attackers
{
   # First, check if there were interesting lines in the log file to parse...
   if ( ! @LogQuery )
   {
      if ($DEBUG == 1)
      {  print "  * no interesting lines in the log file\n";  }
   }
   else
   {
      #  Pull each IP address from the attacker array ($LogQuery)...
      #   If it is a safety address, do nothing, set a flag, send an alert
      #   If it isn't a safety address, is it already in the DF file?
      #    If it's new, set it's count to "1"
      #    If it's already listed, increment it's hit count...
      #  For each attacker in the attacker counter array
      #   If they are currently "active" in the DB file, do nothing
      #    Read the next log line if there is already an IPTABLE rule
      #    Otherwise, add them to the DB File, and mark them "active"
      #         (timestamp, IP, count, flag)
      #
      my %Blocked = ();
      # link "badIPdb" ;
      # Normally, we run from Root's crontab, which would put a relative path file in /root
      #  BUT, since we may run the script in debug mode, it's best to specify the file path...
      tie %bipdb, "DB_File", $sshattackblock_config::DBfilePath, O_RDWR|O_CREAT, 0666, $DB_HASH
        or die "Cannot open file $sshattackblock_config::DBfilePath : $!\n";
      #  We also need to scan the IPTABLES rules for DROP filters, just a list of unique IPs...
      #   When we determine the attacker IP, it may be a persistant log because we banned him last time
      #   It's possible to add the same address many time over... but we don't want to.
      @CurrentRules = `$sshattackblock_config::GetRulesCmd`;
      my $BlockedIP = "";
      foreach my $rule (@CurrentRules)
      {
         #get the rule number and the IP of the attacker... we rely on Search being 'greedy'...
         if ($rule =~ /^(\d{1,2} )/)
         {  $ruleNumber = $1;  }
         if ($rule =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/)
         {  $BlockedIP = $1 . "." . $2 . "." . $3 . "." . $4;  }
          $Blocked{$BlockedIP} = $ruleNumber
      }
      if ($DEBUG == 1)
      {  print "---- Parsing log results for attackers -------";  }
      # We need to break $LogQuery down into individual lines...
      LOGQUERY: foreach my $Line (@LogQuery)
      {
         $attackStatus = 0 ;
         my $AttackCount = 0 ;
         #  Look for an IP address, aggregate from $line into $attacker
         if ($Line =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/)
             {  $attacker = $1 . "." . $2 . "." . $3 . "." . $4;  }
         # Did we find an IP address?  If not, skip to the next log line...
             else
             {
            next LOGQUERY ;
             }
             if ($attacker =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
         {
            #  $attacker is a valid IP address...
            unless ( $Blocked{$attacker} )
            {
               #  This is no rule blocking attacker...
               if ($DEBUG == 1)
               {  print "\nNew Attacker IP address is $attacker";  }
            }
            else
            {
               #  We already have a rule in place for this address...
               if ($DEBUG == 1)
               {  print "\n $attacker is already in IPTABLES (rule: $Blocked{$attacker}), old log entry";  }
               next LOGQUERY;
            }
            if ( exists $AttackCount{$attacker} )
            {
               #  We've seen this attacker more than once in this run, increment the count
               $count = $AttackCount{$attacker} ;
               $count++ ;
               $AttackCount{$attacker} = $count ;
               #if ($DEBUG == 1)
               #{  print "  Attacker $attacker, count = $count\n";  }
            }
            else
            {
               #  This is the first time we have seen this attack in this pass...
               $AttackCount = 1 ;
               $AttackCount{$attacker} = 1 ;
               #if ($DEBUG == 1)
               #print "  Attacker $attacker, count = $AttackCount";
            }
            #  Build the key for the DB-file, by concatenating the timestamp and the IP
            $attackerID = $timestamp . ":" . $attacker ;
            #  This next case simply prints Marching Ants for repeat attackers...
            if ($DEBUG == 1)
            {  print ".";  }
            # See if the attacker is one of our Trusted (@Safety) hosts...
            TRUSTED: foreach my $trusted (@sshattackblock_config::safety)
            {
                       if ($attacker eq $trusted)
               {
                  # Exempt the Main Street AMS collector address (204.147.180.199)from the list...
                  if ($attacker eq "204.147.180.199")
                  {
                     #  Add debug indication that we exempted him...
                         if ($DEBUG == 1)
                     {  print "  Never mind, it is the Main Street collector...";  }
                     $attackStatus = 1;
                     next LOGQUERY ;
                  }
                  else
                  {
                         if ($DEBUG == 1)
                     {  print "Attack is from a host in the Safety list!";  }
                     $attackStatus = 2;
                     $SendLogCmd = "logger -s -p local3.warn -- Trusted host at $attackerID attacked me";
                     my $logstatus = `$SendLogCmd`;
                     print OUTFILE "$timestamp : Trusted host at $attackerID attacked me ($day $months[$month] $year, $hour:$min)\n";
                     #   One of our trusted addresses is attacking us?
                     #   append new allert line to $AlertLog
                     next LOGQUERY ;
                  }
               }
            }
            ##  If we get here, the attacker is NOT a Trusted host!
            # Is the Attacker in the DB File?
            #   YES: increment his count; status = "2"; update the timestamp;
            #   NO: set his count to "1"; status = "2"; update the timestamp;
            my $count = "1";
            my $status = "2";
            if ( exists $bipdb{$attackerID} )
            {
                   #  YES: increment his count; leave the status = "1";
                   ($count, $status) = split /:/, $bipdb{$attackerID} ;
                   $count++;
               $bipdb{$attackerID} = join (":", ($count, $status)) ;
               if ( $count > $sshattackblock_config::FailCount )
               {
                  if ( exists $Blocked{$attacker} )
                  {
                     # There is already an IPTEABLE rule for this address
                     if ($DEBUG == 1)
                     {  print " Attack limit met, but there is already a rule, ";  }
                     next LOGQUERY ;
                  }
                  else
                  {
                     # Add $Attacker IP into the $BlockList
                     if ($DEBUG == 1)
                     {  print " Attack limit met, Added to the BlockList... ";  }
                     $BlockList{$attacker} = $count ;
                  }
               }
            }
            else
            {
               #  NO: set his count to "1"; status = "1";
               if ($DEBUG == 1)
               {  print " Added to DB file... ";  }
               $attackStatus = 2;
               $bipdb{$attackerID} = join (":", ($count, $status)) ;
            }
         }
         else
         {
            if (($DEBUG == 1) && ($attacker ne ""))
            {  print "\nA line had no IP address, not an attacker.";  }
         }
      }
      # At this point, we know the attack is valid, is NOT a Safety host, and is ALREADY in the blocklist
      if ($DEBUG == 1)
      {
         $attacker = "";
         print "\n-------- Print the DB File ----------\n";
         foreach $attackerID (keys %bipdb)
         {
           ($count, $status) = split /:/, $bipdb{$attackerID} ;
           printf("%-34s %-7s %-2s\n", $attackerID ,$count, $status);
         }
         print "-------- Print the BlockList ----------\n";
         #my $AttackerCount = scalar keys %BlockList ;
         #if (($DEBUG == 1)
         #{  print "There are $AttackerCount entries in the Block List.\n";  }
         foreach my $attacker (keys %BlockList)
         {
            print "$attacker\n";
         }
      }
   untie %bipdb;
   }
}


sub Grab_the_current_rules
{
   # List the current IPTABLES ruleset for the INPUT filter
   #   We want to be able to search the list for just the DROPped TCP lines...
   #   We want them with line numbers, so we can remove them later...
   # Fetch the current list of denied addresses in the Input list...
   @CurrentRules = `$sshattackblock_config::GetRulesCmd`;
   if ($DEBUG == 1)
   {  print "----------- Filter Rules ----------\n";
      my $rulesCount = @CurrentRules;
      print "  There are $rulesCount Elements in the filter rules query results.\n";
      print @CurrentRules;
   }
   foreach my $rule (@CurrentRules)
   {
      #get the rule number and the IP of the attacker... we rely on Search being 'greedy'...
      if ($rule =~ /^(\d{1,2} )/)
      {  $ruleNumber = $1;  }
      if ($rule =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/)
          {  $AttackerIP = $1 . "." . $2 . "." . $3 . "." . $4;  }
      if ($DEBUG == 1)
      {  print "rule $ruleNumber,  attacker IP is $AttackerIP\n";  }
      $RuleNumbers{$ruleNumber} = $AttackerIP;
   }
   my $rulesCount = scalar keys %RuleNumbers;
   if ($DEBUG == 1)
   {  print "  There are $rulesCount Elements in the filter rules query results.\n";  }
}

sub Remove_old_Rules
{
   # DB File Status field: 2 = Rule added to IPTABLES, 1 = Active attack, but no rule,
   #   but 0 = the rule has been removed (noting that they were attackers before)
   # Read the DB File, find records with status 2, then look for the matching rule number
   tie %bipdb, "DB_File", $sshattackblock_config::DBfilePath, O_RDWR|O_CREAT, 0666, $DB_HASH
     or die "Cannot open file $sshattackblock_config::DBfilePath : $!\n";
   if ($DEBUG == 1)
   {  print "------- Removing Attackers older than $AgeTime minutes ------\n";  }
   CHECKLIST: foreach $attackerID (keys %bipdb)
   {
      (my $attackTimestamp, my $oldAttacker) = split /:/, $attackerID;
      ($count, $status) = split /:/, $bipdb{$attackerID} ;
      #if ($DEBUG == 1)
      #{  print "AttackerID: $attackerID / ATT time: $attackTimestamp / Old time: $OldStamp / IP: $oldAttacker / Count: $count / Status: $status\n";  }
      #
      # Test to see if a log entry put an IP address in the wrong field...
      next CHECKLIST if ($attackTimestamp =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/);
      #  Now a test, is the DB file "attack timestamp" older than the "aged-out threshold timestamp" here...
      #    next line if it's younger (greater than) than old timestamp;
      next CHECKLIST if ( $attackTimestamp > $OldStamp );
      #if ($DEBUG == 1)
      #{  print "old attacker: $oldAttacker / attack timestamp: $attackTimestamp / old timestamp: $timestamp\n";  }
      #
      #  Here, we skip the record, unless we know there was a rule set...
      next CHECKLIST if ($status < 2);
      #It's older than our old-record timeout, AND there WAS a rule set in IPTABLES...
      #
      #
      {
         #It's older than our old-record timeout, and there WAS a rule set in IPTABLES...
         my $AttackerCount = scalar keys %RuleNumbers ;
         #if ($DEBUG == 1)
         #{  print "status = 2, old attacker: $oldAttacker, number of rules in the RuleNumbers hash is $AttackerCount\n";  }
         # Skip this if we have no DENY rules in the IPTABLES list... (an unlikely event)
         unless ( $AttackerCount == 0 )
         {
            foreach my $rule (keys %RuleNumbers)
            {
               my $priorAttacker = "";
               $priorAttacker = ( $RuleNumbers{$rule} );
               #  Check if the IP in this rule matches the IP from this loop of the DB file...
               if ( $priorAttacker eq $oldAttacker )
               {
                  if ($DEBUG == 1)
                  {  print "Old attacker $oldAttacker found in rule $rule, added the rule to DeleteList.\n";  }
                  $DeleteList{$rule} = $oldAttacker;
               }
            }
         }
      }
   }
   # Now, sort the $DeleteList keys in descending order (remove the rules highest to lowest)
   if ($DEBUG == 1)
   {  print "------- Processing the DeleteList ------\n";  }
   foreach my $rule (sort high_to_low keys %DeleteList)
   {
      my $attackerIP = $DeleteList{$rule} ;
      if ($DEBUG == 1)
      {  print "Removing rule $rule, was $attackerIP\n";  }
      #Remove the rule!
      #  our $iptabledelete = "sudo /usr/sbin/iptables -D INPUT";
      my $deleteCmd = `$sshattackblock_config::iptabledelete $rule 2>&1`;
      my $cmdStatus = $?;   # 0 if ok
      if ($cmdStatus == 0)
      {
         if ($DEBUG == 1)
         {  print "rule successfully removed\n";  }
         $SendLogCmd = "logger -s -p local3.warn -- Removed $attackerIP from IPTABLES";
         my $logstatus = `$SendLogCmd`;
         print OUTFILE "$timestamp : Removed $attackerIP from the chains INPUT file ($day $months[$month] $year, $hour:$min)\n";
         #  Set the status for this line of the DB file to 0, since we are removing this rule.
         $status = "3";
         $attackerID = $timestamp . ":" . $attackerIP ;
         $bipdb{$attackerID} = join (":", ($count, $status));
      }
      else
      {
         if ($DEBUG == 1)
         {  print "rule could NOT be removed, returned status $cmdStatus \n";  }
         $SendLogCmd = "logger -s -p local3.warn -- Could NOT remove $attackerID from IPTABLES";
         my $logstatus = `$SendLogCmd`;
         print OUTFILE "$timestamp : Could NOT remove $attackerIP from the chains. ($day $months[$month] $year, $hour:$min)\n";
         #  Set the status to 4, so we know there was an error removing the address.
         $status = "4";
         $attackerID = $timestamp . ":" . $attackerIP ;
         $bipdb{$attackerID} = join (":", ($count, $status));
      }
   }
untie %bipdb;
}

sub Block_the_attackers
{
   #  For each line in the attacker counter array
   #   Add a filter rule to block them
   #
   my @BlockList = @_;
   if ($DEBUG == 1)
   {  print "---- Blocking attackers verified in this pass -------\n";  }
   tie %bipdb, "DB_File", $sshattackblock_config::DBfilePath, O_RDWR|O_CREAT, 0666, $DB_HASH
     or die "Cannot open file $sshattackblock_config::DBfilePath : $!\n";
   BLOCKEM: foreach $attacker (keys %BlockList)
   {
      # Check whether there was a rule for this address BEFORE...
      if ( exists $Blocked{$attacker} )
      {
              next BLOCKEM;
      }
      else
      {
         # sudo /usr/sbin/iptables -I INPUT -p tcp -s $userinput -d 205.248.105.205 --dport 22 -j DROP 2>&1
         # our $iptableset = "sudo /usr/sbin/iptables -I INPUT -p tcp -s";
         my $blockCmd = `$sshattackblock_config::iptableset $attacker -d $sshattackblock_config::hostip --dport 22 -j DROP 2>&1`;
             my $cmdStatus = $?;   # 0 if ok
         if ($cmdStatus == 0)
         {
            # Filter DROP rule has been successfully added
             if ($DEBUG == 1)
            {  print "Added attacker $attacker into IPTABLES\n";  }
            $SendLogCmd = "logger -s -p local3.warn -- Added $attacker into IPTABLES";
            my $logstatus = `$SendLogCmd`;
            print OUTFILE "$timestamp : Added $attacker into the chains INPUT file ($day $months[$month] $year, $hour:$min)\n";
            # Update the DB file Status field to reflect a successful rule-add...
            $attackerID = $timestamp . ":" . $attacker ;
            ($count, $status) = split /:/, $bipdb{$attackerID};
             $status=2;
            $bipdb{$attackerID} = join (":", ($count, $status));
         }
         else
         {
                # Filter rule could NOT be successfully added...
                if ($DEBUG == 1)
            {  print "Rule was NOT added for $attacker. The command returned $cmdStatus \n";  }
            $SendLogCmd = "logger -s -p local3.warn -- Could NOT add $attacker to IPTABLES";
            my $logstatus = `$SendLogCmd`;
            print OUTFILE "$timestamp : Could NOT add $attacker into the chains INPUT file ($day $months[$month] $year, $hour:$min)\n";
         }
      }
   }
untie %bipdb;
@CurrentRules = `$sshattackblock_config::GetRulesCmd`;
if ($DEBUG == 1)
{  print "----------- Final Filter Rules ----------\n";
   my $rulesCount = @CurrentRules;
   print "  The following $rulesCount rules are now active...\n";
   print @CurrentRules;
}
#  Yes, this last bracket below DOES belong there...
}

sub high_to_low
{
   my ($ruleA, $ruleB) = ($a, $b);

   $ruleB <=> $ruleA;
}

sub show_usage
{
   #  Show the command usage banner...
   print "Usage: attackblock.pl\n\nThis script does not accept any added arguments.\n";
   print "This script is meant to be invoked manually, or run by cron.\n\n";
   print "The script looks in the last " . $sshattackblock_config::LogDepth . " lines of the logs for signs of\n";
   print "failed SSH logins, and will add an attackers IP to the IPTABLES\n";
   print "after " . $sshattackblock_config::FailCount . " recent failures.\n\n";
   print "The script also logs to a local DB file. When the script runs,\n";
   print "it also looks at the DB file to find any addreses older than\n";
   print $AgeTime . " minutes, and it will remove those addresses from the INPUT\n";
   print "filter of the IPTABLES list, and then from the DB file.\n\n";
}

### eof
