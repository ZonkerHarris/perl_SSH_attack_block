perl_SSH_attack_block
=====================

Parse logs for SSH attacks, block the offender using IPCHAINS.
We log the block, so that we can unblock it later, when the attack bot has given up, to keep the tables shallow.

This can be adapted, pointing to the log where SSH failed logins are logged, and where your iptables live.
You can also choose the depth (how many fail.ures), the length (blocked for how long), and where you log this activity.
There is also a safety_net feature, where you can exclude certain "important" addresses, so your internal users do not lock themselves out.

Rather than making this a monolith, I adapted to using a PM file to hold configuration clues.

I suggest that you download the repository, versus copy-n-paste from the GIT web windows.
(I've found hidden characters at the head of the files when I've tried that method. BAD Mojo!)
