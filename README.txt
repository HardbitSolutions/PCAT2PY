PCAT2PY
=======

ABOUT
=====

Pre-Compliance Accreditation Tool for Python

PCAT2PY is a Python based program for scanning and remediating security
findings. This implementation is capable of running locally or remotely
against Red Hat and Windows based operating systems. PCAT2PY
generates standard out debugging and html indicating status, documentation,
and standard output of findings that have been scanned and remediated.

For remote use PCAT2PY uses Windows Remote Management and Secure Shell.
Remote scanning and remediation against Windows based environments requires
WINRM with HTTP, Basic Auth, and Unencrypted traffic enabled. For Red Hat
based environments, SSH has to be enabled and either root login permitted
or a account with sudoers rights must be available. Sudoers must have the
requiretty directive disabled.

PCAT2PY is able scan and remediate Red Hat and Windows environments using
the following postures based from DISA STIGS hosted at iase.disa.mil:

     RHEL6       Office2007Access          Office2013Access
                 Office2007Excel           Office2013Excel
     XP          Office2007InfoPath        Office2013InfoPath
     Vista       Office2007OfficeSystem    Office2013OfficeSystem
     Win7        Office2007Outlook         Office2013Outlook
     Win8        Office2007PowerPoint      Office2013PowerPoint
                                           Office2013Word
     IE6         Office2010Access          Office2013OneNote
     IE7         Office2010Excel           Office2013Project
     IE8         Office2010InfoPath        Office2013Publisher     
     IE9         Office2010OfficeSystem    Office2013Lync
     IE10        Office2010Outlook         Office2013Groove
                 Office2010PowerPoint      Office2013Publisher     
     2003MS      Office2010Word            Office2013Visio
     2003DC      Office2010OneNote
     2008MS      Office2010Project
     2008DC      Office2010Publisher
     2008R2MS
     2008R2DC
     2012MS
     2012DC

CONTENT
=======

PCAT2PY is designed to run as a self-contained executable or run as a script on
the Python interpreter. 

When running as a script, Python 2.6.6 or later is required. In addition, the
following python modules must be installed: pywinrm, ecdsa, paramiko, and pycrypto.
When running as a self-contained executable, no Python interpreter is required.

pcat2py.py - entry point for execution (PCAT2PY starts from this script)
local_cli.py - local command line interface class definition
ssh_cli.py - secure shell command line interface class definition
winrm_cli.py - windows remote management command line interface class definition
session.py - PCAT2PY session class definition
presentation.py - standard output and HTML functions
findings - finding(s) class definitions

HOWTO
=====

PCAT2PY has two modes of operation. It can be used to scan or remediate systems using
findings from the above listed postures. Findings can be individually selected for 
scanning or remediation by supplying the --finding switch. Entire postures can be
selected by supplying the --posture switch. 

Be default, not standard output is generated during runtime. Supplying the --debug 
switch allows different verbosities of output to be generated. Results of a PCAT2PY
session can also be written in HTML by supplying the --html switch.

To scan or remediate a remote system, the --winrm or --ssh switches can be supplied
to run PCAT2PY against a remote system. Passwords will be prompted for unless the
--password switch is supplied.

C:\PCAT2PY>python pcat2py.py

PCAT2PY - Pre-Compliance Accreditation Tool for Python

usage: pcat2py scan [arguments]       evaluate compliance for finding(s)
   or: pcat2py remediate [arguments]  remediate finding(s)

Arguments:
   --debug <level>       Print debugging information during remediate/scan
                           0: No debugging output (default)
                           1: Displays finding identification and compliance status
                           2: Displays verbose finding description
                           3: Displays standard output
   --finding <finding>   Scan or remediate a specific finding or findings
                           This switch can accept group id, rule id, ...
                           group title, rule version, or severity.
                           Specify multiple findings by inserting commas.
   --posture <posture>   Scan or remediate finding(s) of a specific os.
   --ssh <user@host>     Scan or remediate finding(s) on a ssh connection
                           Remote user must be root or have sudo
                           Defaults !requiretty must be in the sudoers
                           User will be prompted for password
   --winrm <user@host>   Scan or remediate finding(s) on a winrm connection
                           User will be prompted for password
   --password <password> Supply password as an argument. If this switch ...
                           is not called in addition to the remote switch, ...
                           the user will be prompted for a password.
   --html <filename>     Generate html report

EXAMPLES
========

./pcat2py.py scan --finding V-38623 --debug 3

#############################################
# POSTURE:      RHEL6
# GROUP ID:     V-38623
# GROUP TITLE:  SRG-OS-000206
# RULE ID:      SV-50424r1_rule
# RULE VERSION: RHEL-06-000135
# SEVERITY:     CAT II
#############################################

TITLE:
All rsyslog-generated log files must have mode 0600 or less permissive.

DISCUSSION:
Log files can contain valuable information regarding system configuration. If the 
system log files are not protected, unauthorized users could change the logged data, 
eliminating their forensic value.

         -rw-------. 1 root root 89506 Oct 11 22:47 /var/log/messages
         -rw-------. 1 root root 2434 Oct 11 22:37 /var/log/secure
         -rw-------. 1 root root 339 Oct 11 21:50 /var/log/maillog
         -rw-------. 1 root root 5505 Oct 11 22:01 /var/log/cron
         -rw-------. 1 root root 0 Oct  9 04:40 /var/log/spooler
         
V-38623 COMPLIANT



./pcat2py.py scan --posture RHEL6 --debug 1 --html me
V-38612 NON-COMPLIANT
V-38437 COMPLIANT
V-38493 COMPLIANT
V-38492 COMPLIANT
V-38643 COMPLIANT
V-38531 NON-COMPLIANT
V-38534 NON-COMPLIANT
V-38448 COMPLIANT
V-38647 NON-COMPLIANT
V-38619 COMPLIANT


./pcat2py.py scan --ssh cobra@192.168.1.60 --finding V-38644 --debug 3
Password: 

#############################################
# POSTURE:      RHEL6
# GROUP ID:     V-38644
# GROUP TITLE:  SRG-OS-000096
# RULE ID:      SV-50445r2_rule
# RULE VERSION: RHEL-06-000265
# SEVERITY:     CAT III
#############################################

TITLE:
The ntpdate service must not be running.

DISCUSSION:
The ntpdate service may only be suitable for systems which are rebooted frequently 
enough that clock drift does not cause problems between reboots. In any event, the 
functionality of the ntpdate service is now available in the ntpd program and should 
be considered deprecated.

V-38644 COMPLIANT



./pcat2py.py scan --winrm administrator@pcat2pytest2.phnomlab.net --finding 
HBSPCAT2K8R2MS0000186 --debug 3
Password: 

#############################################
# POSTURE:      2008R2MS
# GROUP ID:     V-26470
# SEVERITY:     CAT II
# HIPPA:        164.312(a)(1)
# PCI:          7.1
# HBS:          HBSPCAT2K8R2MS0000186
# DoD 8500.2:   ECLP-1
# 800 53:       AC-5, AC-6, AC-6(2)
# ISO 27001:    A.10.1.3, A.11.2.2, A.11.4.1, A.11.4.4, A.11.5.4, A.11.6.1, A.12.4.3
#############################################

TITLE:
Unauthorized accounts will not have the ''Access this computer from the network'' 
user right.

DISCUSSION:
Inappropriate granting of user rights can provide system, administrative, and other 
high level capabilities.Accounts with the ''Access this computer from the network'' 
right may access resources on the system and should be limited to those requiring it. 
Set the policy value for Computer Configuration \ Windows Settings \ Security 
Settings \ Local Policies \ User Rights Assignment \ ''Access this computer from the 
network'' as defined.

         SeNetworkLogonRight=
         Everyone
         BUILTIN\Administrators
         BUILTIN\Users
         BUILTIN\Backup Operators
V-26470 NON-COMPLIANT