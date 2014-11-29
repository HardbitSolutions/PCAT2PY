#!/usr/bin/python
################################################################################
# PCAT2PY
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# The purpose of this exercise is to gain a working understanding for capturing
# standard out and processing output line by line while being backwards
# compatible to Python 2.6.6.
#
# 05/28/2014 Original construction
# 06/29/2014 Added help page
#            Added remote switch for scanning remote hosts
#            Added automatic CLI selection and object instantiation
#            Added remarks
# 07/01/2014 Added HTML report generation
# 07/09/2014 Version Control Test
# 07/13/2014 Moved all compliance evaluation code into the PCAT2PY session
#            object class. This code now serves as a command line wrapper for
#            a session object. Arguments and modes have been collapsed. List, 
#            verbose, and show arguments have been removed. Debug switch has 
#            been rewritten to set the debugging level for the session object.
# 07/19/2014 Changed appending findings and setting debug mode to direct access
#            to members instead of mutation methods.
# 07/26/2014 Add password switch to supply passwords as an argument
# 08/17/2014 Collapsed lib sub-directory
# 09/13/2014 Replace remote switch with ssh and winrm switches
# 09/17/2014 Corrected logon string bug in switches
# 09/19/2014 Added posture switch and removed all "findings selected if none
#            specified" logic. Findings will only be appended if an os or
#            finding switch has been set
# 09/20/2014 Added syntax exception handling to loading findings
# 10/09/2014 Fixed logical bug in load findings block
# 10/11/2014 Updated the help message
################################################################################

import os
import sys
import getpass
import session
import presentation

#### User Dialog #############################
def help_message():
    print """
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

PCAT2PY is able scan and remediate Red Hat and Windows environments using
the following postures:

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
     
Examples:
    ./pcat2py.py scan --finding V-38623 --debug 3
    ./pcat2py.py scan --posture RHEL6 --debug 1 --html me
    ./pcat2py.py scan --ssh cobra@192.168.1.60 --finding V-38644 --debug 3
    ./pcat2py.py scan --winrm administrator@pcat2pytest2.phnomlab.net --finding 
        HBSPCAT2K8R2MS0000186 --debug 3
    """


#### Setup and Configure PCAT2PY Session #####
# Create a PCAT2PY session object and configure it based on the provided
# command line arguments. Switches have been setup for debugging, remote hosts,
# selected findings, and HTML report generation. If no arguments have been
# provided, the help message is displayed. If the remote switch has been set,
# start the SSH CLI inside of the session object.
selected_findings = []
selected_posture = []
logon_strings = []
html_filename = ''
current_session = session.Session()
protocol = 0

# Loop through all the command line arguments and look for switch statements.
# Check to see if a string is prepended by '-' for single character switches or 
# '--' for multicharacter switches signalling options.
for i in range(1, len(sys.argv)):
    if str(sys.argv[i]).startswith("-"):
        if str(sys.argv[i])[1] == "-":
            # Debug level switch
            if str(sys.argv[i])[2:] == "debug" and i + 1 < len(sys.argv):
                if int(sys.argv[i + 1]) in range(0, 4):
                    current_session.debug_mode = int(sys.argv[i + 1])
            
            # Finding switch
            if str(sys.argv[i])[2:] == "finding" and i + 1 < len(sys.argv):
                for element in str(sys.argv[i + 1]).split(','): 
                    selected_findings.append(element)
                    
            # Posture switch
            if str(sys.argv[i])[2:] == "posture" and i + 1 < len(sys.argv):
                selected_posture = str(sys.argv[i + 1]) 
            
            # SSH switch
            if str(sys.argv[i])[2:] == "ssh" and i + 1 < len(sys.argv):
                logon_strings = str(sys.argv[i + 1]).split('@')
                protocol = 1
                
            # WINRM switch
            if str(sys.argv[i])[2:] == "winrm" and i + 1 < len(sys.argv):
                logon_strings = str(sys.argv[i + 1]).split('@')
                protocol = 2
            
            # Password switch
            if str(sys.argv[i])[2:] == "password" and i + 1 < len(sys.argv):
                if len(logon_strings) == 2:
                    logon_strings.append(str(sys.argv[i + 1]).strip())
                
            # HTML report switch
            if str(sys.argv[i])[2:] == "html" and i + 1 < len(sys.argv):
                html_filename = str(sys.argv[i + 1])
                if ".html" not in html_filename: html_filename += ".html"

# Setup remote connection if logon_strings has been populated.
# logon_string[0]: username
# logon_string[1]: remote host
# logon_string[2]: password
if len(logon_strings) == 2 and protocol == 1:
    current_session.connect_ssh_cli(logon_strings[1], 
                                    logon_strings[0], 
                                    getpass.getpass('Password: '))
if len(logon_strings) == 3 and protocol == 1:
    current_session.connect_ssh_cli(logon_strings[1], 
                                    logon_strings[0], 
                                    logon_strings[2])
if len(logon_strings) == 2 and protocol == 2:
    current_session.connect_winrm_cli(logon_strings[1], 
                                      logon_strings[0], 
                                      getpass.getpass('Password: '))
if len(logon_strings) == 3 and protocol == 2:
    current_session.connect_winrm_cli(logon_strings[1], 
                                      logon_strings[0], 
                                      logon_strings[2])


# If no command line arguments are present then display help message and exit.
if len(sys.argv) == 1:
    help_message()
    sys.exit(1)
                
#### Load Findings ###########################
# All findings are located within a subdirectory called findings
# Findings will be imported if they have class definition named Finding
sys.path.insert(0, os.getcwd() + "/findings")
detected_modules = os.listdir(os.getcwd() + "/findings")

# Loop through the detected findings. If no finding arguments were present,
# import the all of the detected findings. If finding arguments are present,
# only import a finding if it has the specified severity, group id, group title,
# rule id, or rule version
for module_name in detected_modules:
	if module_name.endswith(".py"):
		try:
                    module = __import__(module_name[:-3])
		
                    if hasattr(module, "Finding"): 
                        finding = module.Finding()

                        if hasattr(finding, "get_posture"):
                            if finding.get_posture() in selected_posture: 
                                current_session.findings.append(finding)
                        if hasattr(finding, "get_group_id"):
                            if finding.get_group_id() in selected_findings: 
                                current_session.findings.append(finding)
                        if hasattr(finding, "get_hbs_id"):
                            if finding.get_hbs_id() in selected_findings: 
                                current_session.findings.append(finding)
                        
                except SyntaxError as e:
                    print e




#### Scan ####################################
# Execute the scan method in the session object. If an HTML filename was
# specified, execute the create HTML report method as well. Exit after
# completing scan and HTML report.
if(sys.argv[1] == "scan"):
    current_session.scan()
    
    if html_filename:
        presentation.create_html_report(current_session, html_filename)
    
    sys.exit(0)




#### Remediate ###############################
# Execute the remediate method in the session object. If an HTML filename was
# specified, execute the create HTML report method as well. Exit after
# completing scan and HTML report.
elif(sys.argv[1] == "remediate"):
    current_session.remediate()
    
    if html_filename:
        presentation.create_html_report(current_session, html_filename)
    
    sys.exit(0)