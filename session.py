#!/usr/bin/python
################################################################################
# SESSION
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# phnomcobra@gmail.com
#
# PCAT2PY Session class. This class contains all methods and members for 
# encapsulating individual PCAT2PY sessions. This class has methods for 
# scanning, remediating, HTML report generation, local or SSH CLI objects, and 
# finding debugging.
#
# 07/09/2014 Original construction
# 07/13/2014 Implemented debugging levels, local and SSH CLI, and HTML
# 07/18/2014 Renamed filename to session.py
# 07/19/2014 Switched to all public methods and members
#            Offloaded print_verbose and create_html_report to presentation.py
# 09/13/2014 Added connect_winrm_cli :)
# 09/21/2014 Added NameError exception handling to scan and remediate methods
################################################################################

import ssh_cli
import local_cli
import presentation
import winrm_cli
import traceback

class Session:
    def __init__(self):
        self.cli = local_cli.Console()
	self.findings = []
        self.html = ''
        self.debug_mode = 0
    
    def debug_finding(self, finding):
        # Print debugging information based on debug level
        # Level 1: id and compliance status
        # Level 2: verbose finding details
        # Level 3: standard output from check method
        status = 'MANUAL'
        if hasattr(finding, 'get_compliance'):
            if finding.get_compliance():
                status = 'COMPLIANT'
            else: 
                status = 'NON-COMPLIANT'
        
        if self.debug_mode > 1: 
            presentation.print_verbose(finding)
            if self.debug_mode > 2 and hasattr(finding, 'get_output'):
                for line in finding.get_output():
                    print "         " + line.strip()
        
        if hasattr(finding, "get_group_id"):
            print finding.get_group_id() + " " + status
        
    def scan(self):
        for finding in self.findings:
            if (hasattr(finding, "check")): 
                try:
                    finding.check(self.cli)

                    if self.debug_mode:
                        self.debug_finding(finding)
                except NameError:
                    print "\n***********************"
                    print "scan NameError:"
                    print traceback.format_exc()
                    print "***********************\n"
                
        
    def remediate(self):
        for finding in self.findings:
            if (hasattr(finding, "check")): 
                try:
                    if not finding.check(self.cli):
                        if (hasattr(finding, "fix")): 
                            finding.fix(self.cli)
                            finding.check(self.cli)

                    if self.debug_mode:
                        self.debug_finding(finding)
                except NameError:
                    print "\n***********************"
                    print "remediate NameError:"
                    print traceback.format_exc()
                    print "***********************\n"

        
    def connect_ssh_cli(self, host, username, password):
        self.cli = ssh_cli.Console()
        self.cli.set_username(username)
        self.cli.set_password(password)
        self.cli.set_remote_host(host)
        self.cli.connect()
        
    def connect_winrm_cli(self, host, username, password):
        self.cli = winrm_cli.Console()
        self.cli.set_username(username)
        self.cli.set_password(password)
        self.cli.set_remote_host(host)
        self.cli.connect_http()