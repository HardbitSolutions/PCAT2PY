#!/usr/bin/python
################################################################################
# V38520
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/08/2014 Original construction
# 07/13/2014 Removed get_verbose, get_compliance, __init__, set_verbose, and
#            get_output methods. This finding is an inert object.
################################################################################

class Finding:
    def get_severity(self):
        return "CAT II"
    
    def get_rule_id(self):
        return "SV-50321r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000136"
    
    def get_group_id(self):
        return "V-38520"
    
    def get_group_title(self):
        return "SRG-OS-000215"
    
    def get_rule_title(self):
        return "The operating system must back up audit records on an organization defined frequency onto a different system or media than the system being audited."
    
    def get_vulnerability_discussion(self):
        return "A log server (loghost) receives syslog messages from one or more systems. This data can be used as an additional log source in the event a system is compromised and its local logs are suspect. Forwarding log messages to a remote loghost also provides system administrators with a centralized place to view the status of multiple hosts within the enterprise."
    def get_posture(self):
        return "RHEL6"