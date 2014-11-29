#!/usr/bin/python
################################################################################
# V38621
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/09/2014 Original construction
# 07/13/2014 Removed get_verbose, get_compliance, __init__, set_verbose, and
#            get_output methods. This finding is an inert object.
################################################################################

class Finding:
    def get_severity(self):
        return "CAT II"
    
    def get_rule_id(self):
        return "SV-50422r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000248"
    
    def get_group_id(self):
        return "V-38621"
    
    def get_group_title(self):
        return "SRG-OS-000056"
    
    def get_rule_title(self):
        return "The system clock must be synchronized to an authoritative DoD time source."
    
    def get_vulnerability_discussion(self):
        return "Synchronizing with an NTP server makes it possible to collate system logs from multiple sources or correlate computer events with real time events. Using a trusted NTP server provided by your organization is recommended."
    def get_posture(self):
        return "RHEL6"