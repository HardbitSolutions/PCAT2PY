#!/usr/bin/python
################################################################################
# V38481
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/04/2014 Original construction
# 07/13/2014 Removed get_verbose, get_compliance, __init__, set_verbose, and
#            get_output methods. This finding is an inert object.
################################################################################

class Finding:
    def get_severity(self):
        return "CAT II"
    
    def get_rule_id(self):
        return "SV-50281r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000011"
    
    def get_group_id(self):
        return "V-38481"
    
    def get_group_title(self):
        return "SRG-OS-000191"
    
    def get_rule_title(self):
        return "System security patches and updates must be installed and up-to-date."
    
    def get_vulnerability_discussion(self):
        return "Installing software updates is a fundamental mitigation against the exploitation of publicly-known vulnerabilities."
    def get_posture(self):
        return "RHEL6"