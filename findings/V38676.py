#!/usr/bin/python
################################################################################
# V38676
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/19/2014 Original construction
# 07/13/2014 Removed get_verbose, get_compliance, __init__, set_verbose, and
#            get_output methods. This finding is an inert object.
################################################################################

class Finding:
    def get_severity(self):
        return "CAT III"
    
    def get_rule_id(self):
        return "SV-50477r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000291"
    
    def get_group_id(self):
        return "V-38676"
    
    def get_group_title(self):
        return "SRG-OS-999999"
    
    def get_rule_title(self):
        return "The xorg-x11-server-common (X Windows) package must not be installed, unless required."
    
    def get_vulnerability_discussion(self):
        return "Unnecessary packages should not be installed to decrease the attack surface of the system."
    def get_posture(self):
        return "RHEL6"