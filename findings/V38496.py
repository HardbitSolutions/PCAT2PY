#!/usr/bin/python
################################################################################
# V38496
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
        return "SV-50297r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000029"
    
    def get_group_id(self):
        return "V-38496"
    
    def get_group_title(self):
        return "SRG-OS-999999"
    
    def get_rule_title(self):
        return "Default operating system accounts, other than root, must be locked."
    
    def get_vulnerability_discussion(self):
        return "Disabling authentication for default system accounts makes it more difficult for attackers to make use of them to compromise a system."
    def get_posture(self):
        return "RHEL6"