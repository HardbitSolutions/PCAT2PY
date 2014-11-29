#!/usr/bin/python
################################################################################
# V38685
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
        return "SV-50486r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000297"
    
    def get_group_id(self):
        return "V-38685"
    
    def get_group_title(self):
        return "SRG-OS-000002"
    
    def get_rule_title(self):
        return "Temporary accounts must be provisioned with an expiration date."
    
    def get_vulnerability_discussion(self):
        return "When temporary accounts are created, there is a risk they may remain in place and active after the need for them no longer exists. Account expiration greatly reduces the risk of accounts being misused or hijacked."
    def get_posture(self):
        return "RHEL6"