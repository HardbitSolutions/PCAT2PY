#!/usr/bin/python
################################################################################
# V38439
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/15/2014 Original construction
# 07/13/2014 Removed get_verbose, get_compliance, __init__, set_verbose, and
#            get_output methods. This finding is an inert object.
################################################################################

class Finding:
    def get_severity(self):
        return "CAT II"
    
    def get_rule_id(self):
        return "SV-50239r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000524"
    
    def get_group_id(self):
        return "V-38439"
    
    def get_group_title(self):
        return "SRG-OS-000001"
    
    def get_rule_title(self):
        return "The system must provide automated support for account management functions."
    
    def get_vulnerability_discussion(self):
        return "A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. Enterprise environments make user account management challenging and complex. A user management process requiring administrators to manually address account management functions adds risk of potential oversight."
    def get_posture(self):
        return "RHEL6"