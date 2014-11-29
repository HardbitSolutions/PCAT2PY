#!/usr/bin/python
################################################################################
# V38595
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/12/2014 Original construction
# 07/13/2014 Removed get_verbose, get_compliance, __init__, set_verbose, and
#            get_output methods. This finding is an inert object.
################################################################################

class Finding:
    def get_severity(self):
        return "CAT II"
    
    def get_rule_id(self):
        return "SV-50396r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000349"
    
    def get_group_id(self):
        return "V-38595"
    
    def get_group_title(self):
        return "SRG-OS-000105"
    
    def get_rule_title(self):
        return "The system must be configured to require the use of a CAC, PIV compliant hardware token, or Alternate Logon Token (ALT) for authentication."
    
    def get_vulnerability_discussion(self):
        return "Smart card login provides two-factor authentication stronger than that provided by a username/password combination. Smart cards leverage a PKI (public key infrastructure) in order to provide and verify credentials."
    def get_posture(self):
        return "RHEL6"