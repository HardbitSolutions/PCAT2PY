#!/usr/bin/python
################################################################################
# V38626
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
        return "SV-50427r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000253"
    
    def get_group_id(self):
        return "V-38626"
    
    def get_group_title(self):
        return "SRG-OS-000113"
    
    def get_rule_title(self):
        return "The LDAP client must use a TLS connection using trust certificates signed by the site CA."
    
    def get_vulnerability_discussion(self):
        return "The tls_cacertdir or tls_cacertfile directives are required when tls_checkpeer is configured (which is the default for openldap versions 2.1 and up). These directives define the path to the trust certificates signed by the site CA."
    def get_posture(self):
        return "RHEL6"