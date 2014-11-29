#!/usr/bin/python
################################################################################
# V38625
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
        return "SV-50426r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000252"
    
    def get_group_id(self):
        return "V-38625"
    
    def get_group_title(self):
        return "SRG-OS-000250"
    
    def get_rule_title(self):
        return "If the system is using LDAP for authentication or account information, the system must use a TLS connection using FIPS 140-2 approved cryptographic algorithms."
    
    def get_vulnerability_discussion(self):
        return "The ssl directive specifies whether to use ssl or not. If not specified it will default to ""no"". It should be set to ""start_tls"" rather than doing LDAP over SSL."
    def get_posture(self):
        return "RHEL6"