#!/usr/bin/python
################################################################################
# V38662
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
        return "SV-50463r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000277"
    
    def get_group_id(self):
        return "V-38662"
    
    def get_group_title(self):
        return "SRG-OS-000230"
    
    def get_rule_title(self):
        return "The operating system must employ cryptographic mechanisms to prevent unauthorized disclosure of data at rest unless otherwise protected by alternative physical measures."
    
    def get_vulnerability_discussion(self):
        return "The risk of a system's physical compromise, particularly mobile systems such as laptops, places its data at risk of compromise. Encrypting this data mitigates the risk of its loss if the system is lost."
    def get_posture(self):
        return "RHEL6"