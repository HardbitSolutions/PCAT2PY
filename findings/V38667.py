#!/usr/bin/python
################################################################################
# V38667
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/10/2014 Original construction
# 07/13/2014 Removed get_verbose, get_compliance, __init__, set_verbose, and
#            get_output methods. This finding is an inert object.
################################################################################

class Finding:
    def get_severity(self):
        return "CAT II"
    
    def get_rule_id(self):
        return "SV-50468r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000285"
    
    def get_group_id(self):
        return "V-38667"
    
    def get_group_title(self):
        return "SRG-OS-000196"
    
    def get_rule_title(self):
        return "The system must have a host-based intrusion detection tool installed."
    
    def get_vulnerability_discussion(self):
        return "Adding host-based intrusion detection tools can provide the capability to automatically take actions in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools also often include a reporting capability to provide network awareness of system, which may not otherwise exist in an organization's systems management regime."
    def get_posture(self):
        return "RHEL6"