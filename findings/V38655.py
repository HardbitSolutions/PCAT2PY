#!/usr/bin/python
################################################################################
# V38655
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/09/2014 Original construction
# 06/19/2014 Removed check method
# 07/13/2014 Removed get_verbose, get_compliance, __init__, set_verbose, and
#            get_output methods. This finding is an inert object.
################################################################################

class Finding:
    def get_severity(self):
        return "CAT III"
    
    def get_rule_id(self):
        return "SV-50456r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000271"
    
    def get_group_id(self):
        return "V-38655"
    
    def get_group_title(self):
        return "SRG-OS-000035"
    
    def get_rule_title(self):
        return "The noexec option must be added to removable media partitions."
    
    def get_vulnerability_discussion(self):
        return "Allowing users to execute binaries from removable media such as USB keys exposes the system to potential compromise."
    def get_posture(self):
        return "RHEL6"