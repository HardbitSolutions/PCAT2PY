#!/usr/bin/python
################################################################################
# V38488
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
        return "SV-50289r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000504"
    
    def get_group_id(self):
        return "V-38488"
    
    def get_group_title(self):
        return "SRG-OS-000099"
    
    def get_rule_title(self):
        return "The operating system must conduct backups of user-level information contained in the operating system per organization defined frequency to conduct backups consistent with recovery time and recovery point objectives."
    
    def get_vulnerability_discussion(self):
        return " Operating system backup is a critical step in maintaining data assurance and availability. User-level information is data generated by information system and/or application users. Backups shall be consistent with organizational recovery time and recovery point objectives."
    def get_posture(self):
        return "RHEL6"