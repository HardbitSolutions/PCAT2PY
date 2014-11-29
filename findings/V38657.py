#!/usr/bin/python
################################################################################
# V38657
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
        return "SV-50448r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000273"
    
    def get_group_id(self):
        return "V-38657"
    
    def get_group_title(self):
        return "SRG-OS-999999"
    
    def get_rule_title(self):
        return "The system must use SMB client signing for connecting to samba servers using mount.cifs."
    
    def get_vulnerability_discussion(self):
        return "Packet signing can prevent man-in-the-middle attacks which modify SMB packets in transit."
    def get_posture(self):
        return "RHEL6"