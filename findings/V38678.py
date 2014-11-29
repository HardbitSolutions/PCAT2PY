#!/usr/bin/python
################################################################################
# V38678
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/11/2014 Original construction
# 07/13/2014 Removed get_verbose, get_compliance, __init__, set_verbose, and
#            get_output methods. This finding is an inert object.
################################################################################

class Finding:
    def get_severity(self):
        return "CAT II"
    
    def get_rule_id(self):
        return "SV-50479r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000311"
    
    def get_group_id(self):
        return "V-38678"
    
    def get_group_title(self):
        return "SRG-OS-000048"
    
    def get_rule_title(self):
        return "The audit system must provide a warning when allocated audit record storage volume reaches a documented percentage of maximum audit record storage capacity."
    
    def get_vulnerability_discussion(self):
        return "Notifying administrators of an impending disk space problem may allow them to take corrective action prior to any disruption."
    def get_posture(self):
        return "RHEL6"