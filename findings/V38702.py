#!/usr/bin/python
################################################################################
# V38702
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
        return "SV-50503r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000339"
    
    def get_group_id(self):
        return "V-38702"
    
    def get_group_title(self):
        return "SRG-OS-000037"
    
    def get_rule_title(self):
        return "The FTP daemon must be configured for logging or verbose mode."
    
    def get_vulnerability_discussion(self):
        return "To trace malicious activity facilitated by the FTP service, it must be configured to ensure that all commands sent to the ftp server are logged using the verbose vsftpd log format. The default vsftpd log file is /var/log/vsftpd.log."
    def get_posture(self):
        return "RHEL6"