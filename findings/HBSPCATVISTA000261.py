
#!/usr/bin/python
################################################################################
# V6850
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated MANUAL finding
#
# 09/30/2014 Original Construction
################################################################################

class Finding:
    # Initialize compliance
    def __init__(self):
        self.__verbose = False
        self.__output = []
        self.__is_compliant = []

    def get_verbose(self):
        return self.__verbose

    def get_output(self):
        return self.__output

    def get_severity(self):
        return "CAT II"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-6850"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Auditing must be configured as required."

    def get_vulnerability_discussion(self):
        return r"Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. Set the system to audit subcategories as outlined below.Open a Command Prompt with elevated privileges.  (Run as administrator).Execute the following command for each subcategory. Auditpol /set /subcategory:''subcategory name'' /success:enable(disable) /failure:enable(disable)(Include the quotes around the subcategory name).SystemSecurity System Extension - Success and FailureSystem Integrity - Success and FailureIPSec Driver - Success and FailureSecurity State Change - Success and FailureLogon/Logoff       Logon - Success and Failure Logoff - SuccessSpecial Logon - SuccessObject Access             File System - FailureRegistry - FailurePrivilege Use       Sensitive Privilege Use - Success and FailureDetailed Tracking       Process Creation - SuccessPolicy Change       Audit Policy Change - Success and FailureAuthentication Policy Change - SuccessAccount Management       User Account Management - Success and FailureComputer Account Management - Success and FailureSecurity Group Management - Success and FailureOther Account Management Events - Success and FailureAccount Logon       Credential Validation - Success and Failure"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "Vista"

    def get_hippa(self):
        return "164.312(b)"
    
    def get_pci(self):
        return "10.3.4"
    
    def get_hbs_id(self):
        return "HBSPCATVISTA000261"
    
    def get_dod8500_2(self):
        return "ECAR-2, ECAR-3"

    def get_800_53(self):
        return "AU-2 ,AU-3,AU-8"
    
    def get_iso_27001(self):
        return "A.10.10.1, A.10.10.2, A.10.10.4, A.10.10.5, A.11.5.4, A.15.3.1, A.10.10.6, A.13.2.3"