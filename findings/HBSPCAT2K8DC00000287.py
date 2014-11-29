
#!/usr/bin/python
################################################################################
# V39327
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
        return r"V-39327"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Active Directory Infrastructure object must be configured with proper audit settings."

    def get_vulnerability_discussion(self):
        return r"When inappropriate audit settings are configured for directory service database objects, it may be possible for a user or process to update the data without generating any tracking data.  The impact of missing audit data is related to the type of object.  A failure to capture audit data for objects used by identification, authentication, or authorization functions could degrade or eliminate the ability to track changes to access policy for systems or data. For Active Directory (AD), there are a number of critical object types in the domain naming context of the AD database for which auditing is essential.  This includes the Infrastructure object.  Because changes to these objects can significantly impact access controls or the availability of systems, the absence of auditing data makes it impossible to identify the source of changes that impact the confidentiality, integrity, and availability of data and systems throughout an AD domain.  The lack of proper auditing can result in insufficient forensic evidence needed to investigate an incident and prosecute the intruder. Set the audit settings for Infrastructure object to include the following.Type - FailName - EveryoneAccess - Full ControlInherited From - <not inherited>The success types listed below are defaults. Where Special is listed in the summary screens for Access, detailed Permissions are provided for reference, various Properties selections may also exist by default.Type - SuccessName - EveryoneAccess - SpecialInherited From - <not inherited>(Access - Special = Permissions: Write all properties, All extended rights, Change infrastructure master)Two instances with the following summary information will be listed.Type - SuccessName - EveryoneAccess - (blank)Inherited From - (CN of domain)"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008DC"

    def get_hippa(self):
        return "164.308(a)(5)(ii)(C),164.312(b)"
    
    def get_pci(self):
        return "10.2,10.3,10.7"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8DC00000287"
    
    def get_dod8500_2(self):
        return "ECAR-1, ECAR-2, ECAR-3"

    def get_800_53(self):
        return "AU-2, AU-3, AU-8"
    
    def get_iso_27001(self):
        return "A.10.10.1, A.10.10.2, A.10.10.4, A.10.10.5, A.11.5.4, A.15.3.1, A.10.10.6, A.13.2.3"