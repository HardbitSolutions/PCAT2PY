
#!/usr/bin/python
################################################################################
# V3454
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated DWORD EQ finding
#
# 09/21/2014 Original Construction
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
        return r"V-3454"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Terminal Services is not configured with the client connection encryption set to the required level."

    def get_vulnerability_discussion(self):
        return r"Remote connections must be encrypted to prevent interception of data or sensitive information.  Selecting ?High Level? will ensure encryption of Terminal Services sessions in both directions. Set the policy value for Computer Configuration \ Administrative Templates \ Windows Components \ Terminal Services \ Encryption and Security ?Set Client Connection Encryption Level? to ?Enabled? and select ?High Level? for the ?Encryption Level?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services', 'MinEncryptionLevel')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services', ('MinEncryptionLevel=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 3:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows NT'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' -name 'MinEncryptionLevel' -value 3 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "XP"

    def get_hippa(self):
        return "164.312(a)(2)(iv),164.312(e)(2)(ii)"
    
    def get_pci(self):
        return "8.3,8.5,4.1,3.6,2.3"
    
    def get_hbs_id(self):
        return "HBSPCATWINXP000168"
    
    def get_dod8500_2(self):
        return "ECCT-1, ECCT-2"

    def get_800_53(self):
        return "AC-17(2),AC-18(1),SC-9,SC-9(1),SC-13,SC-13(1)"
    
    def get_iso_27001(self):
        return "A.10.6.1, A.10.8.1, A.10.8.5, A.11.4.1, A.11.4.2, A.11.4.6,  A.11.7.1, A.11.7.2, A.10.9.1, A.10.9.2, A.15.1.6"