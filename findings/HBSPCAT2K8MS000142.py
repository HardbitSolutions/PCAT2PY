
#!/usr/bin/python
################################################################################
# V15712
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
        return "CAT III"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-15712"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Search ? Exchange Folder Indexing"

    def get_vulnerability_discussion(self):
        return r"This check verifies that mail items on a Microsoft Exchange server are not indexed when Outlook is run in uncached mode. Vista/2008 SP2 or Search 4.0 installed:Set the policy value for Computer Configuration \ Administrative Templates \ Windows Components \ Search ?Enable indexing uncached Exchange folders? to ?Disabled?.  Prior to Vista/2008 SP2 or Search 4.0 installation, the policy name is ?Prevent indexing uncached Exchange folders? and will be set to ?Enabled?.  The registry Value Name and Value referenced in the manual check remain the same."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Windows\Windows Search', 'PreventIndexingUncachedExchangeFolders')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Windows\Windows Search', ('PreventIndexingUncachedExchangeFolders=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' -name 'PreventIndexingUncachedExchangeFolders' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8MS000142"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"