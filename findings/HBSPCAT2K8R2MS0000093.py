
#!/usr/bin/python
################################################################################
# V14268
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
        return r"V-14268"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Zone information will be preserved when saving attachments."

    def get_vulnerability_discussion(self):
        return r"This check verifies that file attachments are marked with their zone of origin allowing Windows to determine risk. Set the policy value for User Configuration \ Administrative Templates \ Windows Components \ Attachment Manager \ ?Do not preserve zone information in file attachments? to ?Disabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments', 'SaveZoneInformation')

        # Output Lines
        self.__output = [r'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments', ('SaveZoneInformation=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 2:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments' -name 'SaveZoneInformation' -value 2 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008R2MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2MS0000093"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"