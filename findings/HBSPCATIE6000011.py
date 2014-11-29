
#!/usr/bin/python
################################################################################
# V6236
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
        return r"V-6236"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The IE signature checking parameter is not set correctly."

    def get_vulnerability_discussion(self):
        return r"This parameter will ensure digital signatures are checked on downloaded programs. Manipulate the value of registry key HKCU\Software\Microsoft\Internet Explorer\Download to CheckExeSignatures is yes."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Microsoft\Internet Explorer\Download', 'CheckExeSignatures')

        # Output Lines
        self.__output = [r'HKCU:\Software\Microsoft\Internet Explorer\Download', ('CheckExeSignatures=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == yes:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Internet Explorer'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Internet Explorer\Download'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Microsoft\Internet Explorer\Download' -name 'CheckExeSignatures' -value yes -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE6"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE6000011"
    
    def get_dod8500_2(self):
        return "DCMC-1"

    def get_800_53(self):
        return "SC-18, SC-18(2), SC-18(3), SC-18(4)"
    
    def get_iso_27001(self):
        return "A.10.4.2, A.12.4.1"