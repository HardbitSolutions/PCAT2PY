
#!/usr/bin/python
################################################################################
# V7006
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated DWORD OR finding
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
        return r"V-7006"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The IE search parameter is not set correctly."

    def get_vulnerability_discussion(self):
        return r"This parameter ensures automatic searches are not performed from the address bar.  When a web site is not found and searching is performed, potentially malicious or unsuited sites may be displayed. Manipulate the value: HKCU\Software\Microsoft\Internet Explorer\MainEnsure the value AutoSearch is  0 or 4"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Microsoft\Internet Explorer\Main', 'AutoSearch')

        # Output Lines
        self.__output = [r'HKCU:\Software\Microsoft\Internet Explorer\Main', ('AutoSearch=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0  or dword ==  4:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Internet Explorer'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Internet Explorer\Main'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Microsoft\Internet Explorer\Main' -name 'AutoSearch' -value 0 or 4 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE6"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE6000010"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"