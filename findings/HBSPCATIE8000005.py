
#!/usr/bin/python
################################################################################
# V32808
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
        return r"V-32808"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Check for publishers certificate revocation must be enforced."

    def get_vulnerability_discussion(self):
        return r"Check for publisher''s certificate revocation options should be enforced to ensure all PKI signed objects are validated. Check mark the option to enable ''Check for publishers certificate revocation'' in the Internet Explorer Options, Advanced page. NOTE: Manual entry for the value State, set to REG_DWORD = 65536, may first be required."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing', 'State')

        # Output Lines
        self.__output = [r'HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing', ('State=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 65536:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing' -name 'State' -value 65536 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE8"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE8000005"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"