
#!/usr/bin/python
################################################################################
# V6252
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
        return r"V-6252"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Don''t prompt for client certificate selection when no certificate or only one certificate exists is not set properly for the Internet Zone."

    def get_vulnerability_discussion(self):
        return r"Client certificates should not be presented to web sites without the user''s acknowledgement. Manipulate the registry key to read as follows: HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3Criteria: Set the value 1A04 to REG_DWORD=3 (Disabled)."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3', '1A04')

        # Output Lines
        self.__output = [r'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3', ('1A04=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 3:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3' -name '1A04' -value 3 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE6"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE6000028"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"