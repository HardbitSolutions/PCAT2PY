
#!/usr/bin/python
################################################################################
# V1118A
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated DWORD GE finding
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
        return r"V-1118A"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Event log sizes do not meet minimum requirements."

    def get_vulnerability_discussion(self):
        return r"Inadequate log size will cause the log to fill up quickly and require frequent clearing by administrative personnel. Set the system to have the required minimum Event log sizes."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application', 'MaxSize')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application', ('MaxSize=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword >= 16384:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\EventLog'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application' -name 'MaxSize' -value 16384 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2003MS"

    def get_hippa(self):
        return "164.312(b),164.312(c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3MS000032"
    
    def get_dod8500_2(self):
        return "ECRR-1"

    def get_800_53(self):
        return "AU-11"
    
    def get_iso_27001(self):
        return "A.10.10.1, A.13.2.3, A.15.1.3"