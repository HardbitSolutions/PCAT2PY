
#!/usr/bin/python
################################################################################
# V6319
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
        return r"V-6319"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Error Reporting tool for IE is installed or enabled."

    def get_vulnerability_discussion(self):
        return r"An error reporting tool may send sensitive data to a vendor. Manipulate the registry key HKLM\Software\Microsoft\Internet Explorer\Main.  Make sure that the key exists and the value data for the IEWatsonEnabled value is 0 (the number zero)."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\ Software\Microsoft\Internet Explorer\Main', 'IEWatsonEnabled')

        # Output Lines
        self.__output = [r'HKLM:\ Software\Microsoft\Internet Explorer\Main', ('IEWatsonEnabled=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\ Software\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\ Software\Microsoft\Internet Explorer'")
        cli.powershell(r"New-Item -path 'HKLM:\ Software\Microsoft\Internet Explorer\Main'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\ Software\Microsoft\Internet Explorer\Main' -name 'IEWatsonEnabled' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE6"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE6000087"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"