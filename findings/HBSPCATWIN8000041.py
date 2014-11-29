
#!/usr/bin/python
################################################################################
# V1158
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
        return r"V-1158"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Recovery Console SET command must be disabled."

    def get_vulnerability_discussion(self):
        return r"The Recovery Console SET command allows environment variables to be set in the Recovery Console.  This permits access to all drives and folders  and the copying of files to removable media which could expose sensitive information. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ''Recovery Console: Allow floppy copy and access to all drives and folders'' to ''Disabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole', 'SetCommand')

        # Output Lines
        self.__output = [r'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole', ('SetCommand=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole' -name 'SetCommand' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Win8"

    def get_hippa(self):
        return "164.312(c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCATWIN8000041"
    
    def get_dod8500_2(self):
        return "ECCD-1, ECCD-2"

    def get_800_53(self):
        return "AC-3, AC-3(3), AC-3(4)"
    
    def get_iso_27001(self):
        return "A.7.2.2, A.10.6.1, A.10.7.3, A.10.7.4, A.10.8.1 A.10.9.1, A.10.9.2, A.10.9.3, A.11.2.2, A.11.5.4, A.11.6.1, A.12.4.3, A.15.1.3"