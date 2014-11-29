
#!/usr/bin/python
################################################################################
# V1084
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
        return r"V-1084"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"System pagefile is cleared upon shutdown."

    def get_vulnerability_discussion(self):
        return r"This check verifies that Windows is not configured to wipe clean the system page file during a controlled system shutdown. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?Shutdown: Clear virtual memory pagefile? to ?Disabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management', 'ClearPageFileAtShutdown')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management', ('ClearPageFileAtShutdown=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control\Session Manager'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management' -name 'ClearPageFileAtShutdown' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Vista"

    def get_hippa(self):
        return "164.312(c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCATVISTA000012"
    
    def get_dod8500_2(self):
        return "ECRC-1"

    def get_800_53(self):
        return "SC-4"
    
    def get_iso_27001(self):
        return ""