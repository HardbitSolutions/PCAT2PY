
#!/usr/bin/python
################################################################################
# V1160
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated BINARY EQ finding
#
# 09/23/2014 Original Construction
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
        return r"V-1160"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The unsigned driver installation behavior is improperly set."

    def get_vulnerability_discussion(self):
        return r"Determines what should happen when an attempt is made to install a device driver (by means of the Windows device installer) that has not been certified by the Windows Hardware Quality Lab (WHQL).The options are:- Silently succeed- Warn but allow installation- Do not allow installation Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?Devices: Unsigned driver installation behavior? to ?Warn but allow installation? or ?Do not allow installation?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry BINARY
        binary = cli.get_reg_binary(r'HKLM:\Software\Microsoft\Driver Signing', 'Policy')

        # Output Lines
        self.__output = [r'HKLM:\Software\Microsoft\Driver Signing', ('Policy=')] + binary

        if self.__verbose:
            print self.__output

        if len(binary) == 1:
            if int(binary[0], 0) == 1:
                self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Driver Signing'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Microsoft\Driver Signing' -name 'Policy' -Type Binary -value 1")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2003DC"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3DC000063"
    
    def get_dod8500_2(self):
        return "DCSL-1"

    def get_800_53(self):
        return "CM-5(6)"
    
    def get_iso_27001(self):
        return "A.10.1.2, A.12.4.1, A.12.4.3, A.12.5.3"