
#!/usr/bin/python
################################################################################
# V1139
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
        return r"V-1139"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The option to prevent the password in dial-up networking from being saved is not enabled."

    def get_vulnerability_discussion(self):
        return r"The default Windows configuration enables the option to save the password used to gain access to a remote server using the dial-up networking feature.  With this option enabled, an unauthorized user who gains access to a Windows machine would also have access to remote servers with which the  machine uses dial-up networking to communicate.  Disabling this option will introduce another layer of security and help limit the scope of any security compromise to the local machine. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?MSS: (DisableSavePassword) Prevent the dial-up password from being saved (recommended)? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Services\RasMan\Parameters', 'DisableSavePassword')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Services\RasMan\Parameters', ('DisableSavePassword=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\RasMan'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\RasMan\Parameters'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\RasMan\Parameters' -name 'DisableSavePassword' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "XP"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCATWINXP000050"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"