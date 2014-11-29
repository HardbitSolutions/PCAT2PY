
#!/usr/bin/python
################################################################################
# V1174
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated DWORD LE finding
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
        return r"V-1174"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Amount of idle time required before suspending a session is improperly set."

    def get_vulnerability_discussion(self):
        return r"Administrators should use this setting to control when a computer disconnects an inactive SMB session. If client activity resumes, the session is automatically reestablished.  This protects critical and sensitive network data from exposure to unauthorized personnel with physical access to the computer. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?Microsoft Network Server: Amount of idle time required before suspending a session? to ?15? minutes or less."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters', 'AutoDisconnect')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters', ('AutoDisconnect=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword <= 15:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\LanManServer'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters' -name 'AutoDisconnect' -value 15 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2003DC"

    def get_hippa(self):
        return "164.312(c)(1)"
    
    def get_pci(self):
        return "12.3.8"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3DC000073"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"