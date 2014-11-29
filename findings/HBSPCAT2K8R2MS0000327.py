
#!/usr/bin/python
################################################################################
# V4113
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
        return r"V-4113"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The system will be configured to limit how often keep-alive packets are sent."

    def get_vulnerability_discussion(self):
        return r"Controls how often TCP sends a keep-alive packet in attempting to verify that an idle connection is still intact. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds? to ?300000 or 5 minutes (recommended)? or less."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters', 'KeepAliveTime')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters', ('KeepAliveTime=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 300000:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\Tcpip'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters' -name 'KeepAliveTime' -value 300000 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008R2MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2MS0000327"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"