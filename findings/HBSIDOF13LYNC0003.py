
#!/usr/bin/python
################################################################################
# V40778
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
        return r"V-40778"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"In the event a secure Session Initiation Protocol (SIP) connection fails, the connection must be restricted from resorting to the unencrypted HTTP."

    def get_vulnerability_discussion(self):
        return r"Lync 2013 provides a single, unified client for real-time communications, including voice and video calls, Lync Meetings, presence, instant messaging, and persistent chat. The Lync client has a fall back option so that, in the event the Lync client cannot make a secure SIP connection to the Lync server, it will fall back to an unencrypted HTTP connection. In that event, all traffic will be unencrypted and in clear text. The configuration must be set to prevent HTTP being used for SIP connections in the event TLS or TCP fail. Set the policy value for: Computer Configuration \ Administrative Templates \ Microsoft Lync 2013 \ Microsoft Lync Feature Policies ''Disable HTTP fallback for SIP connection'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\office\15.0\lync', 'disablehttpconnect')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\office\15.0\lync', ('disablehttpconnect=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\office'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\office\15.0'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\office\15.0\lync'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\office\15.0\lync' -name 'disablehttpconnect' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Lync"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Lync0003"
    
    def get_dod8500_2(self):
        return ""

    def get_800_53(self):
        return "MA-4"
    
    def get_iso_27001(self):
        return "A.9.2.4, A.11.4.4"