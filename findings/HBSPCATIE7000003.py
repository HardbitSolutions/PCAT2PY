
#!/usr/bin/python
################################################################################
# V6238
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
        return r"V-6238"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The IE SSL/TLS parameter must be set correctly."

    def get_vulnerability_discussion(self):
        return r"This parameter ensures  only approved ciphers and algorithms are enabled for use by the web browser. TLS and SSL are protocols for protecting communication between the browser and the target server.  When the browser attempts to set up a protected communication with the target server, the browser and server negotiate which protocol and version to use.  The browser and server attempt to match each other?s list of supported protocols and versions and pick the most preferred match. Manipulate the value HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings so that value SecureProtocols is REG_DWORD a0 (hex). NOTE: Use of TLS 1.1 and 1.2 are permissible in connection with SSl 3.0 and TLS 1.0."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings', 'SecureProtocols')

        # Output Lines
        self.__output = [r'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings', ('SecureProtocols=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 160:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Windows'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'SecureProtocols' -value 160 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE7"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE7000003"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"