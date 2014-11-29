
#!/usr/bin/python
################################################################################
# V17634
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
        return r"V-17634"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Intranet with Safe Zones for automatic picture downloads must be configured."

    def get_vulnerability_discussion(self):
        return r"Malicious email senders can send HTML email messages with embedded Web beacons, which are pictures and other content from external servers that can be used to track whether recipients open the messages. Viewing email messages with Web beacons in them provides confirmation that the recipient''s email address is valid, which leaves the recipient vulnerable to additional spam and harmful email.By default, Outlook does not download external content in HTML email messages from untrusted senders over the local intranet. If this configuration is changed, Outlook will display external content in all HTML email messages received via the local intranet, which could include Web beacons. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Outlook 2013 \ Security \ Automatic Picture Download Settings ''Include Intranet in Safe Zones for Automatic Picture Download'' to ''Disabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options\mail', 'Intranet')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options\mail', ('Intranet=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options\mail'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options\mail' -name 'Intranet' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Outlook"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Out0029"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"