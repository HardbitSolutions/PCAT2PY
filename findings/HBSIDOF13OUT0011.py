
#!/usr/bin/python
################################################################################
# V17564
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
        return r"V-17564"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"IE Trusted Zones assumed trusted must be blocked."

    def get_vulnerability_discussion(self):
        return r"Malicious users can send HTML email messages with embedded Web beacons, which are pictures and other content from external servers that can be used to track whether specific recipients open the message. Viewing an email message that contains a Web beacon provides confirmation that the recipient''s email address is valid, which leaves the recipient vulnerable to additional spam and harmful email.To reduce the risk from Web beacons, Outlook disables external content in email messages by default, unless the content is considered ''safe'' as determined by the check boxes in the Automatic Download section of the Trust Center. Depending on how these options are configured, safe content can include content in messages from addresses defined in the Safe Senders and Safe Recipients Lists used by the Junk email filter, content from SharePoint discussion boards, and content from websites in the Trusted sites zone in Internet Explorer.By default, Outlook considers trusted sites from Internet Explorer safe, and automatically downloads content from them, which could potentially include Web beacons. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Outlook 2013 \ Security \ Automatic Picture Download Settings ''Block Trusted Zones'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options\mail', 'TrustedZone')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options\mail', ('TrustedZone=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options\mail'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options\mail' -name 'TrustedZone' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Outlook"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Out0011"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"