
#!/usr/bin/python
################################################################################
# V17739
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
        return r"V-17739"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Disable automatic download content for email from people in Safe Senders and Safe reciipeint lists."

    def get_vulnerability_discussion(self):
        return r"Malicious e-mail senders can send HTML e-mail messages with embedded Web beacons, or pictures and other content from external servers that can be used to track whether specific recipients have opened a message. Viewing an e-mail message that contains a Web beacon provides confirmation that the recipient''s e-mail address is valid, which leaves the recipient vulnerable to additional spam and harmful e-mail. To help protect users from Web beacons, Outlook 2007 can be configured to automatically block the display of external content in e-mail messages. However, because this configuration could block desirable content from display, Outlook can also be configured to automatically display external content in any messages sent by people who are listed in users'' Safe Senders Lists or Safe Recipients Lists.By default, Outlook 2007 automatically displays external content in e-mail messages from people listed in users'' Safe Senders Lists or Safe Recipients Lists, and automatically blocks external content in other messages. If a malicious sender is accidentally added to a user''s Safe Senders List or Safe Recipients List, Outlook will display external content in all e-mail messages from the malicious sender, which could include Web beacons. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office Outlook 2007 \ Security \ Automatic Picture Download Settings ?Automatically download content for e-mail from people in Safe Senders and Safe Recipients Lists? will be set to ?Disabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Outlook\Options\Mail', 'UnblockSpecificSenders')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Outlook\Options\Mail', ('UnblockSpecificSenders=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Outlook'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Outlook\Options'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Outlook\Options\Mail'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Outlook\Options\Mail' -name 'UnblockSpecificSenders' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007Outlook"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07Out0046"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"