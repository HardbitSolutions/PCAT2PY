
#!/usr/bin/python
################################################################################
# V17748
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
        return r"V-17748"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Junk email protection level for outlook"

    def get_vulnerability_discussion(self):
        return r"The Junk E-mail Filter in Outlook 2007 is designed to intercept the most obvious junk e-mail, or spam, and send it to users'' Junk E-mail folders. The filter evaluates each incoming message based on several factors, including the time when the message was sent and the content of the message. The filter does not single out any particular sender or message type, but instead analyzes each message based on its content and structure to discover whether or not it is probably spam. By default, users can choose from four levels of junk e-mail filtering:?	No Automatic Filtering. Outlook does not evaluate incoming messages by content.  Outlook continues to evaluate messages by using the domain names and e-mail addresses in the users'' Blocked Senders Lists, and continues to move messages from  blocked senders to users'' Junk E-mail folders. ?	Low. Outlook only moves the most obvious spam messages to users'' Junk E-mail folders.  This level is the default setting.?	High. Outlook intercepts most junk e-mail, but might incorrectly classify some legitimate messages as junk. Users are advised to check their Junk E-mail folders often. ?	Safe Lists Only. Outlook moves all incoming messages to users'' Junk E-mail folders except messages from someone on users'' Safe Senders Lists and messages sent to mailing lists on users'' Safe Recipients Lists.If users choose an inappropriate setting, they might miss important messages or accumulate large amounts of junk e-mail in their Inboxes. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office Outlook 2007 \ Tools \ Options \ Preferences \ Junk E-mail ?Junk E-mail protection level? will be set to ?Enabled (Low)?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Outlook\Options\Mail', 'JunkMailProtection')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Outlook\Options\Mail', ('JunkMailProtection=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 6:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Outlook'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Outlook\Options'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Outlook\Options\Mail'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Outlook\Options\Mail' -name 'JunkMailProtection' -value 6 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007Outlook"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07Out0047"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"