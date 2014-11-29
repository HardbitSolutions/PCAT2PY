
#!/usr/bin/python
################################################################################
# V17795
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
        return r"V-17795"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Enable security feature to never automatically send  s/Mime receipt requests."

    def get_vulnerability_discussion(self):
        return r"Incoming signed or encrypted messages might include S/MIME receipt requests. S/MIME receipts provide confirmation that messages are received unaltered, and can include information about who opened the message and when it was opened.By default, when users open messages with attached receipt requests, Outlook 2007 prompts them to decide whether to send a receipt to the sender with information about the identity of the user who opened the message and the time it was opened. If Outlook cannot send the receipt, the user is still allowed to open the message.In some situations, allowing Outlook to automatically send receipt requests could cause sensitive information to be divulged to unauthorized people. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office Outlook 2007 \ Security \ Cryptography ?S/MIME receipt requests? will be set to ?Enabled (Never send S\MIME receipts)?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Outlook\Security', 'RespondToReceiptRequests')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Outlook\Security', ('RespondToReceiptRequests=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 2:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Outlook'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Outlook\Security'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Outlook\Security' -name 'RespondToReceiptRequests' -value 2 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007Outlook"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07Out0067"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"