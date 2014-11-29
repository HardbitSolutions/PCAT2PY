
#!/usr/bin/python
################################################################################
# V17775
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated DWORD NOT EXIST finding
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
        return r"V-17775"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Level 2 file extensions must be blocked and not removed."

    def get_vulnerability_discussion(self):
        return r"Malicious code is often spread through email. Some viruses have the ability to send copies of themselves to other people in the victim''s Address Book or Contacts list, and such potentially harmful files can affect the computers of unwary recipients.Outlook uses two levels of security to restrict users'' access to files attached to email messages or other items. Files with specific extensions can be categorized as Level 1 (users cannot view the file) or Level 2 (users can open the file after saving it to disk). Users can freely open files of types that are not categorized as Level 1 or Level 2.By default, Outlook classifies a number of potentially harmful file types as Level 1. (See Attachment file types restricted by Outlook for the complete list.) Outlook does not classify any file types as Level 2 by default, so this setting is not particularly useful in isolation. Typically, if there are extensions on the Level 2 list they would have been added by using the ''Add file extensions to block as Level 2'' setting, through which they can be removed.The combined lists of blocked and restricted file extensions that Outlook uses are actually built by combining various policies together. If a machine policy classifies an extension as Level 2, this setting could be used to remove the extension from the list in some situations. As with Level 1 extensions, though, removing restrictions on potentially dangerous extensions can make it easier for users to open dangerous files, which can significantly reduce security. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Outlook 2013 \ Security \ Security Form Settings \ Attachment Security ''Remove file extensions blocked as Level 2'' to ''Disabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\security\FileExtensionsRemoveLevel2', '')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\security\FileExtensionsRemoveLevel2', ('=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == -1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\security'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\security\FileExtensionsRemoveLevel2'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\security\FileExtensionsRemoveLevel2' -name '' -value -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Outlook"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Out0052"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"