
#!/usr/bin/python
################################################################################
# V17752
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
        return r"V-17752"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Hidden markup options must be visible."

    def get_vulnerability_discussion(self):
        return r"PowerPoint presentations that are saved in standard or HTML format can contain a flag indicating whether markup (comments or ink annotations) in the presentation should be visible when the presentation is open. PowerPoint ignores this flag when opening a file, and always displays any markup present in the file. In addition, when saving a file, PowerPoint sets the flag to display markup when the presentation is next opened.If this default configuration is changed, PowerPoint sets the flag according to the state of the Show Markup option on the Review tab of the Ribbon when it saves presentations in standard or HTML format. In addition, PowerPoint enables or disables the Show Markup option according to the way the flag is set when it opens files, which means that a presentation saved with hidden markup is opened with the markup still hidden.If a file is saved with hidden markup, users might inadvertently distribute sensitive comments or information to others via the presentation file. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft PowerPoint 2013 \ PowerPoint Options \ Security ''Make hidden markup visible'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\powerpoint\options', 'MarkupOpenSave')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\powerpoint\options', ('MarkupOpenSave=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\powerpoint'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\powerpoint\options'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\powerpoint\options' -name 'MarkupOpenSave' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013PowerPoint"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13PP0014"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"