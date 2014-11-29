
#!/usr/bin/python
################################################################################
# V15522
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
        return r"V-15522"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Loose or un-compiled XAML files for restricted sites zone are not disabled."

    def get_vulnerability_discussion(self):
        return r"These are eXtensible Application Markup Language (XAML) files. XAML is an XML-based declarative markup language commonly used for creating rich user interfaces and graphics that leverage the Windows Presentation Foundation.  If you enable this policy setting and the dropdown box is set to Enable, .XAML files will be automatically loaded inside Internet Explorer 7.0. User will not be able to change this behavior. If the dropdown box is set to Prompt, users will receive a prompt for loading .XAML files.  If you disable this policy setting, .XAML files will not be loaded inside Internet Explorer 7. User will not be able to change this behavior.  If you do not configure this policy setting, users will have the freedom to decide whether to load XAML files inside Internet Explorer 7.0. Manipulate the value: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4Criteria: Set the value 2402 to REG_DWORD = 3."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4', '2402')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4', ('2402=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 3:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4' -name '2402' -value 3 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE7"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE7000068"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"