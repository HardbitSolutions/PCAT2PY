
#!/usr/bin/python
################################################################################
# V1104
#
# Justin Dierking
# phnomcobra@gmail.com
# justin.dierking@hardbitsolutions.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated SECEDIT finding
#
# 09/30/2014 Original Construction
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
        return r"V-1104"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Maximum password age does not meet minimum requirements."

    def get_vulnerability_discussion(self):
        return r"The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the passwords.   Further, scheduled changing of passwords hinders the ability of unauthorized system users to crack passwords and gain access to a system. Set the Maximum Password Age so that it is not ''0'' and doesn''t exceed 60 days."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Secedit Value
        value = cli.get_secedit_value('MaximumPasswordAge')

        # Output Lines
        self.__output = ["MaximumPasswordAge=" + value]
	
	# Recommended Value
	rec_value = ("1 to 60")

        if self.__verbose:
            print self.__output

	try:
            if int(value) >= int(rec_value.split("to")[0]) and int(value) <= int(rec_value.split("to")[1]):
                self.__is_compliant = True
        except ValueError:
            None

        return self.__is_compliant

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Vista"

    def get_hippa(self):
        return "164.308(a)(5)(ii)(D)"
    
    def get_pci(self):
        return "8.2.4"
    
    def get_hbs_id(self):
        return "HBSPCATVISTA000025"
    
    def get_dod8500_2(self):
        return "IAIA-1, IAIA-2"

    def get_800_53(self):
        return "IA-2, IA-4(2), IA-4(3), IA-5, IA-5(1), IA-5(3), IA-5(5), IA-5(6), IA-5(7)"
    
    def get_iso_27001(self):
        return "A.10.9.1, A.10.9.2, A.11.4.2, A.11.5.1, A.11.5.2 ,A.11.2.1, A.11.2.3, A.11.3.1, A.11.5.3"