from firewall_checks import Firewall
from sec_configs_checks import Configs
from extras import Colours
from extras import print_tests

class Report:
    @classmethod
    def firewall_report(cls):
        print(f"=== Firewall report started")
        checks = []
        i = 1
        checks.append(Firewall.firewall_check_1())
        checks.append(Firewall.firewall_check_2())
        for check in checks:
            print_tests(i, check)
            i += 1
            #win32api.MessageBox(0, rtrn.value, 'Possible Vulnerability Detected: ' +  rtrn.name, 0x00001000)
        print(f"==========")

    @classmethod
    def configs_report(cls):
        print(f"=== Secure Configurations report started")
        checks = []
        i = 1
        checks.append(Configs.configs_check_1())
        checks.append(Configs.configs_check_2())
        checks.append(Configs.configs_check_3())
        checks.append(Configs.configs_check_4())
    
        for check in checks:
            print_tests(i, check)
            i += 1
            #win32api.MessageBox(0, rtrn.value, 'Possible Vulnerability Detected: ' +  rtrn.name, 0x00001000)
        print(f"==========")

    @classmethod
    def full_report(cls):
        cls.firewall_report()
        cls.configs_report()