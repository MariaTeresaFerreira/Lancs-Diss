from enum import Enum

class Colours:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    DEFAULT = '\033[0m'

class Errors(Enum):
    OK = "Test passed"
    FWC_01 = "At least one domain of the Firewall is not enabled"
    FWC_02 = "At least on domain of the Firewall has remote access enabled"
    SCC_01 = "Guest or Administrator user is enabled, confirm if this is necessary"
    SCC_02 = "Autoplay is enabled"
    SCC_03 = "Active users are not as expected"
    SCC_04 = "Administrator users are not as expected"


def print_tests_colour(number, feedback):
    if feedback == Errors.OK:
        print(f"    Check" , number, f"-> {Colours.GREEN}Pass{Colours.DEFAULT}")
    elif feedback == False:
        print(f"    Check" , number, f"-> {Colours.RED}Fail{Colours.DEFAULT}")
    else:
        print(f"    Check" , number, f"-> {Colours.YELLOW}Possible Vulnerability {Colours.DEFAULT}(" + feedback.name +  "):", feedback.value )

def print_tests(number, feedback):
    if feedback == Errors.OK:
        print(f"    Check" , number, f"-> Pass")
    elif feedback == False:
        print(f"    Check" , number, f"-> Fail")
    else:
        print(f"    Check" , number, f"-> Possible Vulnerability (" + feedback.name +  "):", feedback.value )


def print_dicts(dicts):
    for dict in dicts:
        #print("===========")
        for elem in dict:
            print(elem, ":", dict[elem])