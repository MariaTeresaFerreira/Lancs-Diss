from enum import Enum

class Colours:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    DEFAULT = '\033[0m'

class Errors(Enum):
    OK = "Test passed"
    ERR_01 = "At least one domain of the Firewall is not enabled"
    ERR_02 = "At least one domain of the Firewall has remote access enabled"
    ERR_03 = "Guest user is enabled, confirm if this is necessary"
    ERR_04 = "Autoplay is enabled"
    ERR_05 = "Active users are not as expected"
    ERR_06 = "Administrator users are not as expected"
    ERR_07 = "Non Administrator User has administrator privileges"
    ERR_08 = "Minimum Password Policy Requirements not met"
    ERR_09 = "Firewall default rule not set as BlockInbound"


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

