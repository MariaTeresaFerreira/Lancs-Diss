import subprocess
import re
from extras import Errors
import winreg
import os
import xml.etree.ElementTree as ET

class Check:

    @classmethod
    def __get_firewall_dict(cls, name):
        options = [
            'State',
            'Firewall Policy',
            'LocalFirewallRules',
            'LocalConSecRules',
            'InboundUserNotification',
            'RemoteManagement',
            'UnicastResponseToMulticast',
            'LogAllowedConnections',
            'LogDroppedConnections',
            'FileName',
            'MaxFileSize']

        out = (subprocess.check_output('netsh advfirewall show ' + name, shell=True)).decode("utf-8")
        dict = {}
        dict["Name"] = name
        out_split = re.split('\n', out)
        for line in out_split:
            entry = line.split()
            if len(entry) > 0:
                if (entry[0] in options):
                    key = entry[0]
                    entry.pop(0)
                    dict[key] = ' '.join(entry)
                elif (entry[0] == "Firewall") and (entry[1] == "Policy"):
                    key = "Firewall Policy"
                    in_out = []
                    for rule in re.split(',', entry[2]):
                        in_out.append(rule)
                    dict[key] = in_out
        
        return dict

    @classmethod
    def __get_all_firewall_dicts(cls):
        '''Returns a list of 3 dictionaries that correspond to the three types of firewall (Domain, Private, and Public), the dictionaries have the settings of the firewall'''
        return [cls.__get_firewall_dict("Domain"), cls.__get_firewall_dict("Private"), cls.__get_firewall_dict("Public")]


    @classmethod
    def __get_all_users(cls):
        out = (subprocess.check_output('wmic UserAccount get Name', shell=True)).decode("utf-8")
        out_split = out.split()
        out_split.remove("Name")
        return out_split

    @classmethod
    def __get_active_users(cls):
        users_list = cls.__get_all_users()
        active_user = ['Account', 'active', 'Yes']
        active_users_list = []
        for user in users_list:
            out = (subprocess.check_output('net user ' + user, shell=True)).decode("utf-8")
            out_split = re.split('\n', out)
            for line in out_split:
                entry = line.split()
                if entry == active_user:

                    active_users_list.append(user)
        
        return active_users_list

    @classmethod
    def __get_admin_users(cls):
        all_users = cls.__get_all_users()
        admin_users = []
        out = (subprocess.check_output('net localgroup Administrators', shell=True)).decode("utf-8")
        out_split = re.split('\n', out)
        for line in out_split:
            entry = line.split()
            if (len(entry) != 0) and (entry[0] in all_users):
                admin_users.append(entry[0])
        return admin_users

    @classmethod
    def __get_username_privileges(cls):
        employee_list = [] 
        try:
            tree = ET.parse(os.path.dirname(__file__) + '/EmployeeData.xml')
        except ET.ParseError:
            print("INVALID INPUT FILE: EmployeeData.xml file example")
            print('<EmployeeData>\n'+
                '   <Employee user = "m.ferreira" privilege = "stardard">\n'+
                '       <FirstName>Maria</FirstName>\n'+
                '       <LastName>Ferreira</LastName>\n'+
                '   </Employee>\n'+
                '</EmployeeData>')
            exit()


        root = tree.getroot()
        for employee in root:
            dic = {}
            dic["username"] = employee.attrib["user"]
            dic["privilege"] = employee.attrib["privilege"]
            employee_list.append(dic)
        return employee_list

    @classmethod
    def __get_password_policy(cls):
        options = [
            'ComplexityEnabled',
            'DistinguishedName',
            'LockoutDuration',
            'LockoutObservationWindow',
            'LockoutThreshold',
            'MaxPasswordAge',
            'MinPasswordAge',
            'MinPasswordLength',
            'objectClass',
            'objectGuid',
            'PasswordHistoryCount',
            'ReversibleEncryptionEnabled'
        ]

        p = subprocess.Popen(["powershell.exe", 
              "Get-ADDefaultDomainPasswordPolicy"], 
              stdout=subprocess.PIPE)
        pass_policy = {}
        out = p.stdout.read().decode("utf-8")
        out_split = re.split('\n', out)
        for line in out_split:
            entry = line.split()
            if len(entry) != 0:
                if entry[0] in options:
                    pass_policy[entry[0]] = entry[2]
        
        max_pass_age = pass_policy["MaxPasswordAge"]
        min_pass_age = pass_policy["MinPasswordAge"]
        pass_policy["MaxPasswordAge"] = cls.__parse_day(max_pass_age)
        pass_policy["MinPasswordAge"] = cls.__parse_day(min_pass_age)        
        return pass_policy

    @classmethod
    def __parse_day(cls, days):
        return days.split('.')[0]



#=============== STARTING CHECK METHODS

    @classmethod
    def check_1(cls):
        '''Returns OK if all three firewall options are enabled'''
        for dic in cls.__get_all_firewall_dicts():
            if dic['State'] == 'OFF':
                return Errors.ERR_01
        return Errors.OK

    @classmethod
    def check_2(cls):
        '''Returns OK if all three firewall options have remote access disabled'''
        #TEST: Run as Admin - netsh advfirewall firewall set rule group="Windows Defender Firewall Remote Management" new enable=no
        for dic in cls.__get_all_firewall_dicts():
            if dic['RemoteManagement'] != 'Disable':
                return Errors.ERR_02
        return Errors.OK

    @classmethod
    def check_3(cls):
        '''Returns OK if Guest users are disabled'''
        #TEST: Run as Admin - Net user Guest /active:yes
        
        active_users = cls.__get_active_users()
        if "Guest" in active_users:
            return Errors.ERR_03
        return Errors.OK


    @classmethod
    def check_4(cls):
        '''Returns OK if Autoplay is disabled'''
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers", 0, winreg.KEY_READ)
        for i in range(winreg.QueryInfoKey(key)[1]):
            name, data, type = winreg.EnumValue(key, i)
            if name == "DisableAutoplay" and data == 1:
                return Errors.OK
        return Errors.ERR_04

    @classmethod
    def check_5(cls):
        '''Returns OK if active users are as expected according to the EmployeeData.xml file'''
        expected_users = []
        for user in cls.__get_username_privileges():
            expected_users.append(user["username"])

        active_users = cls.__get_active_users()

        if sorted(active_users) == sorted(expected_users):
            return Errors.OK
        else:
            return Errors.ERR_05
    

    @classmethod
    def check_6(cls):
        '''Returns OK if admin users are as expected according to the EmployeeData.xml file'''
        users_input = cls.__get_username_privileges()
        admins_input = []
        active_admins = list(set(cls.__get_active_users()) & set(cls.__get_admin_users()))

        for user in users_input:
            if user["privilege"] == "administrator":
                admins_input.append(user["username"])
        
        if sorted(active_admins) == sorted(admins_input):
            return Errors.OK
        else:
            return Errors.ERR_06
    
    @classmethod
    def check_7(cls):
        '''Check if only Administrator has admin privileges'''
        tst = cls.__get_username_privileges()
        for usr in tst:
            if (usr['username'] != "Administrator") and (usr['privilege'] == "administrator"):
                print(usr)
                return Errors.ERR_07

        return Errors.OK
        #active_admins = list(set(cls.__get_active_users()) & set(cls.__get_admin_users()))
        #if active_admins == ["Administrator"]:
            
        


    @classmethod
    def check_8(cls):
        '''Returns OK if the Password Policy values are not less secure than the reccomended specification'''
        #TEST - go to Group Policy Management Editor, edit fields and run 'gpupdate'
        pass_policy = cls.__get_password_policy()
        if pass_policy['ComplexityEnabled'] != 'False':
            #print("Failed ComplexityEnabled")
            return Errors.ERR_08
        elif int(pass_policy['LockoutThreshold']) > 100:
            #print("Failed LockoutThreshold")
            return Errors.ERR_08
        elif int(pass_policy['MaxPasswordAge']) < 365:
            #print("Failed MaxPasswordAge")
            return Errors.ERR_08
        elif int(pass_policy['MinPasswordLength']) < 8:
            #print("Failed MinPasswordLength")
            return Errors.ERR_08
        elif int(pass_policy['PasswordHistoryCount']) < 10:
            #print("Failed PasswordHistoryCount")
            return Errors.ERR_08
        if pass_policy['ReversibleEncryptionEnabled'] != 'False':
            #print("Failed ReversibleEncryptionEnabled")
            return Errors.ERR_08
        else:
            return Errors.OK
    
    @classmethod
    def check_9(cls):
        '''Returns OK if all Firewall domains inbound default is set as BlockInbound'''
        for dic in cls.__get_all_firewall_dicts():
            if dic['Firewall Policy'][0] != "BlockInbound":
                return Errors.ERR_09
        return Errors.OK
