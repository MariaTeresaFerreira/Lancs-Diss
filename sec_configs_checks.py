import subprocess
import re
import winreg
import os
import xml.etree.ElementTree as ET

def get_all_users():
    out = (subprocess.check_output('wmic UserAccount get Name', shell=True)).decode("utf-8")
    out_split = out.split()
    out_split.remove("Name")
    return out_split

def get_active_users():
    users_list = get_all_users()
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

def get_admin_users():
    all_users = get_all_users()
    admin_users = []
    out = (subprocess.check_output('net localgroup Administrators', shell=True)).decode("utf-8")
    out_split = re.split('\n', out)
    for line in out_split:
        entry = line.split()
        if (len(entry) != 0) and (entry[0] in all_users):
            admin_users.append(entry[0])
    return admin_users

def parse_employee_data():
    #file_path = open(os.path.dirname(__file__) + "/EmployeeData.xml","r")
    tree = ET.parse('diss/EmployeeData.xml')
    root = tree.getroot()
    for employee in root:
        print(employee.attrib)


parse_employee_data()


def configs_check_1():
    '''Checks if Administrator or Guest users are enabled'''
    #TEST: Run as Admin - Net user Guest /active:yes
    active_users = get_active_users()
    if "Guest" in active_users or "Administrator" in active_users:
        return "scc_01"
    return True

def configs_check_2():
    #win32net.NetValidatePasswordPolicy(options.server,None, val_type, input)
    return True

def configs_check_3():
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers", 0, winreg.KEY_READ)
    for i in range(winreg.QueryInfoKey(key)[1]):
        name, data, type = winreg.EnumValue(key, i)
        if name == "DisableAutoplay" and data == 1:
            return True
    return "scc_03"