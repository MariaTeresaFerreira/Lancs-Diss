import subprocess

cmds = [("netsh advfirewall set allprofiles state off", "Press enter to turn off Firewall"),
        ("netsh advfirewall set allprofiles state on", "Press enter to turn on Firewall"),
        ('netsh advfirewall firewall set rule group="Windows Defender Firewall Remote Management" new enable=yes', "Press enter to enable Firewall Remote Management"),
        ('netsh advfirewall firewall set rule group="Windows Defender Firewall Remote Management" new enable=no', "Press enter to disable Firewall Remote Management"),
        ('net user Guest /active:yes', "Press enter to enable Guest account"),
        ('net user Guest /active:no', "Press enter to disable Guest account"),
        ('', "Please enable Autoplay"),
        ('', "Please disable autoplay"),
        ('net localgroup administrators m.ferreira /add', "Press enter to make m.ferreira user Administrator"),
        ('net localgroup administrators m.ferreira /delete', "Press enter to make m.ferreira user Stardard")]

for cmd,text in cmds:
        print(text)
        input()
        subprocess.check_output(cmd, shell=True)
        
print("Demo completed")
exit()