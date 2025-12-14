import os
import time

usrname = input("| Enter your server's username :> ")
websvr = input("| Enter your web server's name :> ")

if usrname == "root":
 home = "/root"
else:
 home = f"/home/{usrname}"

unban = f"{home}/unban.py"
moni = f"{home}/moni.py"
service = f"/etc/systemd/system/moni.service"
log = f"/var/log/{websvr}/moni.log"

os.system(f"rm -rf {unban} {moni} {service} {log}")
time.sleep(1)
os.system("rm -rf ./uninstall.py")
print("[!] Uninstalled moni service... ")
