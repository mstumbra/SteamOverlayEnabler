#!/usr/bin/env python
import os
import pexpect
import sys
import re

############################ Search Steam PID ##################################
steamPids = []
pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
for pid in pids:
    try:
        cmdline = open(os.path.join('/proc', pid, 'cmdline')).read().split('\0')[0]
        if cmdline.endswith('steam'):
            steamPids.append(pid)
    except IOError: # proc has already terminated
        continue
print('Found {} candidates for steam executable:'.format(len(steamPids)))
print(steamPids)
if len(steamPids) == 0:
    exit()

################################ Run scanmem ###################################
try:
    sm = pexpect.spawn("scanmem", encoding='utf-8', echo=False)
except:
    print("Can not start scanmem")
    exit()
sm.logfile=sys.stdout
sm.expect([">"])
sm.sendline("option scan_data_type string")
sm.expect([">"])
sm.sendline("option region_scan_level 1")
sm.expect([">"])
patched = False
for pid in steamPids:
    try:
        sm.sendline("reset")
        sm.expect([">"])
        sm.sendline("pid {}".format(steamPids[0]))
        sm.expect([">"])
        sm.sendline("\" disableoverlay")
        res = sm.expect(["[0-9]+>", ">"])
        if res == 1:
            continue

        ########### Extract matches addresses and modify memory ################
        sm.sendline("list")
        sm.expect(["[0-9]+>"])
        addresses = re.findall(r"\[[ 0-9]+\] *([0-9a-f]+),.+heap.+$", sm.before, re.M)
        for address in addresses:
            sm.sendline("write string {} b".format(address))
            patched = True
        break
    except:
        continue
sm.sendline("q")
if patched:
    print("Successfully patched steam process")
else:
    print("Didn't found anything to modify")
