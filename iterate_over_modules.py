import sys
import math
import re
from pwn import * 
from dumpulator import Dumpulator
from solve_hash_syscalls import iterate_over_module_name_and_hash
from solve_hash_syscalls import some_hash_0x1003F

def f(x):
    process_list = [ #use this to emulate the low level api to get a list of current process on analysis machine 
        "conhost"
        "csrss"
        "csrss"
        "dwm"
        "explorer"
        "GoogleCrashHandler"
        "GoogleCrashHandler64"
        "Idle"
        "lsass"
        "lsm"
        "powershell"
        "ProcessHacker"
        "SearchFilterHost"
        "SearchIndexer"
        "SearchProtocolHost"
        "services"
        "smss"
        "spoolsv"
        "sppsvc"
        "svchost"
        "svchost"
        "svchost"
        "svchost"
        "svchost"
        "svchost"
        "svchost"
        "svchost"
        "svchost"
        "svchost"
        "svchost"
        "svchost"
        "svchost"
        "System"
        "taskeng"
        "taskhost"
        "VBoxService"
        "VBoxTray"
        "wininit"
        "winlogon"
        "wmpnetwk"
        "wuauclt"
        "x64dbg"
    ]
    for i in process_list:
        if(some_hash_0x1003F(i) == x):
            break
    return 0



def main():
    v4 = [None for i in range(0xf)]
    v0 = 0
    v4[0] = 0x42D12D59
    v1 = 0
    v4[1] = 0xEC5D7AA
    v4[2] = 0x861E460F
    v4[3] = 0x84BCC8DB
    v4[4] = 0x6474D72B
    v4[5] = 0xB8B9C504
    v4[6] = 0x69A0620E
    v4[7] = 0x6017EE43
    v4[8] = 0xE93BE2E0
    v4[9] = 0x149EFC55
    v4[10] = 0xE3FA84A4
    v4[11] = 0x7CFDD7AF
    v4[12] = 0x5B098C67
    v4[13] = 0x2F1FB18E
    v4[14] = 0xFE8F2B18
    while(not f(v4)):
        v2 = v4[v1]
        print(v1)
        v1+=1
        if ( v1 >= 0xF ):
            return v0
    return 1

if __name__ == "__main__":
    main()
