import copy
from pwn import *
from dumpulator import Dumpulator
syscall_table = [0 for i in range(256)]
lista_de_dll = []


def some_hash_0x1003F(x):
    rez = 0
    counter = 0
    if(x):
        for i in range(0,len(x)):
            if(x[i]):
                rez = rez * 0x1003f + ord(x[i])
                if len(hex(rez)) > 8:
                    rez = ((rez)) & 0xffffffff
    return rez

def subs_box(a,b):
    """
        a = variabila
        b = constant 46 
    """
    r10d = 0 
    r9d  = r10d
    if(a):
        r8d = r10d
        for i in a:
            if i == '.':
                break
            else:
                r9d +=1
                r8d = r9d
                eax=a[r9d]
    return (a[0:r9d])

def ascii_range_decode2_suta_la_suta(requested_hash,x):
    """
        x = flink from previous function
        requested_hash = hash requested from previous functions
    """
    r8d = x
    #print(r8d)
    ebx = 0 
    r11 = requested_hash
    rax = x
    v6 = 0
    tmp = ""
    if(r8d):
        len_string = len(rax)
        edx = 0
        r10 = ebx
        for i in range(0,len(rax)):
            if((ord(r8d[i])-0x41)<0x19):
                tmp += str(ord(r8d[i]) + 32)
        eax = len(tmp)
    return eax

def swapPositions(list, pos1, pos2):
     
    list[pos1], list[pos2] = list[pos2], list[pos1]
    return list

def iterate_over_module_name_and_hash(x):
    """
        x= requested hash
    """
    v10 = 0
    v8 = 0
    dp = Dumpulator("blacklotus.dmp",quiet=True)
    rdi = -1
    current_modules = []
    r15d = x
    modules = dp.modules._name_lookup
    for key in modules:
        if not 'C:' in key:
            current_modules.append(key)
    swapPositions(current_modules,0,1)
    for i in range(0,len(current_modules)-1):
        flink = current_modules[i+1]
        if(flink):
            v10 = ascii_range_decode2_suta_la_suta(x,flink)
            #print(v10)
            rcx = current_modules[i]
            v8 = some_hash_0x1003F(rcx) == x
            edx = 0x2e
            module_name = subs_box(rcx,46)
            #print(module_name)
            if(some_hash_0x1003F(module_name) == x or v8):
                v2 = current_modules[i]
                return v2
    


def check_inmemory_ldr(y,x):
    r14 = x
    edx = 0
    v4 = (iterate_over_module_name_and_hash(0x0000000D22E2014))
    #print(v4)
    directory = ""
    if(v4):
        dp = Dumpulator("blacklotus.dmp",quiet=True)
        for i in dp.modules._name_lookup:
            if v4 in i:
                if "C:\\" in i:
                    directory = i.encode('utf-8')
                else:
                    continue
    print(directory)
    """
    under normal circumstances this works fine
    given that the analysis was done on a windows 7 vm we replace directory variable with
    sys.argv[1] where argv[1] == ntdll from win7
    """
    binar = open(directory,"rb").read()
    mz_header = binar[0:2]
    if(mz_header == b'MZ'):
        mz_header_binary = binar
        print("aici")
        pe_heder =  binar[binar[0x3c]:]
        if(pe_heder):
            print(hexdump([binar[0x3c:]]))

def syscall_solve_hash(x):
        esi = x
        edi = -1
        eax = syscall_table[0]
        rbp = syscall_table[0]
        check_inmemory_ldr(syscall_table,x)


if __name__ == "__main__":
    #print("aici")
    #some_hash_0x1003F("d68f668b4240f9518e4f80499d93d8c5a1eddece0771658c33ae916cc54f5a66.exe")
    syscall_solve_hash(0x000000002ED76231)
