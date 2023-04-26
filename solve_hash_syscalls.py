from pwn import *
from dumpulator import Dumpulator

syscall_table = [0 for i in range(2000*4)]
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

def REV(n: int) -> int:
    return ((n >> 24) & 0xff) | ((n << 8) & 0xff0000) | ((n >> 8) & 0xff00) | ((n << 24) & 0xff000000)
    # If output of all the above expression is
    # OR'ed then it results in 0xddccbbaa

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
    v4 = iterate_over_module_name_and_hash(0x0000000D22E2014)
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
    binar = open(sys.argv[1],"rb").read()
    mz_header = binar[0:2]
    if(mz_header == b'MZ'):
        mz_header_binary = binar
        print("aici")
        pe_heder =  binar[binar[0x3c]:]
        if(pe_heder):
            x = (hexdump(pe_heder[0x8c:]))
            if(x):
                eax = int.from_bytes(pe_heder[0x88:0x8c])
                #eax = binar[eax:]
                eax = hex(eax)[2:8]
                eax = int(eax,base=16)
                eax = REV(eax) >> 8
                #print(hex(eax))
                #print(hexdump(binar))
                eax = binar[eax:]
                r12d = eax[0x1c:0x1c+4]
                r12d = int.from_bytes(r12d)
                r12d = hex(r12d)[2:8]
                r12d = int(r12d,base=16)
                r12d = REV(r12d) >> 8
                r12d = binar[r12d:]

                r15d = eax[0x20:0x24] 
                r15d = int.from_bytes(r15d)
                r15d = hex(r15d)[2:8]
                r15d = int(r15d,base=16)
                r15d = REV(r15d) >> 8

                r13d = eax[0x24:0x28] 
                r13d = int.from_bytes(r13d)
                r13d = hex(r13d)[2:8]
                r13d = int(r13d,base=16)
                r13d = REV(r13d) >> 8

                r15d = binar[r15d:]

                ebp = eax[0x18:0x18+2]
                ebp = int.from_bytes(ebp)
                ebp = hex(ebp)[2:8]
                ebp = int(ebp,base=16)
                ebp = REV(ebp) >> 8

                r13d = binar[r13d:]                
                #print(hexdump(r15d))
                eax = r15d
                ebp = ebp >> 8
                neparsat = []
                for i in range(ebp-1,0,-1):
                    eax = i
                    ecx = r15d[(eax*4):(eax*4+4)]
                    ecx = int.from_bytes(ecx)
                    ecx = hex(ecx)[2:8]
                    ecx = int(ecx,base=16)
                    ecx = REV(ecx) >> 8
                    ebp = i
                    tmp = ecx
                    ecx = binar[ecx:tmp+0x30]
                    if(b'Zw' in ecx):
                        neparsat.append(ecx)

                parsat = []
                currnt_str = ""
                for i in neparsat:
                    for j in range(0,len(i)):
                        if(chr(i[j]) == '\x00'):
                            if "Zw" not in currnt_str:
                                continue
                            else:
                                parsat.append(currnt_str)
                                currnt_str = ""
                        else:
                            currnt_str += chr(i[j])
                print(parsat)
                cnt = 0
                for i in parsat:
                    v12 = 2*cnt
                    temp = (hex(some_hash_0x1003F(i)))
                    y[(cnt+1)] = {i:temp}
                    #tf does this mean
                    #*&a1[2 * v12 + 4] = *&v7[4 * *&v10[2 * v9]];
                    rax = 0x718
                    eax = r13d[rax*2:(rax*2+1)]
                    eax = ord(eax)
                    eax = hex(eax)[2:]
                    eax = "0x7"+eax
                    ecx = r12d[int(eax,base=16)*4:int(eax,base=16)*4+4]
                    ecx = int.from_bytes(ecx)
                    ecx = hex(ecx)[2:8]
                    ecx = int(ecx,base=16)
                    ecx = REV(ecx) >> 8
                    print(hex(ecx))
                    y[2*cnt+10] = ecx
                    if(cnt == 500):
                        break
                    cnt += 1
                print(y)
                

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
