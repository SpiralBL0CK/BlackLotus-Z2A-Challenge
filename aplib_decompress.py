import sys
import math
import re
from pwn import * 
from solve_hash_syscalls import iterate_over_module_name_and_hash


def my_wcsncat(a,b,c):
    """
    b = source in our case c:\\windows\\system32\ntdll.dll
    a = destination in our case buffer(\\??\\)+b
    c = size de concatenat
    alltough this algorithm seems to support unicode fuck unicode :)
    we do it normally as normal human beings :)
    """
    rax = c-1
    r11 = b
    r9 = c
    rbx = a
    if(rax > 0x7FFFFFFE):
        return 0x80070057
    else:
        r10 = c
        rax = a
        edi = 0
        ctr = 0
        if(len(rax) == edi):
            return 
        else:
            while(rax):
                if(rax == "00"):#or (rax == "00" and a[ctr+2:ctr+4] and a[ctr+6:ctr+8]))):
                    break
                rax = a[ctr:ctr+2]
                #print(hex(r10))
                ctr += 1
                print(hex(r10))
                r10 -=1
            rax = r10-1
            rcx = c
            rax = ~rax 
            print(hex(rax& 0xffffffff))
            rax = r10

def replace_str_index(text,index=0,replacement=''):
    return f'{text[:index]}{replacement}{text[index+1:]}'

def sub_13FDE67D4(a,b,c,binar):
    """
    goal return \\??\\ as string
    """
    v5 = 0 
    #print(a)
    if(b > 2):
        if(c):
            dword_13FE5FA24 = 0
            dword_13FE5FA28 = [None for i in range(0x7D0)]
            dword_13FE5FA20 = [None for i in range(0x10)]

        ecx = dword_13FE5FA24
        v6 = b - 1
        edx = a[v6*2]
        #print(hexdump(a))
        #print(hex(edx))
        v8 = 0
        edx = int(edx) - 0x60
        eax = -1
        r11 = dword_13FE5FA20[1]
        #print("aicia")
        #print(hex(edx))
        #print(hex(a[v6*2]))
        if(int(a[v6*2]) <= 0x7F):
            edx = a[v6*2]
        #print(hex(edx))
        eax += b
        dword_13FE5FA20[((eax*2+8)//4)+1] = hex(edx)
        cnt_extern = b
        rax_temp = 0
        while ( v8 < b ):
            #print(v8,b)
            edx = dword_13FE5FA24
            eax = b
            eax -= v8
            edx -= v8
            eax -=1
            edx += b
            #print(eax,int(math.floor((eax*2+8)/4)))
            ecx = a[eax*2]
            #print(hex(ecx))
            #eax = b-1
            #print("aicia2")
            xor_operand = int(str(dword_13FE5FA20[b-v8]),base=16)
            #print("xor_operand")
            #print(hex(xor_operand))
            r8d =( ecx - 0x60 )
            if(r8d < 0):
                #print("aicia3")
                r8d =( ecx - 0x60 )  & 0xffffffff
                #print(hex(r8d))
                r8d = hex(r8d)[2:6]+"0000"
                r8d = int(r8d,base=16)

            if(r8d ^ xor_operand == 0):
            #print(eax,int(math.floor((eax*2+8)/4)))
                dword_13FE5FA20[b-v8-1] = hex(xor_operand)
            else:
                if(len(hex(r8d ^ xor_operand)) > 4):
                    dword_13FE5FA20[b-v8-1] = "0x"+hex(r8d ^ xor_operand)[-2:]
                    """
                    current bug
                    din 0xffffffa0 -> paddui manual in ffff0000 e bun pt prim caz da al 2
                    a 2 iteratie ar trebui sa fie 0xffffffac->00000000FFFF000C
                    """
                else:
                    dword_13FE5FA20[b-v8-1] = hex(r8d ^ xor_operand)
            #print("r8d operand")
            #print(hex(r8d))
            #print(r8d)
            #print(dword_13FE5FA20)
            v8 += 1
        dword_13FE5FA20 = dword_13FE5FA20[0:5]
        print(dword_13FE5FA20)
        
        v12 = 0 
        if(b != 1):
            while(v12 < v6):
                eax = dword_13FE5FA24+v12
                edx = eax
                print(eax,edx)
                r8d = dword_13FE5FA20[v12]
                print(r8d)
                eax +=1
                eax = dword_13FE5FA20[eax]
                dword_13FE5FA20[edx] = eax
                ecx = v12+1
                dword_13FE5FA20[ecx] = r8d
                #print(dword_13FE5FA20)
                v12 += 2
        print(dword_13FE5FA20)

        r10 = 0
        for i in range(2):
            ecx = dword_13FE5FA24
            eax = ecx+r10
            ecx -= r10
            r8d = dword_13FE5FA20[eax]
            edx = eax
            #print(edx)
            eax = b-1
            eax += ecx
            eax = dword_13FE5FA20[eax]
            dword_13FE5FA20[edx] = eax
            eax = dword_13FE5FA24
            eax -= r10
            r10 += 1
            eax -= 1
            eax +=b
            #print(eax)
            dword_13FE5FA20[eax] = r8d

        print(dword_13FE5FA20)
        edx = dword_13FE5FA24
        dword_13FE5FA20[4] = 0x00
        dword_13FE5FA20.insert(0,b)
        print(dword_13FE5FA20)
        s = ""
        for i in range(1,len(dword_13FE5FA20)):
            s += chr(int(str(dword_13FE5FA20[i]),base=16))
        return s

def get_ntdll_and_unhook2(x):
    """
    None of the less the function starts like this 
      if ( ntquertyinformationprocess_anti_debug() )// anti_debug
                                                // 
                                                // 
    MEMORY[0] = 0x4E8C;
    but we skip cause oh well dast is nice and it renders this anti debug usless
    :)
    """
    v2 = iterate_over_module_name_and_hash(x)
    v3 = v2
    if(v2 and v3):    
        binar = open(sys.argv[1],"rb").read()
        mz_header = binar[0:2]
        if(mz_header == b'MZ'):
            mz_header_binary = binar
            print("aici")
            pe_heder =  binar[binar[0x3c]:]
            if(pe_heder):
                rcx = [
                    0x0C, 0x00, 0xCF, 0x00, 0x00, 0x00, 0xC3, 0x00, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0xC2, 0x00, 0x9D, 0x00, 0xBE, 0x00, 0xA7, 0x00, 0x11, 0x00, 0x1C, 0x00, 0x0A, 0x00, 0x00, 0x00,
                    0xD3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x84, 0x00, 0x07, 0x00, 0x16, 0x00,
                    0x06, 0x00, 0x01, 0x00, 0x08, 0x00, 0x0E, 0x00, 0x8B, 0x00, 0x82, 0x00, 0x08, 0x00, 0x8B, 0x00,
                    0x8F, 0x00, 0x12, 0x00, 0x16, 0x00, 0x87, 0x00, 0x83, 0x00, 0x9D, 0x00, 0xBC, 0x00, 0x00, 0x00,
                    0x9C, 0x00, 0x94, 0x00, 0x08, 0x00, 0x01, 0x00, 0xA3, 0x00, 0xAF, 0x00, 0x05, 0x00, 0x14, 0x00,
                    0x13, 0x00, 0x9F, 0x00, 0xBC, 0x00, 0x00, 0x00, 0x85, 0xC8, 0xA8, 0x18, 0x85, 0x06, 0x19, 0x15,
                    0x8D, 0x88, 0x87, 0x09, 0x18, 0x90, 0xD7, 0x7F, 0x83, 0xBA, 0xBA, 0x99, 0x1E, 0x09, 0xD8, 0xCD,
                    0x85, 0x17, 0xBF, 0xB5, 0x95, 0x81, 0x1C, 0x0D, 0xC9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x84, 0x00, 0x95, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x03, 0x00, 0x1F, 0x00, 0x1D, 0x00, 0x19, 0x00,
                    0x1F, 0x00, 0x8C, 0x00, 0x8B, 0x00, 0x92, 0x00, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0xC0, 0x00, 0xC1, 0x00, 0x1F, 0x00, 0xAB, 0x00, 0xAA, 0x00, 0xBF, 0x00, 0x1C, 0x00, 0x0D, 0x00,
                    0x0C, 0x00, 0x88, 0x00, 0x9D, 0x00, 0x88, 0x00, 0xD0, 0x00, 0xD4, 0x00, 0x00, 0x00, 0x9A, 0x00,
                    0x86, 0x00, 0x1F, 0x00, 0x9E, 0x00, 0xC9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x9D, 0x00, 0x93, 0x00, 0x0C, 0x00, 0x06, 0x00, 0xA7, 0x00, 0xAD, 0x00, 0x10, 0x00, 0x07, 0x00,
                    0x1A, 0x00, 0x1D, 0x00, 0x15, 0x00, 0xA8, 0x00, 0xA3, 0x00, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0xD7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x84, 0x00, 0x84, 0x00, 0x0C, 0x00, 0x11, 0x00,
                    0xA7, 0x00, 0xAD, 0x00, 0x10, 0x00, 0xBC, 0x00, 0xA1, 0x00, 0xCE, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x04, 0x00, 0x17, 0x00, 0x02, 0x00, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x9D, 0x00, 0x84, 0x00, 0x11, 0x00, 0x1C, 0x00, 0x0A, 0x00, 0x80, 0x00, 0xB3, 0x00, 0x00, 0x00,
                    0xC0, 0x00, 0xC7, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x11, 0x00, 0x83, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0x00, 0x87, 0x00, 0x19, 0x00, 0x0A, 0x00,
                    0x0B, 0x00, 0x1A, 0x00, 0x01, 0x00, 0x07, 0x00, 0x1B, 0x00, 0x1C, 0x00, 0xB4, 0x00, 0xAE, 0x00,
                    0x01, 0x00, 0x00, 0x00, 0xAF, 0x00, 0x00, 0x00, 0xC4, 0x00, 0x97, 0x00, 0xBD, 0x00, 0xAB, 0x00,
                    0x16, 0x00, 0x14, 0x00, 0x15, 0x00, 0x00, 0x00, 0x1D, 0x00, 0xAF, 0x00, 0xB0, 0x00, 0x19, 0x00,
                    0x07, 0x00, 0x0B, 0x00, 0xA5, 0x00, 0xA1, 0x00, 0x15, 0x00, 0x04, 0x00, 0x14, 0x00, 0x91, 0x00,
                    0xB5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD9, 0x00, 0x12, 0x00, 0x03, 0x00, 0xDA, 0x00,
                    0x00, 0x00, 0xDA, 0x00, 0xDA, 0x00, 0x00, 0x00, 0xD0, 0x00, 0x08, 0x00, 0x0A, 0x00, 0x06, 0x00,
                    0x06, 0x00, 0x08, 0x00, 0xDA, 0x00, 0x12, 0x00, 0x01, 0x00, 0xC9, 0x00, 0x14, 0x00, 0xCE, 0x00,
                    0x00, 0x00, 0xCC, 0x00, 0xCC, 0x00, 0xC9, 0x00, 0x19, 0x00, 0xD0, 0x00, 0xD0, 0x00, 0x08, 0x00,
                    0x0A, 0x00, 0x06, 0x00, 0x06, 0x00, 0x08, 0x00, 0xDA, 0x00, 0x12, 0x00, 0x01, 0x00, 0xC9, 0x00,
                    0x0F, 0x00, 0xD5, 0x00, 0x00, 0x00, 0xDA, 0x00, 0xDA, 0x00, 0x00, 0x00, 0xD0, 0x00, 0x08, 0x00,
                    0x0A, 0x00, 0x06, 0x00, 0x06, 0x00, 0x0D, 0x00, 0x7F, 0x00, 0x12, 0x00, 0x01, 0x00, 0xCA, 0x00,
                    0x05, 0x00, 0xDC, 0x00, 0x00, 0x00, 0xDA, 0x00, 0xDA, 0x00, 0x00, 0x00, 0xD0, 0x00, 0x08, 0x00,
                    0x0A, 0x00, 0x06, 0x00, 0x06, 0x00, 0x0D, 0x00, 0x7F, 0x00, 0x01, 0x00, 0x12, 0x00, 0xCC, 0x00,
                    0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x93, 0x00, 0x06, 0x00, 0x13, 0x00,
                    0x1F, 0x00, 0x8D, 0x00, 0x81, 0x00, 0x99, 0x00, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x94, 0x00, 0x17, 0x00, 0x12, 0x00,
                    0x13, 0x00, 0x19, 0x00, 0x88, 0x00, 0x8C, 0x00, 0x1D, 0x00, 0x06, 0x00, 0x03, 0x00, 0x99, 0x00,
                    0x8B, 0x00, 0x0B, 0x00, 0x92, 0x00, 0x95, 0x00, 0x06, 0x00, 0x1D, 0x00, 0x01, 0x00, 0x85, 0x00,
                    0x93, 0x00, 0x0B, 0x00, 0x1A, 0x00, 0x06, 0x00, 0x17, 0x00, 0x10, 0x00, 0x07, 0x00, 0x8E, 0x00,
                    0x1F, 0x00, 0x0D, 0x00, 0x1A, 0x00, 0x87, 0x00, 0xB3, 0x00, 0xAF, 0x00, 0x18, 0x00, 0x19, 0x00,
                    0x0A, 0x00, 0x93, 0x00, 0x9E, 0x00, 0x1D, 0x00, 0x88, 0x00, 0x93, 0x00, 0x09, 0x00, 0x09, 0x00,
                    0x1C, 0x00, 0x10, 0x00, 0x11, 0x00, 0x9F, 0x00, 0x84, 0x00, 0x0C, 0x00, 0x99, 0x00, 0x9D, 0x00,
                    0x13, 0x00, 0x06, 0x00, 0x03, 0x00, 0x18, 0x00, 0x09, 0x00, 0x9A, 0x00, 0x0F, 0x00, 0x9D, 0x00,
                    0x0B, 0x00, 0x0D, 0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00, 0x9F, 0x00, 0x11, 0x00, 0x9F, 0x00,
                    0x0B, 0x00, 0x0A, 0x00, 0x07, 0x00, 0x13, 0x00, 0x0E, 0x00, 0x9B, 0x00, 0x97, 0x00, 0x99, 0x00,
                    0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x95, 0x00, 0x91, 0x00, 0x0C, 0x00, 0x08, 0x00,
                    0x8B, 0x00, 0x87, 0x00, 0x0A, 0x00, 0x11, 0x00, 0x04, 0x00, 0x85, 0x00, 0x96, 0x00, 0xC5, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x9F, 0x00, 0x1B, 0x00, 0x96, 0x00,
                    0x8D, 0x00, 0x1B, 0x00, 0x88, 0x00, 0x93, 0x00, 0x09, 0x00, 0x09, 0x00, 0x1C, 0x00, 0x10, 0x00,
                    0x11, 0x00, 0x9F, 0x00, 0x84, 0x00, 0x80, 0x00, 0x15, 0x00, 0x19, 0x00, 0x03, 0x00, 0x1A, 0x00,
                    0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x95, 0x00, 0x17, 0x00, 0x87, 0x00,
                    0x86, 0x00, 0x0A, 0x00, 0x85, 0x00, 0x88, 0x00, 0x06, 0x00, 0x1B, 0x00, 0x1A, 0x00, 0x16, 0x00,
                    0x02, 0x00, 0x9B, 0x00, 0x0E, 0x00, 0xB2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
                    0x02, 0x80, 0x02, 0x80, 0xBC, 0xAF, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0xC0, 0xB0, 0x00, 0x00,
                    0x08, 0x00, 0x00, 0x00, 0xD4, 0x11, 0x00, 0x00, 0x5F, 0x12, 0x00, 0x00, 0xD6, 0x12, 0x00, 0x00,
                    0x98, 0x14, 0x00, 0x00, 0xB0, 0x14, 0x00, 0x00, 0xF6, 0x16, 0x00, 0x00, 0x90, 0x1B, 0x00, 0x00,
                    0x26, 0x1C, 0x00, 0x00, 0xCD, 0x1D, 0x00, 0x00, 0x2D, 0x1F, 0x00, 0x00, 0x57, 0x1F, 0x00, 0x00,
                    0xB3, 0x2B, 0x00, 0x00, 0xD7, 0x38, 0x00, 0x00, 0xF4, 0x38, 0x00, 0x00, 0x11, 0x39, 0x00, 0x00,
                    0x2F, 0x39, 0x00, 0x00, 0x4E, 0x39, 0x00, 0x00, 0x6D, 0x39, 0x00, 0x00, 0x8C, 0x39, 0x00, 0x00,
                    0xAA, 0x39, 0x00, 0x00, 0xB0, 0x3B, 0x00, 0x00, 0xCD, 0x3B, 0x00, 0x00, 0xF7, 0x3C, 0x00, 0x00,
                    0x10, 0x45, 0x00, 0x00, 0x30, 0x45, 0x00, 0x00, 0xC9, 0x45, 0x00, 0x00, 0xF8, 0x45, 0x00, 0x00,
                    0xB8, 0x47, 0x00, 0x00, 0xD5, 0x47, 0x00, 0x00, 0x36, 0x50, 0x00, 0x00, 0x96, 0x50, 0x00, 0x00,
                    0x41, 0x51, 0x00, 0x00, 0x7B, 0x5C, 0x00, 0x00, 0x16, 0x60, 0x00, 0x00, 0x46, 0x60, 0x00, 0x00,
                    0xFD, 0x60, 0x00, 0x00, 0x8C, 0x61, 0x00, 0x00, 0xED, 0x61, 0x00, 0x00, 0x98, 0x62, 0x00, 0x00,
                    0x4D, 0x63, 0x00, 0x00, 0xDD, 0x63, 0x00, 0x00, 0x0E, 0x65, 0x00, 0x00, 0x2B, 0x65, 0x00, 0x00,
                    0x52, 0x66, 0x00, 0x00, 0x21, 0x67, 0x00, 0x00, 0x16, 0x68, 0x00, 0x00, 0x10, 0x69, 0x00, 0x00,
                    0xC7, 0x69, 0x00, 0x00, 0xE8, 0x69, 0x00, 0x00, 0xA8, 0x6D, 0x00, 0x00, 0xD4, 0x6F, 0x00, 0x00,
                    0x17, 0x70, 0x00, 0x00, 0x6F, 0x70, 0x00, 0x00, 0xCC, 0x70, 0x00, 0x00, 0x61, 0x71, 0x00, 0x00,
                    0x0A, 0x72, 0x00, 0x00, 0x09, 0x73, 0x00, 0x00, 0x58, 0x73, 0x00, 0x00, 0x91, 0x74, 0x00, 0x00,
                    0xF4, 0x74, 0x00, 0x00, 0x5D, 0x76, 0x00, 0x00, 0xB5, 0x76, 0x00, 0x00, 0xF7, 0x76, 0x00, 0x00,
                    0xCD, 0x79, 0x00, 0x00, 0xE7, 0x7A, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0xA0, 0x6B, 0x00, 0x00,
                    0x01, 0x05, 0x02, 0x00, 0x05, 0x74, 0x01, 0x00, 0x01, 0x04, 0x01, 0x00, 0x04, 0x42, 0x00, 0x00,
                    0x01, 0x1F, 0x0C, 0x00, 0x1F, 0x74, 0x16, 0x00, 0x1F, 0x64, 0x15, 0x00, 0x1F, 0x34, 0x14, 0x00,
                    0x1F, 0xD2, 0x18, 0xF0, 0x16, 0xE0, 0x14, 0xD0, 0x12, 0xC0, 0x10, 0x50, 0x01, 0x04, 0x01, 0x00,
                    0x04, 0x42, 0x00, 0x00, 0x01, 0x06, 0x02, 0x00, 0x06, 0x32, 0x02, 0x30, 0x01, 0x06, 0x02, 0x00,
                    0x06, 0x32, 0x02, 0x30, 0x01, 0x10, 0x06, 0x00, 0x10, 0x54, 0x0B, 0x00, 0x10, 0x34, 0x0A, 0x00,
                    0x10, 0x52, 0x0C, 0x60, 0x01, 0x06, 0x02, 0x00, 0x06, 0x32, 0x02, 0x30, 0x01, 0x0A, 0x04, 0x00,
                    0x0A, 0x34, 0x06, 0x00, 0x0A, 0x32, 0x06, 0x70, 0x01, 0x10, 0x06, 0x00, 0x10, 0x64, 0x0D, 0x00,
                    0x10, 0x34, 0x0C, 0x00, 0x10, 0x92, 0x0C, 0x70, 0x01, 0x06, 0x02, 0x00, 0x06, 0x72, 0x02, 0x30,
                    0x01, 0x17, 0x08, 0x00, 0x17, 0x74, 0x10, 0x00, 0x17, 0x64, 0x0F, 0x00, 0x17, 0x34, 0x0E, 0x00,
                    0x17, 0xB2, 0x10, 0x50, 0x01, 0x1A, 0x09, 0x00, 0x1A, 0x64, 0x2E, 0x00, 0x1A, 0x34, 0x2D, 0x00,
                    0x1A, 0x01, 0x28, 0x00, 0x0E, 0xE0, 0x0C, 0x70, 0x0B, 0x50, 0x00, 0x00, 0x01, 0x1C, 0x0B, 0x00,
                    0x1C, 0x34, 0x21, 0x00, 0x1C, 0x01, 0x16, 0x00, 0x10, 0xF0, 0x0E, 0xE0, 0x0C, 0xD0, 0x0A, 0xC0,
                    0x08, 0x70, 0x07, 0x60, 0x06, 0x50, 0x00, 0x00, 0x01, 0x14, 0x08, 0x00, 0x14, 0x64, 0x09, 0x00,
                    0x14, 0x54, 0x08, 0x00, 0x14, 0x34, 0x07, 0x00, 0x14, 0x32, 0x10, 0x70, 0x01, 0x17, 0x0A, 0x00,
                    0x17, 0x54, 0x0C, 0x00, 0x17, 0x34, 0x0B, 0x00, 0x17, 0x32, 0x13, 0xF0, 0x11, 0xE0, 0x0F, 0xD0,
                    0x0D, 0x70, 0x0C, 0x60, 0x01, 0x0A, 0x04, 0x00, 0x0A, 0x34, 0x07, 0x00, 0x0A, 0x32, 0x06, 0x70,
                    0x01, 0x18, 0x0A, 0x00, 0x18, 0x64, 0x0C, 0x00, 0x18, 0x54, 0x0B, 0x00, 0x18, 0x34, 0x0A, 0x00,
                    0x18, 0x52, 0x14, 0xF0, 0x12, 0xE0, 0x10, 0x70, 0x01, 0x06, 0x02, 0x00, 0x06, 0x32, 0x02, 0x30,
                    0x01, 0x1D, 0x0C, 0x00, 0x1D, 0x74, 0x0B, 0x00, 0x1D, 0x64, 0x0A, 0x00, 0x1D, 0x54, 0x09, 0x00,
                    0x1D, 0x34, 0x08, 0x00, 0x1D, 0x32, 0x19, 0xF0, 0x17, 0xE0, 0x15, 0xC0, 0x01, 0x06, 0x02, 0x00,
                    0x06, 0x32, 0x02, 0x30, 0x01, 0x06, 0x02, 0x00, 0x06, 0x52, 0x02, 0x30, 0x01, 0x23, 0x0B, 0x00,
                    0x23, 0x34, 0x76, 0x00, 0x23, 0x01, 0x6C, 0x00, 0x14, 0xF0, 0x12, 0xE0, 0x10, 0xD0, 0x0E, 0xC0,
                    0x0C, 0x70, 0x0B, 0x60, 0x0A, 0x50, 0x00, 0x00, 0x01, 0x1B, 0x0B, 0x00, 0x1B, 0x64, 0x4C, 0x00,
                    0x1B, 0x54, 0x4B, 0x00, 0x1B, 0x34, 0x4A, 0x00, 0x1B, 0x01, 0x46, 0x00, 0x14, 0xF0, 0x12, 0xE0,
                    0x10, 0x70, 0x00, 0x00, 0x01, 0x1C, 0x0C, 0x00, 0x1C, 0x64, 0x0D, 0x00, 0x1C, 0x54, 0x0C, 0x00,
                    0x1C, 0x34, 0x0B, 0x00, 0x1C, 0x32, 0x18, 0xF0, 0x16, 0xE0, 0x14, 0xD0, 0x12, 0xC0, 0x10, 0x70,
                    0x01, 0x14, 0x08, 0x00, 0x14, 0x64, 0x08, 0x00, 0x14, 0x54, 0x07, 0x00, 0x14, 0x34, 0x06, 0x00,
                    0x14, 0x32, 0x10, 0x70, 0x01, 0x0A, 0x04, 0x00, 0x0A, 0x74, 0x02, 0x00, 0x05, 0x34, 0x01, 0x00,
                    0x01, 0x24, 0x0B, 0x00, 0x24, 0x34, 0x73, 0x01, 0x24, 0x01, 0x6A, 0x01, 0x15, 0xF0, 0x13, 0xE0,
                    0x11, 0xD0, 0x0F, 0xC0, 0x0D, 0x70, 0x0C, 0x60, 0x0B, 0x50, 0x00, 0x00, 0x01, 0x21, 0x0B, 0x00,
                    0x21, 0x64, 0x91, 0x00, 0x21, 0x34, 0x8E, 0x00, 0x21, 0x01, 0x88, 0x00, 0x12, 0xF0, 0x10, 0xE0,
                    0x0E, 0xD0, 0x0C, 0x70, 0x0B, 0x50, 0x00, 0x00, 0x01, 0x0C, 0x02, 0x00, 0x0C, 0xF2, 0x02, 0x50,
                    0x01, 0x15, 0x08, 0x00, 0x15, 0x64, 0x11, 0x00, 0x15, 0x34, 0x10, 0x00, 0x15, 0x92, 0x0E, 0xF0,
                    0x0C, 0x70, 0x0B, 0x50, 0x01, 0x1B, 0x09, 0x00, 0x1B, 0x34, 0x95, 0x00, 0x1B, 0x01, 0x8E, 0x00,
                    0x0C, 0xF0, 0x0A, 0xE0, 0x08, 0x70, 0x07, 0x60, 0x06, 0x50, 0x00, 0x00, 0x01, 0x17, 0x09, 0x00,
                    0x17, 0x01, 0x28, 0x00, 0x0B, 0xF0, 0x09, 0xE0, 0x07, 0xC0, 0x05, 0x70, 0x04, 0x60, 0x03, 0x30,
                    0x02, 0x50, 0x00, 0x00, 0x01, 0x04, 0x01, 0x00, 0x04, 0x62, 0x00, 0x00, 0x01, 0x07, 0x01, 0x00,
                    0x07, 0xA2, 0x00, 0x00, 0x01, 0x15, 0x08, 0x00, 0x15, 0x01, 0x1F, 0x00, 0x09, 0xF0, 0x07, 0xE0,
                    0x05, 0x70, 0x04, 0x60, 0x03, 0x30, 0x02, 0x50, 0x01, 0x14, 0x07, 0x00, 0x14, 0x34, 0x1C, 0x00,
                    0x14, 0x01, 0x18, 0x00, 0x08, 0x70, 0x07, 0x60, 0x06, 0x50, 0x00, 0x00, 0x01, 0x0F, 0x06, 0x00,
                    0x0F, 0x64, 0x0B, 0x00, 0x0F, 0x34, 0x0A, 0x00, 0x0F, 0x72, 0x0B, 0x70, 0x01, 0x23, 0x0B, 0x00,
                    0x23, 0x34, 0x40, 0x01, 0x23, 0x01, 0x36, 0x01, 0x14, 0xF0, 0x12, 0xE0, 0x10, 0xD0, 0x0E, 0xC0,
                    0x0C, 0x70, 0x0B, 0x60, 0x0A, 0x50, 0x00, 0x00, 0x01, 0x0A, 0x04, 0x00, 0x0A, 0x34, 0x0A, 0x00,
                    0x0A, 0x72, 0x06, 0x70, 0x01, 0x0D, 0x04, 0x00, 0x0D, 0x34, 0x11, 0x00, 0x0D, 0xD2, 0x06, 0x50,
                    0x01, 0x0D, 0x04, 0x00, 0x0D, 0x34, 0x0E, 0x00, 0x0D, 0xB2, 0x06, 0x50, 0x01, 0x0A, 0x04, 0x00,
                    0x0A, 0x34, 0x08, 0x00, 0x0A, 0x52, 0x06, 0x70, 0x01, 0x17, 0x08, 0x00, 0x17, 0x74, 0x10, 0x00,
                    0x17, 0x64, 0x0F, 0x00, 0x17, 0x34, 0x0E, 0x00, 0x17, 0xB2, 0x10, 0x50, 0x01, 0x19, 0x0B, 0x00,
                    0x19, 0x74, 0x07, 0x00, 0x19, 0x64, 0x06, 0x00, 0x19, 0x54, 0x05, 0x00, 0x19, 0x34, 0x04, 0x00,
                    0x19, 0xF0, 0x17, 0xE0, 0x15, 0xC0, 0x00, 0x00, 0x01, 0x05, 0x02, 0x00, 0x05, 0x34, 0x01, 0x00,
                    0x01, 0x18, 0x0A, 0x00, 0x18, 0x64, 0x0A, 0x00, 0x18, 0x54, 0x09, 0x00, 0x18, 0x34, 0x08, 0x00,
                    0x18, 0x32, 0x14, 0xF0, 0x12, 0xE0, 0x10, 0x70, 0x01, 0x0F, 0x06, 0x00, 0x0F, 0x64, 0x07, 0x00,
                    0x0F, 0x34, 0x06, 0x00, 0x0F, 0x32, 0x0B, 0x70, 0x01, 0x14, 0x08, 0x00, 0x14, 0x64, 0x08, 0x00,
                    0x14, 0x54, 0x07, 0x00, 0x14, 0x34, 0x06, 0x00, 0x14, 0x32, 0x10, 0x70, 0x01, 0x05, 0x02, 0x00,
                    0x05, 0x34, 0x01, 0x00, 0x01, 0x06, 0x02, 0x00, 0x06, 0x32, 0x02, 0x30, 0x01, 0x06, 0x02, 0x00,
                    0x06, 0xB2, 0x02, 0x30, 0x01, 0x10, 0x04, 0x00, 0x10, 0x34, 0x12, 0x00, 0x10, 0xF2, 0x06, 0x50,
                    0x01, 0x1F, 0x0B, 0x00, 0x1F, 0x34, 0x66, 0x00, 0x1F, 0x01, 0x5E, 0x00, 0x10, 0xF0, 0x0E, 0xE0,
                    0x0C, 0xD0, 0x0A, 0xC0, 0x08, 0x70, 0x07, 0x60, 0x06, 0x50, 0x00, 0x00, 0x01, 0x1B, 0x0B, 0x00,
                    0x1B, 0x64, 0x4B, 0x00, 0x1B, 0x54, 0x4A, 0x00, 0x1B, 0x34, 0x48, 0x00, 0x1B, 0x01, 0x44, 0x00,
                    0x14, 0xF0, 0x12, 0xE0, 0x10, 0x70, 0x00, 0x00, 0x01, 0x10, 0x06, 0x00, 0x10, 0x64, 0x0B, 0x00,
                    0x10, 0x34, 0x0A, 0x00, 0x10, 0x52, 0x0C, 0x70, 0x01, 0x13, 0x08, 0x00, 0x13, 0x34, 0x0F, 0x00,
                    0x13, 0x52, 0x0C, 0xF0, 0x0A, 0xE0, 0x08, 0x70, 0x07, 0x60, 0x06, 0x50, 0x01, 0x1E, 0x0B, 0x00,
                    0x1E, 0x64, 0x1F, 0x00, 0x1E, 0x34, 0x1C, 0x00, 0x1E, 0x01, 0x16, 0x00, 0x12, 0xF0, 0x10, 0xE0,
                    0x0E, 0xC0, 0x0C, 0x70, 0x0B, 0x50, 0x00, 0x00, 0x01, 0x0A, 0x04, 0x00, 0x0A, 0x34, 0x0A, 0x00,
                    0x0A, 0x72, 0x06, 0x70, 0x01, 0x1A, 0x09, 0x00, 0x1A, 0x64, 0x1B, 0x00, 0x1A, 0x34, 0x1A, 0x00,
                    0x1A, 0x01, 0x16, 0x00, 0x0E, 0xF0, 0x0C, 0x70, 0x0B, 0x50, 0x00, 0x00, 0x01, 0x27, 0x0D, 0x00,
                    0x27, 0x74, 0x2D, 0x00, 0x27, 0x64, 0x2C, 0x00, 0x27, 0x34, 0x2B, 0x00, 0x27, 0x01, 0x24, 0x00,
                    0x1C, 0xF0, 0x1A, 0xE0, 0x18, 0xD0, 0x16, 0xC0, 0x14, 0x50, 0x00, 0x00, 0x01, 0x14, 0x08, 0x00,
                    0x14, 0x64, 0x0A, 0x00, 0x14, 0x54, 0x09, 0x00, 0x14, 0x34, 0x08, 0x00, 0x14, 0x52, 0x10, 0x70,
                    0x01, 0x17, 0x07, 0x00, 0x17, 0x74, 0x21, 0x00, 0x17, 0x34, 0x20, 0x00, 0x17, 0x01, 0x1E, 0x00,
                    0x0B, 0x50, 0x00, 0x00, 0x01, 0x23, 0x0D, 0x00, 0x23, 0xC4, 0x27, 0x00, 0x23, 0x74, 0x26, 0x00,
                    0x23, 0x64, 0x25, 0x00, 0x23, 0x34, 0x24, 0x00, 0x23, 0x01, 0x20, 0x00, 0x18, 0xF0, 0x16, 0xE0,
                    0x14, 0x50, 0x00, 0x00, 0x01, 0x12, 0x06, 0x00, 0x12, 0x64, 0x11, 0x00, 0x12, 0x34, 0x0E, 0x00,
                    0x12, 0xB2, 0x0B, 0x50, 0x01, 0x1B, 0x09, 0x00, 0x1B, 0x74, 0x1A, 0x00, 0x1B, 0x64, 0x19, 0x00,
                    0x1B, 0x34, 0x18, 0x00, 0x1B, 0x01, 0x16, 0x00, 0x10, 0x50, 0x00, 0x00, 0x01, 0x11, 0x03, 0x00,
                    0x11, 0x01, 0x4A, 0x02, 0x02, 0x50, 0x00, 0x00, 0x01, 0x10, 0x06, 0x00, 0x10, 0x64, 0x08, 0x00,
                    0x10, 0x34, 0x07, 0x00, 0x10, 0x32, 0x0C, 0x70, 0x01, 0x14, 0x08, 0x00, 0x14, 0x64, 0x08, 0x00,
                    0x14, 0x54, 0x07, 0x00, 0x14, 0x34, 0x06, 0x00, 0x14, 0x32, 0x10, 0x70, 0x01, 0x15, 0x08, 0x00,
                    0x15, 0x64, 0x0D, 0x00, 0x15, 0x34, 0x0C, 0x00, 0x15, 0x72, 0x0E, 0xE0, 0x0C, 0x70, 0x0B, 0x50,
                    0x01, 0x1F, 0x0C, 0x00, 0x1F, 0x74, 0x15, 0x00, 0x1F, 0x64, 0x14, 0x00, 0x1F, 0x34, 0x13, 0x00,
                    0x1F, 0xB2, 0x18, 0xF0, 0x16, 0xE0, 0x14, 0xD0, 0x12, 0xC0, 0x10, 0x50, 0x01, 0x16, 0x07, 0x00,
                    0x16, 0x01, 0x64, 0x00, 0x07, 0xE0, 0x05, 0x70, 0x04, 0x60, 0x03, 0x30, 0x02, 0x50, 0x00, 0x00,
                    0x01, 0x12, 0x06, 0x00, 0x12, 0x74, 0x13, 0x00, 0x12, 0x34, 0x10, 0x00, 0x12, 0xD2, 0x0B, 0x50,
                    0x01, 0x0C, 0x06, 0x00, 0x0C, 0x34, 0x0E, 0x00, 0x0C, 0x72, 0x08, 0x70, 0x07, 0x60, 0x06, 0x50,
                    0x01, 0x17, 0x0A, 0x00, 0x17, 0x54, 0x11, 0x00, 0x17, 0x34, 0x10, 0x00, 0x17, 0x92, 0x13, 0xF0,
                    0x11, 0xE0, 0x0F, 0xC0, 0x0D, 0x70, 0x0C, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                ]
            r13d = 1
            r8d = r13d
            edx = r13d+4
            unk_13FDEBC38 = [0x0C, 0x00, 0xCF, 0x00, 0x00, 0x00, 0xC3, 0x00, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
            rax = sub_13FDE67D4(unk_13FDEBC38,5,1,binar)
            edx = 0x108
            rcx = [0x33, 0x00, 0x33, 0x00, 0x61, 0x00, 0x65, 0x00, 0x39, 0x00, 0x31, 0x00, 0x36, 0x00, 0x63, 0x00,
                0x63, 0x00, 0x35, 0x00, 0x34, 0x00, 0x66, 0x00, 0x35, 0x00, 0x61, 0x00, 0x36, 0x00, 0x36, 0x00,
                0x00, 0x00, 0x65, 0x00, 0x78, 0x00, 0x65, 0x00] # this corresponds to 33ae916cc54f5a66.exe
            r9d = edx
            r8d = rcx
            
            new_s = ""
            for i in range(0,len(rcx),2):
                new_s += chr(rcx[i])
            print(new_s)
            for i in range(0,len(rax)):
                new_s = replace_str_index(new_s,i,rax[i])
            r8d = new_s[3:]
            print(r8d)
            rcx = new_s
            rax = new_s
            print(rax)
            res = (re.sub('.', lambda x: r'%04X' % ord(x.group()), rax))
            print(res)
            r8 = "C:\\Windows\\SYSTEM32\ntdll.dll"
            my_wcsncat(res[2:],r8,0x108)

if __name__ == "__main__":
    ntdll = get_ntdll_and_unhook2(0xD22E2014)
