# Cspeakes Buffer Overflow

The cspeakes_buffer_overflow.py project was created to assist cyber professionals, white-hat penetration testers,
 and future security researchers in the process of network service exploit development. 

## Requirements:
* Python3.8+

## Scope:
Windows x86 Exploit Development Assistance;
Tested Successfully from x64 Kali VM --> WindowsXP Pro 32 bit; 
  --> Service: Freefloat FTP 1.0
  --> Service: SLMail 5.5
 
## Background

A buffer overflow is basically a situation where a program/service/network service writes data into a memory buffer in such a way that the target memory buffer's defined boundary is overwritten. This is dangerous because it can impose the remaining data into adjacent memory buffers sometimes not owned and/or allotted to the calling program. Exploitation of this type of situation can lead to a number of negative consequences on the target machine including a potential system crash (denial of service), privileged data leakage, and/or full remote access by way of shellcode exploitation.

This situation exists and is seemingly continuously exploitable in legacy and modern software projects largely because of the lack of memory-buffer-boundary-checking via input validation techniques, and lack of secure programming baked into the design such products. Further exacerbating these vulnerabilities is the fact that most lower-level programming languages such as c are ubiquitous in modern software projects due to the lack of software-to-hardware restrictions such as those that prevent direct memory modification, type checking, garbage collection, etc. However, with this freedom and lack of restriction comes the introduction of inherit and unavoidable vulnerabilities such as the classic buffer overflow described and depicted by this project. 

## Usage

```
python3 cspeakes_buffer_overflow.py -i <IP> -p <PORT> -li <local_ip> -lp <local_listening_port> -c <max_char_len_to_test> 
```

## Disclaimer
This script was created for educational purposes only. DO NOT use this script against any system or ip address that you do not have explicit permission to target. Actions such as these ARE ILLEGAL and I take no responsibility for this tool's misuse

Also, be careful when targeting any ip address for that matter as this is purely a developmental project and has no warranty expressed or implied. Additionally, do not use this in a production environment.

*"Quit screwing around, you screw around too much!"* 
-- Richard Adler, South Park
