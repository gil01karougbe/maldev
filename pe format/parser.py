from tabulate import tabulate
import pefile

pe =  pefile.PE("C:\\Users\\essog\\OneDrive\\Bureau\\WIN-MALWARE-DEV\\inject.exe")

###IMAGE_DOS_HEADER
print("[+] DOS HEADER:")
dosheaser = pe.DOS_HEADER
print(hex(dosheaser.e_magic))

###IMAGE_NT_HEADERS
##NT_SIGNATURE
signature = pe.NT_HEADERS.Signature
##IMAGE_FILE_HEADER
fheader = pe.NT_HEADERS.FILE_HEADER
print("[+] Machine")
print(hex(fheader.Machine))
##IMAGE_OPTIONAL_HEADER
oheader = pe.NT_HEADERS.OPTIONAL_HEADER

###DATA DIRECTORIES


###SECTIONS
table = []
for section in pe.sections:
    table.append([
        section.Name.decode().strip(),
        hex(section.VirtualAddress),
        hex(section.Misc_VirtualSize),
        section.SizeOfRawData
    ])
headers = ["Section Name", "Virtual Address", "Virtual Size", "Size of Raw Data"]
print(tabulate(table, headers=headers, tablefmt="grid"))