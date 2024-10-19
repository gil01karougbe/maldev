import pefile
import json

#pe =  pefile.PE("C:\\Windows\\System32\\user32.dll")
#pe =  pefile.PE("C:\\Windows\\System32\\kernelbase.dll")
pe =  pefile.PE("C:\\Windows\\System32\\kernel32.dll")
exports_list = []
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    try:
        exports_list.append(exp.name.decode('utf-8'))
    except:
        continue
exports = {"exports": exports_list}
with open("C:\\Users\\essog\\OneDrive\\Bureau\\maldev\\pe format\\exports.json", "wb") as f:
    f.write(json.dumps(exports).encode())