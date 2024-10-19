apis = "C:\\Users\\essog\\OneDrive\\Bureau\\maldev\\win32 api\\apis.txt";

def hash_djb2(string):
    hash_value = 5381
    for char in string:
        hash_value = ((hash_value << 5) + hash_value) + ord(char)  # hash * 33 + ord(char)
    return str(hash_value)


with open(apis, 'r') as fhandle:
    lines = fhandle.readlines()
    for item in lines:
        item.strip()
        print("[+] " + item + ":" + hash_djb2(item))