import struct
num = 12345678
buffer = struct.pack(">L", num)
print(buffer)