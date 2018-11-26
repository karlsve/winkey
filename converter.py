# Disclaimer:
# This is based on this comment https://superuser.com/questions/897706/retrieve-decrypt-windows-7-product-key-from-linux/1247859#1360965
# Some minor additions to be used with the plaintext key or the windows system path

import sys
import argparse

parser = argparse.ArgumentParser(description='Decrypt Win8/8.1/10 Key')
parser.add_argument('mode', metavar='mode', type=str, help='The mode to run')
parser.add_argument('--path', metavar='path', type=str, help='The path to run on, only mode fs')
parser.add_argument('--key', metavar='key', type=str, help='The key to convert, only mode i')
args = parser.parse_args()
if args.mode == 'i':
    key = args.i
else if args.mode == 'fs':
    from Registry import Registry
    path = args.path + '/Windows/System32/config/RegBack/SOFTWARE' # > Win7
    # path = args.path + 'Windows/system32/config/software' # <= Win7
    reg = Registry.Registry(path)
    key = reg.open("Microsoft\Windows NT\CurrentVersion")
did = bytearray([v.value() for v in key.values() if v.name() == "DigitalProductId"][0])
idpart = did[52:52+15]
charStore = "BCDFGHJKMPQRTVWXY2346789";
productkey = "";
for i in range(25):
  c = 0
  for j in range(14, -1, -1):
    c = (c << 8) ^ idpart[j]
    idpart[j] = c // 24
    c %= 24
  productkey = charStore[c] + productkey
print('-'.join([productkey[i * 5:i * 5 + 5] for i in range(5)]))
