# coding:utf-8

import md5py
import sys
from urllib import unquote
import hashlib
import struct
import urllib


def payload(length, str_append):
    pad = ''
    n0 = ((56 - (length + 1) % 64) % 64)
    pad += '\x80' 
    pad += '\x00'*n0 + struct.pack('Q', length*8)

    return pad + str_append


def hashmd5(str):
    return hashlib.md5(str).hexdigest()


def check_extension_attack():
    for i in range(1, 65):
        s = "A" * i
        mm = md5py.md5()
        assert hashlib.md5(s).hexdigest() == mm.my_md5(s)
        print mm.my_md5(s)
    for i in range(1, 100):
        for j in range(1, 10):
            s = 'A' * i
            salt = 'B' * j
            mm = md5py.md5()
            msg = salt + s + payload(len(salt+s), 'joychou')
            assert hashmd5(msg) == mm.extension_attack(hashmd5(salt+s), 'joychou', len(salt+s))

# check if md5 extension attack is correct
# check_extension_attack()

if len(sys.argv) < 3:
    print "Usage: ", sys.argv[0], " <md5string> <string_to_append> [length of plaintext of md5string]"
    sys.exit()


hash_origin = sys.argv[1]
str_append = sys.argv[2]
lenth = int(sys.argv[3])

m = md5py.md5()

str_payload = payload(lenth, str_append)
print "Payload: ", repr(str_payload)
print "Payload urlencode:", urllib.quote_plus(str_payload)
print "md5:", m.extension_attack(hash_origin, str_append, lenth)
