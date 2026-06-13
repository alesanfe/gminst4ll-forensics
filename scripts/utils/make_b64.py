import base64
d = open('/home/vagrant/beket_extracted2/appy_patched.exe', 'rb').read()
print(f"{len(d)} bytes")
with open('/tmp/appy_patched.b64', 'w') as f:
    f.write(base64.b64encode(d).decode())
print("B64 escrito en /tmp/appy_patched.b64")
