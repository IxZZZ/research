#!/usr/bin/python

import subprocess
import pefile

result = subprocess.run(['wmic', 'service', 'where', 'state like "running" and startname like "LocalSystem" and not pathname like "%svchost.exe%"', 'get', 'pathname', '/format:csv'], stdout=subprocess.PIPE)

for i in str(result.stdout).split("\\r\\r\\n"):
    for j in i.split(","):
        if ".exe" in j:
            binPath = ""
            binPath = j.split("\"")[1] if len(j.split("\"")) > 1 else j
            try:
                pe = pefile.PE(binPath)
            except:
                continue
            try:
                if b"mscoree.dll" in [x.dll for x in pe.DIRECTORY_ENTRY_IMPORT]:
                    print(binPath)
            except:
                continue
