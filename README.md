MultiAV Scanner Wrapper
=======================

MultiAV Python API. It can scan a file or directory with multiple AV
engines simultaneously. It uses, with the only exception of ClamAV, the
command line AV scanners and extracts the malware names from the output
of the command line tools (for ClamAV it uses the https://code.google.com/p/pyclamd/ extension).

It supports a total of 16 AV engines. The list of currently supported
engines is the following:

   * ClamAV (Ultra-fast, using the daemon)
   * F-Prot (Ultra-fast)
   * Comodo (Fast)
   * BitDefender (Medium)
   * ESET (Slow)
   * Avira (Slow)
   * Sophos (Medium)
   * Avast (Ultra-fast, using the daemon)
   * AVG (Ultra-fast, using the daemon)
   * DrWeb (Slow)
   * McAfee (Very slow, only enabled when running all the engines)
   * Ikarus (Medium, using Wine in Linux/Unix)
   * F-Secure (Fast)
   * Kaspersky (Fast, only tested under MacOSX)
   * Zoner Antivirus (Ultra-fast)
   * MicroWorld-eScan (Fast)

This tool have been tested only under Linux. However, it should work equally
in other Unix based operating systems as well as in Windows as long as the
output from the AV command line utilities maintains the same format.

## Example usages

MultiAV.py can be executed via the command line by simply giving to it a
valid path:

```
$ python multiav.py malware/xpaj/

{'AVG': {'malware/xpaj/00908235ee9e267fa2f4c83fb4304c63af976cbc': 'Win32/Xpaj',
         'malware/xpaj/43194f9abf525520639a8bcd434403287ffac63b': 'Win32/Xpaj',
         'malware/xpaj/4fd8b09fd238e5bab13cebed9232c18d505a1a16': 'Win32/Xpaj',
         'malware/xpaj/e0e8c24028775831c52705e42fc2547103bafbbc': 'Win32/Xpaj',
         'malware/xpaj/f144ecc2f480b757946449086fa01eb71694554f': 'Win32/Xpaj'},
 'ClamAV': {'malware/xpaj/00908235ee9e267fa2f4c83fb4304c63af976cbc': 'BC.W32.Xpaj',
            'malware/xpaj/43194f9abf525520639a8bcd434403287ffac63b': 'BC.W32.Xpaj',
            'malware/xpaj/4fd8b09fd238e5bab13cebed9232c18d505a1a16': 'BC.W32.Xpaj',
            'malware/xpaj/c610e8b351f719c5dcf634b8ffe175abac5331b7': 'W32.Xpaj',
            'malware/xpaj/e0e8c24028775831c52705e42fc2547103bafbbc': 'BC.W32.Xpaj',
            'malware/xpaj/f144ecc2f480b757946449086fa01eb71694554f': 'BC.W32.Xpaj'},
 'Comodo': {'malware/xpaj/00908235ee9e267fa2f4c83fb4304c63af976cbc': 'Malware',
            'malware/xpaj/43194f9abf525520639a8bcd434403287ffac63b': 'Malware',
            'malware/xpaj/4fd8b09fd238e5bab13cebed9232c18d505a1a16': 'Malware',
            'malware/xpaj/bd5232259425c72e5ea1f4071e3075058cf70de2': 'Malware',
            'malware/xpaj/c610e8b351f719c5dcf634b8ffe175abac5331b7': 'Malware',
            'malware/xpaj/e0e8c24028775831c52705e42fc2547103bafbbc': 'Malware',
            'malware/xpaj/f144ecc2f480b757946449086fa01eb71694554f': 'Malware'},
 'ESET': {'malware/xpaj/00908235ee9e267fa2f4c83fb4304c63af976cbc': 'Win32/Goblin.D.Gen virus',
          'malware/xpaj/43194f9abf525520639a8bcd434403287ffac63b': 'Win32/Goblin.D.Gen virus',
          'malware/xpaj/4fd8b09fd238e5bab13cebed9232c18d505a1a16': 'Win32/Goblin.D.Gen virus',
          'malware/xpaj/c610e8b351f719c5dcf634b8ffe175abac5331b7': 'Win32/Goblin.A.Gen virus',
          'malware/xpaj/e0e8c24028775831c52705e42fc2547103bafbbc': 'Win32/Goblin.D.Gen virus',
          'malware/xpaj/f144ecc2f480b757946449086fa01eb71694554f': 'Win32/Goblin.D.Gen virus'},
 'F-Prot': {'malware/xpaj/00908235ee9e267fa2f4c83fb4304c63af976cbc': 'W32/Xpaj.A!Generic',
            'malware/xpaj/43194f9abf525520639a8bcd434403287ffac63b': 'W32/Xpaj.C',
            'malware/xpaj/4fd8b09fd238e5bab13cebed9232c18d505a1a16': 'W32/Xpaj.A',
            'malware/xpaj/bd5232259425c72e5ea1f4071e3075058cf70de2': 'W32/Xpaj.A!Generic (damaged)',
            'malware/xpaj/c610e8b351f719c5dcf634b8ffe175abac5331b7': 'W32/Xpaj.A.gen!Eldorado (generic, not disinfectable)',
            'malware/xpaj/e0e8c24028775831c52705e42fc2547103bafbbc': 'W32/Xpaj.C',
            'malware/xpaj/f144ecc2f480b757946449086fa01eb71694554f': 'W32/Xpaj.A!Generic'},
 'Sophos': {'malware/xpaj/00908235ee9e267fa2f4c83fb4304c63af976cbc': 'Mal/Xpaj-B',
            'malware/xpaj/43194f9abf525520639a8bcd434403287ffac63b': 'Mal/Xpaj-B',
            'malware/xpaj/4fd8b09fd238e5bab13cebed9232c18d505a1a16': 'Mal/Xpaj-B',
            'malware/xpaj/c610e8b351f719c5dcf634b8ffe175abac5331b7': 'Mal/Xpaj-A',
            'malware/xpaj/e0e8c24028775831c52705e42fc2547103bafbbc': 'Mal/Xpaj-B',
            'malware/xpaj/f144ecc2f480b757946449086fa01eb71694554f': 'Mal/Xpaj-B'}}
```

However, it's not designed to be executed as an independent tool but 
rather to be used as an API for other tools. The following is an example
of how to use the MultiAV API In your own Python tools:

```python
import pprint
import multiav

multi_av = multiav.CMultiAV()
ret = multi_av.scan(path, multiav.AV_SPEED_MEDIUM)
pprint.pprint(multi_av)
```

Here we're creating a CMultiAV object without specifying the
configuration file (by default "config.cfg"). We can specify it by
passing the path to the *.cfg file to the constructor of the Python
object:

```python
multi_av = multiav.CMultiAV("/path/to/cfg")
```

In the example Python code we're also specifying that we only want to 
run antivirus scanners considered of either fast or "medium" speed. We
can also specify that we want to run all engines (both "fast", "medium",
"slow" and "very slow" ones) by setting the second argument to
object.scan() to AV_SPEED_ALL (or to AV_SPEED_SLOW if we want to omit
the scanners that are really slow, namely, Avast and McAfee):

```python
# For all engines
ret = multi_av.scan(path, multiav.AV_SPEED_ALL)
# For most of the engines with the only exception of Avast and McAfee
ret = multi_av.scan(path, multiav.AV_SPEED_SLOW)
```

AV_SPEED_ALL is default behaviour if one doesn't specifies the maximum 
allowed speed. One can also specify that only fast engines can be 
executed:

```python
ret = multi_av.scan(path, multiav.AV_SPEED_FAST)
```

By default, MultiAV.py will try to run AV scanners at the same time,
simultaneously, maintaning a total number of processes in memory equal
to the number of CPUs reported by multiprocessing.cpu_count(), which 
takes into account also multiple cores in the same physical processor.
If you don't want to run MultiAV.py in parallel mode you can use the 
method object.single_scan() which receives the same arguments as the
method object.scan(), as in the following example:

```python
ret = multi_av.scan_single(path, multiav.AV_SPEED_SLOW)
```

One can also scan a single buffer using the object.scan_buffer() API:

```python
ret = multiav.scan_buffer(buf, multiav.AV_SPEED_SLOW)
```

## Configuration file

When creating a CMultiAV object one can specify a configuration file
like in the following example:

```python
multi_av = multiav.CMultiAV("/path/to/cfg")
```

The format of the configuration file is rather easy. There are only 2 or
3 parameters that one needs in order to use and configure an AV engine
scanner: PATH, ARGUMENTS and DISABLED (if the engine is not enabled).
The only exception to the rule is ClamAV for which there are only 2 
configuration directives: DISABLED and UNIX_SOCKET, which is the Unix 
socket where the daemon "clamd" is listening.

So, let's say that we want to disable Sophos scanner and configure a new
path for McAfee scanner. We would need to modify our *.cfg file with a
content similar to the following one:

```
[McAfee]
PATH=/new/path/to/uvscan
ARGUMENTS=-the -arguments -we -want

[Sophos]
PATH=whatever
ARGUMENTS=whatever
DISABLED=1
```

# Example Web interface and JSON based web API

Since commit c3828b337b98a450a8b48c764aecbb04cc4d2324, MultiAV distributes a basic example web interface using web.py that offers a simple JSON based API. There is also an example client called "multiav-client.py" that uses the JSON API to scan a file with the multiple engines configured in the MultiAV server.

The current version of the basic JSON based web API exports 3 methods:

   * /api/upload
   * /api/upload_fast
   * /api/search

## API /api/upload

This API uploads and analyses with all the configured engines, regardless of how fast or slow they are, the given sample file.

Example usage:
```python
import os
import json
import pprint
import postfile

host = "multi-av-host-ip:8080"
selector = "/api/upload"
filename = "/path/to/eicar.com.txt"
file_buf = open(filename, "rb").read()
files = [("file_upload", os.path.basename(filename), file_buf)]
json_txt = postfile.post_multipart(host, selector, [], files)
pprint.pprint(json.loads(json_txt))
```

Example output:
```
{u'AVG': {u'/tmp/tmpt1WoID': u'EICAR_Test'},
 u'Avast': {u'/tmp/tmpt1WoID': u'EICAR Test-NOT virus!!!'},
 u'BitDefender': {u'/tmp/tmpt1WoID': u'EICAR-Test-File (not a virus)'},
 u'ClamAV': {u'/tmp/tmpt1WoID': u'Eicar-Test-Signature'},
 u'Comodo': {u'/tmp/tmpt1WoID': u'Malware'},
 u'ESET': {u'/tmp/tmpt1WoID': u'Eicar test file'},
 u'F-Prot': {u'/tmp/tmpt1WoID': u'EICAR_Test_File (exact)'},
 u'Ikarus': {u'/tmp/tmpt1WoID': u'EICAR-ANTIVIRUS-TESTFILE'},
 u'McAfee': {u'/tmp/tmpt1WoID': u'EICAR test file NOT'},
 u'Kaspersky': {u'/tmp/tmpt1WoID': u'EICAR-Test-File'},
 u'Sophos': {u'/tmp/tmpt1WoID': u'EICAR-AV-Test'},
 u'ZAV': {u'/tmp/tmpt1WoID': u'EICAR.Test.File-NoVirus'}}
```

## API /api/upload_fast

This API uploads and analyses with only the fastest configured AV engines (Avast, AVG, ClamAV, F-Prot an Zoner Antivirus) the given sample file.

Example usage:
```python
import os
import json
import pprint
import postfile

host = "multi-av-host-ip:8080"
selector = "/api/upload_fast"
filename = "/path/to/eicar.com.txt"
file_buf = open(filename, "rb").read()
files = [("file_upload", os.path.basename(filename), file_buf)]
json_txt = postfile.post_multipart(host, selector, [], files)
pprint.pprint(json.loads(json_txt))
```

Example output:
```
{u'AVG': {u'/tmp/tmpXveafr': u'EICAR_Test'},
 u'Avast': {u'/tmp/tmpXveafr': u'EICAR Test-NOT virus!!!'},
 u'ClamAV': {u'/tmp/tmpXveafr': u'Eicar-Test-Signature'},
 u'F-Prot': {u'/tmp/tmpXveafr': u'EICAR_Test_File (exact)'},
 u'ZAV': {u'/tmp/tmpXveafr': u'EICAR.Test.File-NoVirus'}}
```

## API /api/search

Returns the previously generated report, if any, of the given MD5, SHA1 or SHA256 cryptographic hash.

Example usage:
```
import json
import pprint
import urllib2

report = urllib2.urlopen("http://multiav-ip:8080/api/search?file_hash=44d88612fea8a8f36de82e1278abb02f").read()
pprint.pprint(json.loads(report))
```

Example output:
```
{u'date': u'Mon May  4 19:50:22 2015',
 u'id': 6494,
 u'infected': 1,
 u'md5': u'44d88612fea8a8f36de82e1278abb02f',
 u'name': u'eicar.com.txt',
 u'report': u'{"F-Prot": {"/tmp/tmpUK1qEI": "EICAR_Test_File (exact)"}, "Avast": {"/tmp/tmpUK1qEI": "EICAR Test-NOT virus!!!"}, "ClamAV": {"/tmp/tmpUK1qEI": "Eicar-Test-Signature"}, "McAfee": {}, "ZAV": {"/tmp/tmpUK1qEI": "EICAR.Test.File-NoVirus"}, "AVG": {"/tmp/tmpUK1qEI": "EICAR_Test"}}',
 u'sha1': u'3395856ce81f2b7382dee72602f798b642f14140',
 u'sha256': u'275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'}
```

Copyright (c) 2014, 2015 Joxean Koret
