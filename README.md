MultiAV Scanner Wrapper
=======================

MultiAV Python API. It can scan a file or directory with multiple AV
engines simulateneously. It uses, with the only exception of ClamAV, the
command line AV scanners and extracts the malware names from the output
of the command line tools (for ClamAV it uses the https://code.google.com/p/pyclamd/ extension).

It supports a total of 11 AV engines. The list of currently supported
engines is the following:

   * ClamAV (Fast)
   * F-Prot (Fast)
   * Comodo (Fast)
   * BitDefender (Medium)
   * ESET (Slow)
   * Avira (Slow)
   * Sophos (Medium)
   * Avast (Very slow, only enabled when running all the engines)
   * AVG (Fast)
   * DrWeb (Slow)
   * McAfee (Very slow, only enabled when running all the engines)

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
# For most of the engines with the only exception Avast and McAfee
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
configuration directies: DISABLED and UNIX_SOCKET, which is the Unix 
socket where the daemon "clamd" is listening.

Copyright (c) 2014 Joxean Koret
