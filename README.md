MultiAV Scanner Wrapper
=======================

MultiAV Python API. It can scan a file or directory with multiple AV
engines simulateneously. It uses, with the only exception of ClamAV, the
command line AV scanners and extracts the malware names from the output
of the command line tools.

The list of currently supported engines is the following:

   * ClamAV (Fast)
   * F-Prot (Fast)
   * Comodo (Fast)
   * BitDefender (Medium)
   * ESET (Slow)
   * Avira (Slow)
   * Sophos (Medium)
   * Avast (Slow)
   * AVG (Fast)
   * DrWeb (Slow)

Copyright (c) 2014 Joxean Koret
