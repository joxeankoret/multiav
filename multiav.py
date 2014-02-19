#!/usr/bin/python
# -*- coding: utf-8 -*-

#-----------------------------------------------------------------------
# MultiAV scanner wrapper version 0.0.1
# Copyright (c) 2014, Joxean Koret
#
# License:
#
# MultiAV is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser Public License as published by the 
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
# 
# MultiAV is distributed in the hope that it will be  useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser Public License for more details.
# 
# You should have received a copy of the GNU Lesser Public License
# along with DoctestAll.  If not, see 
# <http://www.gnu.org/licenses/>.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>
# 
# Description:
#
# This script implements a very basic wrapper around various AV engines
# available for Linux using their command line scanners with the only
# exception of ClamAV. The currently supported AV engines are listed
# below:
#
#   * ClamAV (Fast)
#   * F-Prot (Fast)
#   * Comodo (Fast)
#   * BitDefender (Medium)
#   * ESET (Slow)
#   * Avira (Slow)
#   * Sophos (Medium)
#   * Avast (Slow)
#   * AVG (Fast)
#   * DrWeb (Slow)
#   * Ikarus (Medium, using wine in Linux/Unix)
#   * F-Secure (Fast)
#
# Support for the following AV engines is planned:
#
#   * Kaspersky
#
# Features:
#
#   * Parallel scan, by default, based on the number of CPUs.
#   * Analysis by AV engine speed.
#
#-----------------------------------------------------------------------

import os
import re
import sys
import codecs
import ConfigParser

from tempfile import NamedTemporaryFile
from subprocess import check_output, CalledProcessError
from multiprocessing import Process, Queue, cpu_count

try:
  import pyclamd
  has_clamd = True
except ImportError:
  has_clamd = False

#-----------------------------------------------------------------------
AV_SPEED_ALL = 3 # Run only when all engines must be executed
AV_SPEED_SLOW = 2
AV_SPEED_MEDIUM = 1
AV_SPEED_FAST = 0

#-----------------------------------------------------------------------
class CAvScanner:
  def __init__(self, cfg_parser):
    self.cfg_parser = cfg_parser
    self.name = None
    self.speed = AV_SPEED_SLOW
    self.results = {}
    self.pattern = None
    self.file_index = 0
    self.malware_index = 1

  def build_cmd(self, path):
    parser = self.cfg_parser
    scan_path = parser.get(self.name, "PATH")
    scan_args = parser.get(self.name, "ARGUMENTS")
    args = [scan_path]
    args.extend(scan_args.split(" "))
    args.append(path)
    return args

  def scan(self, path):
    if self.pattern is None:
      Exception("Not implemented")

    try:
      cmd = self.build_cmd(path)
    except: # There is no entry in the *.cfg file for this AV engine?
      pass

    try:
      output = check_output(cmd)
    except CalledProcessError as e:
      output = e.output

    pattern = self.pattern
    matches = re.findall(pattern, output, re.IGNORECASE|re.MULTILINE)
    for match in matches:
      self.results[match[self.file_index]] = match[self.malware_index]
    return len(self.results) > 0
  
  def is_disabled(self):
    parser = self.cfg_parser
    try:
      self.cfg_parser.get(self.name, "DISABLED")
      return True
    except:
      return False

#-----------------------------------------------------------------------
class CComodoScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "Comodo"
    self.speed = AV_SPEED_FAST
    self.pattern = "(.*) ---\> Found .*, Malware Name is (.*)"

  def build_cmd(self, path):
    parser = self.cfg_parser
    scan_path = parser.get(self.name, "PATH")
    scan_args = parser.get(self.name, "ARGUMENTS")
    args = [scan_path]
    args.extend(scan_args.replace("$FILE", path).split(" "))
    return args

#-----------------------------------------------------------------------
class CClamScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "ClamAV"
    self.speed = AV_SPEED_FAST

  def scan_one(self, path):
    try:
      tmp = pyclamd.scan_file(path)
      if tmp: self.results.update(tmp)
    except:
      pass

  def scan_dir(self, path):    
    for root, dirs, files in os.walk(path, topdown=False):
      for name in files:
        self.scan_one(os.path.join(root, name))
    return len(self.results)

  def scan(self, path):
    parser = self.cfg_parser
    ep = parser.get(self.name, "UNIX_SOCKET")

    pyclamd.init_unix_socket(filename=ep)
    if os.path.isdir(path):
      self.scan_dir(path)
    else:
      self.scan_one(path)
    return len(self.results) == 0

#-----------------------------------------------------------------------
class CFProtScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "F-Prot"
    self.speed = AV_SPEED_FAST
    self.pattern = "\<(.*)\>\s+(.*)"
    self.file_index = 1
    self.malware_index = 0

#-----------------------------------------------------------------------
class CAviraScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "Avira"
    self.speed = AV_SPEED_SLOW
    self.pattern = "ALERT: \[(.*)\] (.*) \<\<\<"
    self.file_index = 1
    self.malware_index = 0

  def scan(self, path):
    os.putenv("LANG", "C")
    return CAvScanner.scan(self, path)

#-----------------------------------------------------------------------
class CBitDefenderScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "BitDefender"
    self.speed = AV_SPEED_SLOW
    self.pattern = "(.*) \s+infected:\s(.*)"

  def scan(self, path):
    os.putenv("LANG", "C")
    return CAvScanner.scan(self, path)

#-----------------------------------------------------------------------
class CEsetScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "ESET"
    self.speed = AV_SPEED_MEDIUM

  def scan(self, path):
    os.putenv("LANG", "C")
    cmd = self.build_cmd(path)
    try:
      output = check_output(cmd)
    except CalledProcessError as e:
      output = e.output

    pattern = 'name="(.*)", threat="(.*)",'
    matches = re.findall(pattern, output, re.IGNORECASE|re.MULTILINE)
    for match in matches:
      malware = match[1][:match[1].find('", ')]
      if malware != "":
        self.results[match[0]] = match[1][:match[1].find('", ')]
    return len(self.results) > 0

#-----------------------------------------------------------------------
class CSophosScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "Sophos"
    self.speed = AV_SPEED_MEDIUM
    self.pattern = "Virus '(.*)' found in file (.*)"
    self.file_index = 1
    self.malware_index = 0

  def scan(self, path):
    os.putenv("LANG", "C")
    return CAvScanner.scan(self, path)

#-----------------------------------------------------------------------
class CAvastScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "Avast"
    self.speed = AV_SPEED_ALL
    self.pattern = "(.*)\s\[infected by: (.*)\]"

  def scan(self, path):
    os.putenv("LANG", "C")
    return CAvScanner.scan(self, path)

#-----------------------------------------------------------------------
class CDrWebScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "DrWeb"
    self.speed = AV_SPEED_SLOW
    self.pattern = "\>{0,1}(.*) infected with (.*)"

#-----------------------------------------------------------------------
class CMcAfeeScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "McAfee"
    self.speed = AV_SPEED_ALL
    self.pattern = "(.*) \.\.\. Found the (.*) [a-z]+ \!\!"
    self.pattern2 = "(.*) \.\.\. Found [a-z]+ or variant (.*) \!\!"

  def scan(self, path):
    os.putenv("LANG", "C")
    ret = CAvScanner.scan(self, path)
    
    try:
      old_pattern = self.pattern
      self.pattern = self.pattern2
      ret |= CAvScanner.scan(self, path)
    finally:
      self.pattern = old_pattern

    return ret

#-----------------------------------------------------------------------
class CAvgScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "AVG"
    # Considered fast because it requires the daemon to be running.
    # This is why...
    self.speed = AV_SPEED_FAST
    self.pattern = "\>{0,1}(.*) \s+[a-z]+\s+[a-z]+\s+(.*)"

  def scan(self, path):
    cmd = self.build_cmd(path)
    f = NamedTemporaryFile(delete=False)
    f.close()
    fname = f.name

    try:
      cmd.append("-r%s" % fname)
      output = check_output(cmd)
    except CalledProcessError as e:
      output = e.output

    output = open(fname, "rb").read()
    os.unlink(fname)

    matches = re.findall(self.pattern, output, re.IGNORECASE|re.MULTILINE)
    for match in matches:
      if match[1] not in ["file"]:
        self.results[match[0]] = match[1]
    return len(self.results) > 0

#-----------------------------------------------------------------------
class CIkarusScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "Ikarus"
    self.speed = AV_SPEED_MEDIUM
    # Horrible, isn't it?
    self.pattern = "(.*) - Signature \d+ '(.*)' found"
  
  def scan(self, path):
    cmd = self.build_cmd(path)
    f = NamedTemporaryFile(delete=False)
    f.close()
    fname = f.name

    try:
      cmd.append("-logfile")
      cmd.append(fname)
      output = check_output(cmd)
    except CalledProcessError as e:
      output = e.output

    output = codecs.open(fname, "r", "utf-16").read()
    os.unlink(fname)

    matches = re.findall(self.pattern, output, re.IGNORECASE|re.MULTILINE)
    for match in matches:
      if match[1] not in ["file"]:
        self.results[match[0]] = match[1]
    return len(self.results) > 0

#-----------------------------------------------------------------------
class CFSecureScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "F-Secure"
    self.speed = AV_SPEED_FAST
    self.pattern = "(.*): Infected: (.*) \[[a-z]+\]"

#-----------------------------------------------------------------------
class CMultiAV:
  def __init__(self, cfg = "config.cfg"):
    self.engines = [CFProtScanner,  CComodoScanner,      CEsetScanner, 
                    CAviraScanner,  CBitDefenderScanner, CSophosScanner,
                    CAvastScanner,  CAvgScanner,         CDrWebScanner,
                    CMcAfeeScanner, CIkarusScanner,      CFSecureScanner]
    if has_clamd:
      self.engines.append(CClamScanner)

    self.processes = cpu_count()
    self.cfg = cfg
    self.read_config()

  def read_config(self):
    parser = ConfigParser.SafeConfigParser()
    parser.optionxform = str
    parser.read(self.cfg)
    self.parser = parser

  def multi_scan(self, path, max_speed):
    q = Queue()
    engines = list(self.engines)
    running = []
    results = {}

    while len(engines) > 0 or len(running) > 0:
      if len(engines) > 0 and len(running) < self.processes:
        av_engine = engines.pop()
        args = (av_engine, path, results, max_speed, q)
        p = Process(target=self.scan_one, args=args)
        p.start()
        running.append(p)

      i = 0
      for p in list(running):
        p.join(0.1)
        if not p.is_alive():
          del running[i]
          i -= 1
        else:
          i += 1

    results = {}
    while not q.empty():
      results.update(q.get())
    return results

  def scan(self, path, max_speed=AV_SPEED_ALL):
    if not os.path.exists(path):
      raise Exception("Path not found")

    if self.processes > 1:
      return self.multi_scan(path, max_speed)
    else:
      return self.single_scan(path, max_speed)

  def single_scan(self, path, max_speed=AV_SPEED_ALL):
    results = {}
    for av_engine in self.engines:
      results = self.scan_one(av_engine, path, results, max_speed)
    return results

  def scan_one(self, av_engine, path, results, max_speed, q=None):
    av = av_engine(self.parser)
    if av.is_disabled():
      return results

    if av.speed <= max_speed:
      av.scan(path)
      results[av.name] = av.results

    if q is not None:
      q.put(results)
    return results
  
  def scan_buffer(self, buf, max_speed=AV_SPEED_ALL):
    f = NamedTemporaryFile(delete=False)
    f.write(buf)
    f.close()
    fname = f.name

    try:
      ret = self.scan(fname)
    finally:
      os.unlink(fname)

    return ret

#-----------------------------------------------------------------------
def main(path):
  multi_av = CMultiAV()
  ret = multi_av.scan(path, AV_SPEED_ALL)
  
  import pprint
  pprint.pprint(ret)

#-----------------------------------------------------------------------
def usage():
  print "Usage:", sys.argv[0], "<path>"

if __name__ == "__main__":
  if len(sys.argv) == 1:
    usage()
  else:
    main(sys.argv[1])
