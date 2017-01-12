#!/usr/bin/env python

import os, sys
os.chdir('../')
sys.path.append('../')

from multiav.webapi import app

if __name__ == "__main__":
    app.run()
