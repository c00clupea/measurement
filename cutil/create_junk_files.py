#!/usr/bin/env python

import sys
import tempfile
from datetime import datetime
from os import urandom
from os import path
from os import access
from os import W_OK


def create_file(filename,filesize):
    record_block = 1024
    rand_bytes = urandom(record_block)
    with open(filename,'w+b') as rand_file:
        size_count = 1
        while size_count <= filesize:
            rand_file.write(rand_bytes)
            size_count += 1
        rand_file.flush
    
    
def create_files():
    overall = 0
    for a in range(1,1001,1):
        fi = 'seq-'+str(a)+'-chunk'
        print(fi)
        overall += a
#        create_file(fi,a)
    for a in range(2,101,1):
        siz = a * 1000
        fi = 'seq-'+str(siz)+'-chunk'
        print(fi)
        overall += siz
#        create_file(fi,siz)
    for a in range(2,11,1):
        siz = a * 1000 * 100
        fi = 'seq-'+str(siz)+'-chunk'
        print(fi)
        overall += siz
#        create_file(fi,siz)

    megB = float(overall) / float(1024)
    gigB = float(megB) / float(1024)
    print('Full size: '+str(overall)+"kB or "+str(megB)+" MB or "+str(gigB)+" GB")
#        create_file(fi,siz)

if __name__ == "__main__":
    create_files()
    
    
