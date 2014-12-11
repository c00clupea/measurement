#!/usr/bin/env python

import sys
import tempfile
from datetime import datetime
from os import urandom
from os import path
from os import access
from os import W_OK
from os import remove
import subprocess

def create_file(filename,filesize):
    record_block = 1024
    rand_bytes = urandom(record_block)
    with open(filename,'w+b') as rand_file:
        size_count = 1
        while size_count <= filesize:
            rand_file.write(rand_bytes)
            size_count += 1
        rand_file.flush
    with open('measure_tar_gnu.log','a') as logout:
        for i in range(1,101,1):
            test_command(filename,filesize,i,logout)

    if filesize%10 == 0:
        print 'made size ',str(filesize)
    remove(filename)

def test_command(filename,filesize,runner,logout):
#    command = ['perf', 'stat', '-x,', '-e', 'task-clock','--log-fd','2', 'cat', filename, '>','testmich']
    command = "perf stat -x, -e task-clock --log-fd 2 tar -cf testmich.tar "+filename
#    print 'command:',command
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
#    print result
    output,err = process.communicate()
    commout = err.rstrip()
#    print'out:',output,'err:',err
    logger = commout+","+str(filesize)+","+str(runner)+"\n"
    logout.write(logger)
#    sys.exit(0)
    remove('testmich.tar')
  #  remove(filename)



def create_files():
    overall = 0
    for a in range(1,1001,1):
        fi = 'seq-'+str(a)+'-chunk'
#        print(fi)
        overall += a
        create_file(fi,a)
    for a in range(2,101,1):
        siz = a * 1000
        fi = 'seq-'+str(siz)+'-chunk'
#        print(fi)
        overall += siz
        create_file(fi,siz)
    for a in range(2,11,1):
        siz = a * 1000 * 100
        fi = 'seq-'+str(siz)+'-chunk'
 #       print(fi)
        overall += siz
        create_file(fi,siz)

    megB = float(overall) / float(1024)
    gigB = float(megB) / float(1024)
    print('Full size: '+str(overall)+"kB or "+str(megB)+" MB or "+str(gigB)+" GB")
#        create_file(fi,siz)

if __name__ == "__main__":
    create_files()
