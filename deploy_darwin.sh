#!/bin/bash

#!/bin/sh

make distclean

/opt/checker-276/scan-build ./configure --enable-perfwithmain
/opt/checker-276/scan-build make



