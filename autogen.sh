#!/bin/sh
#

set -ex
cd `dirname "$0"`
if [ "`uname`" = "Darwin" ]; then
    glibtoolize --copy
else
    libtoolize --copy
fi
aclocal -I m4
autoheader
autoconf
automake --foreign --add-missing --copy
