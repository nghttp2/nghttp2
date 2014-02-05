#!/bin/sh -e

TAG=$1
PREV_TAG=$2

git checkout refs/tags/$TAG
git log --pretty=fuller --date=short refs/tags/$PREV_TAG..HEAD > ChangeLog

./configure && \
    make dist-bzip2 && make dist-gzip && make dist-xz || echo "error"
make distclean
