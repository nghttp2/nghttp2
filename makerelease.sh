#!/bin/sh -e

VERSION=$1
PREV_VERSION=$2

git checkout refs/tags/release-$VERSION
git log --pretty=fuller --date=short refs/tags/release-$PREV_VERSION..HEAD > ChangeLog

./configure && \
    make dist-bzip2 && make dist-gzip && make dist-xz || echo "error"
make distclean
