#!/bin/bash -xe

GIT_VERSION=$(git describe --tags --long)
VERSION=$(echo $GIT_VERSION | perl -p -e 's/v([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)-(g[0-9a-f]+)/\1/')
RELEASE=$(echo $GIT_VERSION | perl -p -e 's/v([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)-(g[0-9a-f]+)/\2\.\3/')
perl -p -e "s/__VERSION__/${VERSION}/; s/__RELEASE__/${RELEASE}%{?dist}/;" tc-portal-s3-push.spec.in > tc-portal-s3-push.spec

rpmbuild --define "_topdir ${PWD}" \
         --define "_builddir ${PWD}" \
         --define "_sourcedir ${PWD}" \
         --define "_specdir ${PWD}" \
         --define "_srcrpmdir RPMS" \
         -bb tc-portal-s3-push.spec
