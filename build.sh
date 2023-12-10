#!/bin/sh

cmd=${1:-build}

if [ "x$cmd" == "xbuild" ]; then
  REV=$(git describe --long --tags --match='v*' --dirty 2>/dev/null || git rev-list -n1 HEAD)
  NOW=$(date +'%Y-%m-%d_%T')
  GOV=$(go version)
  go mod tidy
  go mod vendor
 
  go build -ldflags "${LDFLAGS} -X main.version=$REV -X main.buildTime=$NOW -X 'main.goVersion=${GOV}'"  -o ./bin/lclcrtmngr ./cmd
  go build -ldflags "${LDFLAGS} -X main.version=$REV -X main.buildTime=$NOW -X 'main.goVersion=${GOV}'"  -o ./bin/examplesrv ./example
elif [ "x$cmd" == "xtest" ]; then
  shift
  ./test.sh $@
else
  echo unknown command
fi
