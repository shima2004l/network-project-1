#!/bin/bash
# Small helper for macOS/Linux.  Usage:
#   ./run.sh upstream        start the simulator
#   ./run.sh upstream 30     simulator with TTL = 30
#   ./run.sh proxy           start the DNS proxy
set -e
cd "$(dirname "$0")"

if javac -version >/dev/null 2>&1 && java -version >/dev/null 2>&1; then
    JAVAC=javac
    JAVA=java
elif [ -x /opt/homebrew/opt/openjdk@17/bin/javac ]; then
    JAVAC=/opt/homebrew/opt/openjdk@17/bin/javac
    JAVA=/opt/homebrew/opt/openjdk@17/bin/java
else
    echo "Java not found. Please install JDK 17 or newer."
    exit 1
fi

"$JAVAC" DnsProxy.java RealDns.java UpstreamMock.java

case "$1" in
    upstream)
        if [ -n "$2" ]; then
            "$JAVA" UpstreamMock "$2"
        else
            "$JAVA" UpstreamMock
        fi
        ;;
    proxy)
        "$JAVA" DnsProxy
        ;;
    *)
        echo "Usage: ./run.sh upstream [ttl] | ./run.sh proxy"
        ;;
esac
