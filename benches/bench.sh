#!/bin/bash
set -e

cd "$(dirname "$0")/.."

echo "Building Docker images..."
docker build -f benches/debian_bench.Dockerfile -t makiatto-debian-bench .
docker build -f benches/axum_control.Dockerfile -t axum-control-bench .

echo "Creating test files..."
mkdir -p /tmp/bench-files
dd if=/dev/zero of=/tmp/bench-files/1kb.bin bs=1024 count=1 2>/dev/null
dd if=/dev/zero of=/tmp/bench-files/100kb.bin bs=1024 count=100 2>/dev/null
dd if=/dev/zero of=/tmp/bench-files/1mb.bin bs=1024 count=1024 2>/dev/null
dd if=/dev/zero of=/tmp/bench-files/10mb.bin bs=1024 count=10240 2>/dev/null
echo "<html><body><h1>Hello World</h1></body></html>" > /tmp/bench-files/index.html

echo "Starting Docker containers..."

docker run -d --replace --name makiatto-bench \
    -v ./benches/makiatto.bench.toml:/etc/makiatto.toml:ro \
    -v /tmp/bench-files:/var/makiatto/sites/localhost:ro \
    -p 8080:80 \
    makiatto-debian-bench

docker run -d --replace --name nginx-bench \
    -v /tmp/bench-files:/usr/share/nginx/html:ro \
    -p 8081:80 \
    nginx:alpine

docker run -d --replace --name caddy-bench \
    -v /tmp/bench-files:/usr/share/caddy:ro \
    -p 8082:80 \
    caddy:alpine \
    caddy file-server --root /usr/share/caddy --listen :80

docker run -d --replace --name apache-bench \
    -v /tmp/bench-files:/usr/local/apache2/htdocs:ro \
    -p 8083:80 \
    httpd:alpine

docker run -d --replace --name axum-control-bench \
    -v /tmp/bench-files:/var/axum-control/files:ro \
    -p 8084:80 \
    axum-control-bench

echo "Waiting for containers to start..."
sleep 5

echo "Running benchmarks..."

echo "=== Different Concurrency Levels ==="
for server in "makiatto:8080" "axum-control:8084" "nginx:8081" "caddy:8082" "apache:8083"; do
    name="${server%%:*}"
    port="${server##*:}"
    echo "Testing $name with varying concurrency..."

    for c in 50 200 1000; do
        echo "- $c concurrent connections:"
        oha -z 10s -c "$c" -H "Host: localhost" --disable-compression "http://localhost:$port/1mb.bin" | grep -E "(Requests/sec|Latency)"
    done
    echo
done

echo "=== Different File Sizes ==="
files=("index.html" "1kb.bin" "100kb.bin" "1mb.bin" "10mb.bin")

for file in "${files[@]}"; do
    echo "Testing file: $file"
    for server in "makiatto:8080" "axum-control:8084" "nginx:8081" "caddy:8082" "apache:8083"; do
        name="${server%%:*}"
        port="${server##*:}"
        echo "- $name:"
        oha -z 10s -c 100 -H "Host: localhost" --disable-compression "http://localhost:$port/$file" | grep -E "(Requests/sec|Total data)"
    done
    echo
done

docker rm -f makiatto-bench nginx-bench caddy-bench apache-bench axum-control-bench
