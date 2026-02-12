 cargo build -r --features aws_lc_rs,mimalloc --no-default-features
 podman build -f Dockerfile.test -t quay.io/arloor/hyperway:test . --net host
 podman login quay.io -u arloor 
 podman push quay.io/arloor/hyperway:test
