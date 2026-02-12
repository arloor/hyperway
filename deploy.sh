cargo build -r --features aws_lc_rs,mimalloc --no-default-features
podman build . -f Dockerfile.dyn -t quay.io/arloor/hyperway:latest --network host --build-arg TARGET_PATH=
podman login quay.io
podman push quay.io/arloor/hyperway:latest

kubectl rollout restart deploy/hyperway
kubectl rollout status deploy/hyperway
