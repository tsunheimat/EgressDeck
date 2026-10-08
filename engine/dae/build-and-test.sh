#!/usr/bin/env bash
set -euo pipefail

# Build only in an explicit empty scratch path, never in an existing checkout.
# This script does not start dae, attach BPF, enroll clients, or deploy an image.
if [[ $# != 1 || -e "$1" ]]; then
  echo "usage: build-and-test.sh /absolute/nonexistent/scratch-directory" >&2
  exit 2
fi
case "$1" in /*) ;; *) echo 'scratch directory must be absolute' >&2; exit 2;; esac
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
scratch_dir=$1
base_commit=e3fee8fbc68a65167af13b685ab0b958757e20ee
headers_commit=56937c66784879fe5e2ff89db5bc05aa061d594c
patch_file="$script_dir/patches/0001-native-hot-provider-runtime.patch"
patch_sha=6dc2bbcb8270adfaac62eda4e33abab98eef9009bfa89e9f107d672cb904aa38
actual_sha=$(sha256sum "$patch_file")
[[ ${actual_sha%% *} == "$patch_sha" ]] || { echo 'patch digest mismatch' >&2; exit 1; }
git clone https://github.com/daeuniverse/dae.git "$scratch_dir"
git -C "$scratch_dir" checkout --detach "$base_commit"
[[ $(git -C "$scratch_dir" rev-parse HEAD) == "$base_commit" ]]
git -C "$scratch_dir" apply --check "$patch_file"
git -C "$scratch_dir" apply "$patch_file"
git -C "$scratch_dir" submodule update --init --recursive
[[ $(git -C "$scratch_dir/control/kern/headers" rev-parse HEAD) == "$headers_commit" ]]
[[ $(git -C "$scratch_dir/trace/kern/headers" rev-parse HEAD) == "$headers_commit" ]]
cd -- "$scratch_dir"
env BPF_CLANG="${BPF_CLANG:-clang}" BPF_STRIP_FLAG=-no-strip \
  BPF_CFLAGS='-O2 -Wall -Werror -DMAX_MATCH_SET_LEN=1024' BPF_TARGET=bpfel \
  go generate ./control/control.go
go test -race ./component/outbound ./control ./cmd -run '^TestHot' -count=1
go test -race -tags dae_stub_ebpf ./component/outbound ./control ./cmd -count=1
go vet ./component/outbound ./control ./cmd
go build -trimpath -o dae-r05 .
sha256sum dae-r05 control/bpf_bpfel.go control/bpf_bpfel.o
