# Actual native source integration fixture

`run_native_source.py` compiles the real `NativeEngine` and the patched dae
`startHotControl` HTTP server with its real `ControlPlane`. It verifies the source
base and every file in `source-manifest.json`, and records hashes for the compiled
source, generated BPF files, client, fixture, commands, host, and test output.

Use a disposable clone at the pinned base with the exported patch applied,
submodules initialized, and normal generated BPF objects present. Supply an
absolute local Go 1.26 executable; both test binaries must run on the same host.

```sh
python3 engine/dae/fixtures/run_native_source.py \
  --dae-source /path/to/patched-dae \
  --go /path/to/go1.26/bin/go \
  --receipt /tmp/egressdeck-native-source-receipt.json
```

The runner temporarily installs two helpers behind the `egressdeck_hot_harness`
build tag and removes them on completion. It uses a private `/tmp` directory and
a fresh external encryption key, with no installed-service mutation. The client
test is skipped by default during ordinary `go test`.

Assertions cover publication of one provider into two existing named groups,
stable candidate IDs despite duplicate display names, isolated manual selection,
selection revision conflicts, encrypted on-disk staging, an actual daemon process
restart, adapter reconstruction from disk, and encrypted daemon journal recovery.

The control-plane harness omits kernel attachment and traffic ingress. Its HTTP
authentication, native dialer construction, publication, selection and journals
are the actual source implementations. This fixture does not establish eBPF
packet-path, proxy handshake, OPNsense, or deployed-gateway qualification.
