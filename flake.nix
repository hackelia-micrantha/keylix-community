{
  description = "Keylix reproducible development and CI toolchain";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system:
          f (import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          }));
      stableRustFor = pkgs: pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      verifierFor = pkgs:
        let
          stableRust = stableRustFor pkgs;
          rustPlatform = pkgs.makeRustPlatform {
            cargo = stableRust;
            rustc = stableRust;
          };
        in
        rustPlatform.buildRustPackage {
          pname = "keylix-verifier";
          version = "0.1.0";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "-p" "keylix-verifier" ];
          cargoTestFlags = [ "-p" "keylix-verifier" ];
          dontUseCmakeConfigure = true;
          dontUseNinjaBuild = true;
          dontUseNinjaCheck = true;
          dontUseNinjaInstall = true;
          nativeBuildInputs = with pkgs; [
            cmake
            ninja
            perl
            pkg-config
          ];
          preBuild = ''
            export CARGO_HOME="$TMPDIR"
          '';
          postInstall = ''
            install -Dm0444 docs/man/keylix-verifier.1 \
              "$out/share/man/man1/keylix-verifier.1"
            install -Dm0444 docs/VERIFIER_PROTOCOL.md \
              "$out/share/doc/keylix-verifier/VERIFIER_PROTOCOL.md"
          '';
          meta = {
            description = "Bounded sender-binding verifier host for Keylix";
            mainProgram = "keylix-verifier";
            license = pkgs.lib.licenses.asl20;
            platforms = pkgs.lib.platforms.unix;
          };
        };
    in {
      packages = forAllSystems (pkgs:
        let verifier = verifierFor pkgs;
        in {
          keylix-verifier = verifier;
          default = verifier;
        });

      apps = forAllSystems (pkgs: {
        keylix-verifier = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.keylix-verifier}/bin/keylix-verifier";
        };
        default = self.apps.${pkgs.stdenv.hostPlatform.system}.keylix-verifier;
      });

      devShells = forAllSystems (pkgs:
        let
          stableRust = stableRustFor pkgs;
          nightlyRust = pkgs.rust-bin.selectLatestNightlyWith (toolchain:
            toolchain.minimal.override {
              extensions = [ "rust-src" ];
            });
          commonPackages = with pkgs; [
            bash
            cacert
            cmake
            coreutils
            curl
            findutils
            gh
            git
            gnutar
            gzip
            ninja
            perl
            pkg-config
            python3
          ];
        in {
          default = pkgs.mkShell {
            packages = [ stableRust ] ++ commonPackages;
            RUST_BACKTRACE = "1";
          };

          fuzz = pkgs.mkShell {
            packages = [ nightlyRust ] ++ commonPackages;
            RUST_BACKTRACE = "1";
          };
        });

      checks = forAllSystems (pkgs:
        let
          stableRust = stableRustFor pkgs;
          verifier = verifierFor pkgs;
        in {
          toolchain = pkgs.runCommand "keylix-toolchain-check" {
            nativeBuildInputs = [ stableRust pkgs.python3 ];
          } ''
            rustc --version | grep -F '1.88.0'
            cargo --version
            cargo clippy --version
            cargo fmt --version
            python3 --version
            touch $out
          '';

          verifier-package = pkgs.runCommand "keylix-verifier-package-check" {
            nativeBuildInputs =
              [ verifier pkgs.python3 pkgs.coreutils ]
              ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.acl ];
          } ''
            set -euo pipefail

            keylix-verifier --help | grep -F -- '--replay-dir'
            keylix-verifier --help | grep -F -- '--socket-group-gid'
            keylix-verifier --version | grep -F 'keylix-verifier 0.1.0'
            test -f ${verifier}/share/man/man1/keylix-verifier.1.gz
            test -f ${verifier}/share/doc/keylix-verifier/VERIFIER_PROTOCOL.md

            smoke="$TMPDIR/keylix-verifier-package-smoke"
            install -d -m 0700 "$smoke" "$smoke/run" "$smoke/replay"
            cat >"$smoke/peers.json" <<'EOF'
            {"schema_version":1,"peers":[{"id":"package-smoke","secret_base64url":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}
            EOF
            chmod 0600 "$smoke/peers.json"

            keylix-verifier \
              --socket "$smoke/run/verifier.sock" \
              --peer-credentials "$smoke/peers.json" \
              --replay-dir "$smoke/replay" \
              >"$smoke/stdout.log" 2>"$smoke/stderr.log" &
            verifier_pid=$!
            cleanup() {
              kill "$verifier_pid" 2>/dev/null || true
              wait "$verifier_pid" 2>/dev/null || true
            }
            trap cleanup EXIT

            python3 - "$smoke/run/verifier.sock" <<'PY'
            import base64
            import hashlib
            import hmac
            import json
            import socket
            import sys
            import time

            path = sys.argv[1]
            peer_id = "package-smoke"
            secret = bytes(32)
            correlation = bytes(range(32))
            payload = b"{}"

            def b64(value: bytes) -> str:
                return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

            request_mac = hmac.new(
                secret,
                b"keylix-verifier-request-v1\0"
                + peer_id.encode("ascii")
                + b"\0"
                + correlation
                + payload,
                hashlib.sha256,
            ).digest()
            envelope = {
                "version": 1,
                "peer_id": peer_id,
                "correlation_base64url": b64(correlation),
                "payload_base64url": b64(payload),
                "mac_base64url": b64(request_mac),
            }

            deadline = time.monotonic() + 5.0
            while True:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    client.connect(path)
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    client.close()
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.02)

            with client:
                client.sendall(
                    json.dumps(envelope, separators=(",", ":")).encode("ascii") + b"\n"
                )
                response_line = client.makefile("rb").readline(65537)
            if not response_line.endswith(b"\n"):
                raise AssertionError("verifier response was not newline terminated")

            outer = json.loads(response_line)
            if outer["version"] != 1 or outer["peer_id"] != peer_id:
                raise AssertionError("unexpected verifier response envelope")
            if outer["correlation_base64url"] != b64(correlation):
                raise AssertionError("verifier response correlation mismatch")

            response_payload = base64.urlsafe_b64decode(
                outer["payload_base64url"] + "=="
            )
            response_mac = base64.urlsafe_b64decode(outer["mac_base64url"] + "==")
            expected_mac = hmac.new(
                secret,
                b"keylix-verifier-response-v1\0"
                + peer_id.encode("ascii")
                + b"\0"
                + correlation
                + response_payload,
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(response_mac, expected_mac):
                raise AssertionError("verifier response MAC mismatch")

            result = json.loads(response_payload)
            expected = {
                "status": "rejected",
                "version": 1,
                "failure": "malformed_request",
            }
            if result != expected:
                raise AssertionError(f"unexpected verifier contract response: {result!r}")
            PY

            cleanup
            trap - EXIT

            # This smoke runs with the current build identity only. It is
            # never evidence of the separate-UID consumer acceptance gate.
            sgid_smoke_status=not_linux
            if [[ "$(uname -s)" == "Linux" ]]; then
              create_setgid_socket_dir() {
                local path=$1
                # Model external supervisor provisioning. The verifier process
                # validates this state but never changes SGID itself.
                if ! install -d -m 2710 "$path"; then
                  return 77
                fi
                local mode
                mode="$(stat -c '%a' "$path")"
                if [[ "$mode" != "2710" ]]; then
                  rmdir "$path" 2>/dev/null || true
                  return 77
                fi
              }

              group_smoke="$TMPDIR/keylix-verifier-group-socket-smoke"
              install -d -m 0700 "$group_smoke" "$group_smoke/replay"
              if create_setgid_socket_dir "$group_smoke/run"; then
                cp "$smoke/peers.json" "$group_smoke/peers.json"
                chmod 0600 "$group_smoke/peers.json"
                transport_gid="$(stat -c '%g' "$group_smoke/run")"
                test "$transport_gid" -gt 0

                (
                  umask 0117
                  exec keylix-verifier \
                  --socket "$group_smoke/run/verifier.sock" \
                  --socket-group-gid "$transport_gid" \
                  --peer-credentials "$group_smoke/peers.json" \
                  --replay-dir "$group_smoke/replay" \
                  >"$group_smoke/stdout.log" 2>"$group_smoke/stderr.log"
                ) &
                group_pid=$!
                cleanup_group() {
                kill "$group_pid" 2>/dev/null || true
                wait "$group_pid" 2>/dev/null || true
              }
                trap cleanup_group EXIT

                socket_path="$group_smoke/run/verifier.sock"
                for _ in $(seq 1 250); do
                  [[ -S "$socket_path" ]] && break
                  sleep 0.02
                done
                test -S "$socket_path"
                test "$(stat -c '%a' "$socket_path")" = "660"
                test "$(stat -c '%g' "$socket_path")" = "$transport_gid"
                test "$(stat -c '%a' "$group_smoke/run")" = "2710"
                test "$(stat -c '%g' "$group_smoke/run")" = "$transport_gid"
                python3 -c 'import socket, sys; s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.close()' "$socket_path"

              if (
                umask 0117
                exec keylix-verifier \
                  --socket "$group_smoke/run/verifier.sock" \
                  --socket-group-gid "$transport_gid" \
                  --peer-credentials "$group_smoke/peers.json" \
                  --replay-dir "$group_smoke/replay" \
                  >"$group_smoke/contender-stdout.log" 2>"$group_smoke/contender-stderr.log"
              ); then
                echo "second verifier unexpectedly acquired live socket directory" >&2
                exit 1
              fi
              test "$(stat -c '%a' "$group_smoke/run")" = "2710"

              cleanup_group
              trap - EXIT

              acl_smoke="$TMPDIR/keylix-verifier-acl-negative"
              install -d -m 0700 "$acl_smoke" "$acl_smoke/replay"
              create_setgid_socket_dir "$acl_smoke/run"
              cp "$smoke/peers.json" "$acl_smoke/peers.json"
              chmod 0600 "$acl_smoke/peers.json"
              acl_gid="$(stat -c '%g' "$acl_smoke/run")"
              setfacl -m u:12345:x "$acl_smoke/run"
              if (
                umask 0117
                exec keylix-verifier \
                  --socket "$acl_smoke/run/verifier.sock" \
                  --socket-group-gid "$acl_gid" \
                  --peer-credentials "$acl_smoke/peers.json" \
                  --replay-dir "$acl_smoke/replay" \
                  >"$acl_smoke/stdout.log" 2>"$acl_smoke/stderr.log"
              ); then
                echo "group socket profile accepted a POSIX ACL" >&2
                exit 1
              fi
              test ! -S "$acl_smoke/run/verifier.sock"

              umask_smoke="$TMPDIR/keylix-verifier-umask-negative"
              install -d -m 0700 "$umask_smoke" "$umask_smoke/replay"
              create_setgid_socket_dir "$umask_smoke/run"
              cp "$smoke/peers.json" "$umask_smoke/peers.json"
              chmod 0600 "$umask_smoke/peers.json"
              umask_gid="$(stat -c '%g' "$umask_smoke/run")"
              if (
                umask 0022
                exec keylix-verifier \
                  --socket "$umask_smoke/run/verifier.sock" \
                  --socket-group-gid "$umask_gid" \
                  --peer-credentials "$umask_smoke/peers.json" \
                  --replay-dir "$umask_smoke/replay" \
                  >"$umask_smoke/stdout.log" 2>"$umask_smoke/stderr.log"
              ); then
                echo "group socket profile accepted unsafe process umask" >&2
                exit 1
              fi
              test ! -S "$umask_smoke/run/verifier.sock"
              sgid_smoke_status=executed_same_identity
              else
                fixture_status=$?
                if [[ "$fixture_status" -ne 77 ]]; then
                  exit "$fixture_status"
                fi
                echo "skipping privileged SGID transport smoke: sandbox forbids supervisor fixture"
                sgid_smoke_status=skipped_fixture
              fi
            fi

            # Report execution branch, not a simulated security pass.
            printf 'schema_version=1\nsgid_smoke=%s\ncross_uid_smoke=not_run\n' \
              "$sgid_smoke_status" > "$out"
          '';
        } // pkgs.lib.optionalAttrs (pkgs.stdenv.hostPlatform.system == "x86_64-linux") {
          # Qualified in a disposable NixOS VM, where two real service UIDs and
          # the explicit transport group must work. No sandbox-skip path.
          verifier-cross-uid-vm = import ./tests/verifier-cross-uid-vm.nix {
            inherit pkgs verifier;
          };
        });

      formatter = forAllSystems (pkgs: pkgs.alejandra);
    };
}
