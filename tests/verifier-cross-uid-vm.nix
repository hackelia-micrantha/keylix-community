{ pkgs, verifier }:

let
  socket = "/run/keylix-qualify/socket/verifier.sock";
  clientPython = pkgs.python3.withPackages (ps: [ ps.cryptography ]);
  clients = pkgs.writeText "keylix-cross-uid-client.py" (builtins.readFile ./fixtures/keylix-cross-uid-client.py);

in
pkgs.testers.runNixOSTest {
  name = "keylix-verifier-cross-uid";

  # Disposable VM under TCG; ordinary self-hosted runners need no /dev/kvm
  # and no elevated host-control capability.
  requiredFeatures.kvm = false;

  nodes.machine = { ... }: {
    system.stateVersion = "26.05";
    networking.hostName = "keylix-verifier-qualification";
    virtualisation.memorySize = 1024;

    users.groups."keylix-verifier-fixture".gid = 27041;
    users.groups."keylix-transport-fixture".gid = 27042;
    users.groups."keylix-admitted-fixture".gid = 27043;
    users.groups."keylix-denied-fixture".gid = 27044;

    users.users."keylix-verifier-fixture" = {
      isSystemUser = true;
      uid = 27041;
      group = "keylix-verifier-fixture";
      extraGroups = [ "keylix-transport-fixture" ];
    };
    users.users."keylix-admitted-fixture" = {
      isSystemUser = true;
      uid = 27043;
      group = "keylix-admitted-fixture";
      extraGroups = [ "keylix-transport-fixture" ];
    };
    users.users."keylix-denied-fixture" = {
      isSystemUser = true;
      uid = 27044;
      group = "keylix-denied-fixture";
    };

    environment.systemPackages = [ pkgs.coreutils pkgs.util-linux pkgs.python3 pkgs.acl ];
    systemd.services.keylix-verifier-qualification = {
      description = "Disposable cross-UID Keylix verifier qualification fixture";
      serviceConfig = {
        Type = "simple";
        User = "keylix-verifier-fixture";
        Group = "keylix-verifier-fixture";
        SupplementaryGroups = "keylix-transport-fixture";
        UMask = "0117";
        NoNewPrivileges = true;
        PrivateNetwork = true;
        RestrictAddressFamilies = "AF_UNIX";
        ProtectSystem = "strict";
        ReadWritePaths = [ "/run/keylix-qualify" ];
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        ExecStart = "${verifier}/bin/keylix-verifier --socket ${socket} --socket-group-gid 27042 --peer-credentials /run/keylix-qualify/private/peers.json --replay-dir /run/keylix-qualify/private/replay";
      };
    };

    # A second independent verifier must fail while the first owns the lock.
    systemd.services.keylix-verifier-contender = {
      description = "Disposable Keylix verifier live contender";
      serviceConfig = {
        Type = "exec";
        User = "keylix-verifier-fixture";
        Group = "keylix-verifier-fixture";
        SupplementaryGroups = "keylix-transport-fixture";
        UMask = "0117";
        NoNewPrivileges = true;
        PrivateNetwork = true;
        RestrictAddressFamilies = "AF_UNIX";
        ExecStart = "${verifier}/bin/keylix-verifier --socket ${socket} --socket-group-gid 27042 --peer-credentials /run/keylix-qualify/private/peers.json --replay-dir /run/keylix-qualify/private/replay";
      };
    };
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    machine.succeed("install -d -o root -g root -m 0755 /run/keylix-qualify")
    machine.succeed("install -d -o keylix-verifier-fixture -g keylix-verifier-fixture -m 0700 /run/keylix-qualify/private")
    machine.succeed("install -d -o keylix-verifier-fixture -g keylix-verifier-fixture -m 0700 /run/keylix-qualify/private/replay")
    machine.succeed("install -d -o keylix-verifier-fixture -g keylix-transport-fixture -m 2710 /run/keylix-qualify/socket")
    machine.succeed("test \"$(stat -c %a /run/keylix-qualify/socket)\" = 2710")
    machine.succeed("test \"$(stat -c %g /run/keylix-qualify/socket)\" = 27042")
    machine.succeed("printf '%s\\n' '{\"schema_version\":1,\"peers\":[{\"id\":\"vm-fixture\",\"secret_base64url\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}]}' > /run/keylix-qualify/private/peers.json")
    machine.succeed("chown keylix-verifier-fixture:keylix-verifier-fixture /run/keylix-qualify/private/peers.json && chmod 0600 /run/keylix-qualify/private/peers.json")

    machine.succeed("systemctl start keylix-verifier-qualification.service")
    machine.wait_for_unit("keylix-verifier-qualification.service")
    machine.wait_until_succeeds("test -S ${socket}")
    machine.succeed("test \"$(stat -c %a ${socket})\" = 660")
    machine.succeed("test \"$(stat -c %g ${socket})\" = 27042")
    machine.succeed("test \"$(stat -c %u ${socket})\" = 27041")
    machine.succeed("test \"$(stat -c %a /run/keylix-qualify/private)\" = 700")
    machine.succeed("test \"$(stat -c %a /run/keylix-qualify/private/replay)\" = 700")

    # Actual different Linux UIDs, not mock identity labels or same-UID probes.
    machine.succeed("test \"$(id -u keylix-verifier-fixture)\" != \"$(id -u keylix-admitted-fixture)\"")
    machine.succeed("test \"$(id -u keylix-verifier-fixture)\" != \"$(id -u keylix-denied-fixture)\"")
    machine.succeed("runuser -u keylix-admitted-fixture -- ${clientPython}/bin/python3 ${clients} ${socket} valid_and_replay")
    machine.succeed("runuser -u keylix-admitted-fixture -- ${clientPython}/bin/python3 ${clients} ${socket} badmac")
    machine.succeed("runuser -u keylix-denied-fixture -- ${clientPython}/bin/python3 ${clients} ${socket} denied")
    machine.fail("runuser -u keylix-admitted-fixture -- test -r /run/keylix-qualify/private/peers.json")
    machine.fail("runuser -u keylix-admitted-fixture -- test -r /run/keylix-qualify/private/replay")
    machine.fail("runuser -u keylix-denied-fixture -- test -r /run/keylix-qualify/private/peers.json")
    machine.succeed("systemctl is-active --quiet keylix-verifier-qualification.service")
    machine.succeed("stat -c '%i:%u:%g:%a' ${socket} > /run/keylix-qualify/socket-before-contender.txt")

    # The second verifier must not replace or unlink the first live socket.
    machine.succeed("systemctl start keylix-verifier-contender.service || true")
    machine.wait_until_succeeds("systemctl is-failed --quiet keylix-verifier-contender.service")
    machine.succeed("systemctl is-active --quiet keylix-verifier-qualification.service")
    machine.succeed("test -S ${socket}")
    machine.succeed("test \"$(stat -c '%i:%u:%g:%a' ${socket})\" = \"$(cat /run/keylix-qualify/socket-before-contender.txt)\"")
    machine.succeed("runuser -u keylix-admitted-fixture -- ${clientPython}/bin/python3 ${clients} ${socket} malformed")
    machine.succeed("systemctl stop keylix-verifier-qualification.service")
    machine.wait_until_fails("systemctl is-active --quiet keylix-verifier-qualification.service")

    # The stopped service must leave a real, owner-matching socket pathname
    # without a live listener. A refused connect proves this is a stale socket,
    # not an arbitrary missing path or a still-live verifier.
    machine.succeed("test -S ${socket}")
    machine.succeed("test \"$(stat -c '%u:%g:%a' ${socket})\" = '27041:27042:660'")
    machine.succeed("runuser -u keylix-admitted-fixture -- ${clientPython}/bin/python3 -c 'import errno,socket,sys; client=socket.socket(socket.AF_UNIX); sys.exit(client.connect_ex(sys.argv[1]) != errno.ECONNREFUSED)' ${socket}")

    # Do not unlink it here: the packaged verifier must perform its own
    # ConnectionRefused stale-socket recovery before binding the new listener.
    machine.succeed("systemctl start keylix-verifier-qualification.service")
    machine.wait_for_unit("keylix-verifier-qualification.service")
    machine.wait_until_succeeds("test -S ${socket}")
    machine.succeed("runuser -u keylix-admitted-fixture -- ${clientPython}/bin/python3 ${clients} ${socket} malformed")
    machine.succeed("systemctl is-active --quiet keylix-verifier-qualification.service")
    machine.succeed("systemctl stop keylix-verifier-qualification.service")
    # Other negatives begin from an absent socket, after the recovery is proven.
    machine.succeed("rm -f ${socket}")
    machine.succeed("test ! -e ${socket}")

    # An explicit POSIX ACL must prevent verifier admission without a socket.
    machine.succeed("setfacl -m u:keylix-denied-fixture:--x,m::--x /run/keylix-qualify/socket")
    machine.succeed("test \"$(stat -c %a /run/keylix-qualify/socket)\" = 2710")
    machine.succeed("systemctl start keylix-verifier-qualification.service || true")
    machine.wait_until_succeeds("systemctl is-failed --quiet keylix-verifier-qualification.service")
    machine.succeed("test ! -S ${socket}")
    machine.succeed("setfacl -b /run/keylix-qualify/socket")
    machine.succeed("chmod 2710 /run/keylix-qualify/socket")
    machine.succeed("systemctl reset-failed keylix-verifier-qualification.service")
    machine.succeed("test \"$(stat -c %a /run/keylix-qualify/socket)\" = 2710")
    machine.succeed("systemctl start keylix-verifier-qualification.service")
    machine.wait_for_unit("keylix-verifier-qualification.service")
    machine.wait_until_succeeds("test -S ${socket}")
    machine.succeed("runuser -u keylix-admitted-fixture -- ${clientPython}/bin/python3 ${clients} ${socket} malformed")
    machine.succeed("systemctl stop keylix-verifier-qualification.service")
    # Normal signal termination can leave a stale pathname, but no live socket.
    # Exercise normal verifier stale-socket recovery separately, and remove the
    # test-only pathname after service shutdown before negative startup checks.
    machine.succeed("rm -f ${socket}")
    machine.succeed("test ! -e ${socket}")

    # A wrong umask must fail before the group-accessible socket is bound.
    machine.succeed("install -d -m 0755 /run/systemd/system/keylix-verifier-qualification.service.d")
    machine.succeed("printf '[Service]\\nUMask=0022\\n' > /run/systemd/system/keylix-verifier-qualification.service.d/override.conf")
    machine.succeed("systemctl daemon-reload")
    machine.succeed("systemctl start keylix-verifier-qualification.service || true")
    machine.wait_until_succeeds("systemctl is-failed --quiet keylix-verifier-qualification.service")
    machine.succeed("test ! -S ${socket}")
    machine.succeed("rm /run/systemd/system/keylix-verifier-qualification.service.d/override.conf")
    machine.succeed("systemctl daemon-reload")
    machine.succeed("systemctl reset-failed keylix-verifier-qualification.service")
    machine.succeed("systemctl start keylix-verifier-qualification.service")
    machine.wait_for_unit("keylix-verifier-qualification.service")
    machine.wait_until_succeeds("test -S ${socket}")
    machine.succeed("runuser -u keylix-admitted-fixture -- ${clientPython}/bin/python3 ${clients} ${socket} malformed")
    machine.succeed("systemctl is-active --quiet keylix-verifier-qualification.service")
    machine.succeed("systemctl stop keylix-verifier-qualification.service")
    # Normal signal termination can leave a stale pathname, but no live socket.
    # Exercise normal verifier stale-socket recovery separately, and remove the
    # test-only pathname after service shutdown before negative startup checks.
    machine.succeed("rm -f ${socket}")
    machine.succeed("test ! -e ${socket}")

    print("cross_uid_transport=qualified; sender_binding=verified; replay=denied; wrong_group=denied; bad_mac=denied; secrets=private; live_contender=denied; acl_umask=denied; recovery=verified")
  '';
}
