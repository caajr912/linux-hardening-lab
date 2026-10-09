# Incident log

## 1. nmcli rejected the static IP command
- **cause:** typed a multi-line command on one line, but kept the '\' cotinutation character.
- **fix:** retyped correctly

## 2. Second network adapter missing on Rocky
- **Symptop:** 'nmcli device' showed only network 'enp0s3'; actingting the host only profile failed.
- **cause:** changed adapter one to host only rather than enabling adapter 2. also removed NAT/ internet
- **fix:** full power down, reconfigured net adapters

## 3. SSH refused on Ubuntu control node
- **Symptom:** `Connection refused` on port 22.
- **Cause:** OpenSSH server not installed; first install attempt failed without `sudo`.
- **Fix:** `sudo apt install openssh-server` and `sudo systemctl enable --now ssh`.

## 4. SSH to Rocky hung at "Connecting" despite successful ping
- **Symptom:** `ssh -v` stalled at the TCP connect; ping to 192.168.56.10 succeeded.
- **Clue:** Ping replies had **TTL=128** (Windows default), not 64 (Linux), so the wrong host was answering.
- **Cause:** The Windows VirtualBox host-only adapter was configured as 192.168.56.10, the same IP as Rocky.
- **Fix:** Set the host adapter to 192.168.56.1, flushed the ARP cache on Ubuntu (`sudo ip neigh flush all`), and verified TTL=64 replies.
- **Lesson:** A successful ping proves only that *something* answered. Verify it's the right host.

## 5. SELinux task failed: missing Python library
- **Symptom:** `ModuleNotFoundError: No module named 'selinux'` on the AC-3 task.
- **Cause:** Rocky's minimal install lacks `python3-libselinux`, which Ansible's selinux module imports on the target.
- **Fix:** Added a prerequisites task installing `python3-libselinux` and `python3-firewall`, so the playbook works on a fresh host.

## 6. CM-7 task reported "changed" on every run
- **Symptom:** The Ctrl-Alt-Del mask task was never idempotent.
- **Cause:** `ctrl-alt-del.target` is an alias of `reboot.target`; the systemd module checked the alias target's state, which was never masked.
- **Fix:** Replaced the task with a forced symlink to `/dev/null` managed by the `file` module.

## 7. CM-7 control silently not applied
- **Symptom:** Ansible reported success, but manual verification showed `ctrl-alt-del.target -> reboot.target`, not `/dev/null`.
- **Cause:** Rocky ships an alias symlink at that path, which blocked the mask.
- **Fix:** `force: true` replaced the symlink; verified with `systemctl is-enabled` (masked).
- **Lesson:** Automation status is not control state. This is why the drift checker inspects the live system instead of trusting Ansible output.

## 8. Unplanned drift: clock unsynchronized (AU-8)
- **Symptom:** Drift checker reported 29/30; `time_synchronized` returned `no`.
- **Clue:** Evidence filenames showed Rocky's clock almost two days behind real time.
- **Cause:** The VM was resumed from a suspended state with a frozen clock; chrony only steps the clock during its first updates after boot, so it slewed slowly and reported unsynchronized.
- **Fix:** `chronyc makestep`; next run passed 30/30. Considered `makestep 1.0 -1` for VMs (tradeoff: sudden time jumps can confuse log ordering in production).
- **Evidence:** `evidence/drift-20261007T073055Z.json`

## 9. Git push rejected
- **Symptom:** `! [rejected] main -> main (fetch first)`.
- **Cause:** README was edited directly on GitHub; the VM's copy was behind.
- **Fix:** `git pull --rebase origin main`, then push. Edit in one place, or pull before changing anything.

## 10. Wazuh install: wrong host, failed dashboard, and a broken package state
- **Symptom 1:** Dashboard unreachable at 192.168.56.12; `wazuh-indexer` and `wazuh-dashboard` services did not exist on the Wazuh VM.
- **Cause 1:** The installer had been run in the `ubuntu-control` SSH session, not on `wazuh-server`. Uninstalled it there (`wazuh-install.sh -u`).
- **Symptom 2:** On the correct host, the install failed: `Wazuh dashboard installation failed`; the dashboard package's post-install script exited 1 with no message, and the installer rolled back.
- **Investigation:** Ruled out memory (no OOM-killer events in `journalctl -k`) and disk space. Found the root volume was only 24 GB of the 50 GB disk (Ubuntu's LVM default); extended it with `lvextend` + `resize2fs`. The specific cause of the dashboard script failure was not identified; a clean reinstall succeeded.
- **Symptom 3:** The reinstall failed: `/var/ossec/bin/wazuh-keystore: No such file or directory`.
- **Cause 3:** The rollback left `wazuh-manager` registered with dpkg. Deleting leftover directories manually, including `/var/ossec`, removed the manager's files while dpkg still recorded it as installed, so the installer skipped reinstalling it.
- **Symptom 4:** `dpkg --purge wazuh-manager` failed: the pre-removal script exited 127 (command not found) because the binaries it called were already deleted.
- **Fix:** Replaced the package's `prerm`/`postrm` scripts with no-ops, purged the package, removed the leftover `wazuh` user, reloaded systemd, and ran a clean install. Agent `rocky-target` enrolled and active.
- **Lessons:** Check the prompt before running anything; with three VMs, the host matters. Remove software through the package manager, never by deleting files, or the package database and the filesystem disagree. Rule out causes (memory, disk) with evidence before retrying.
