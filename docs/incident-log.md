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
