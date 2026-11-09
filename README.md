# mtu-diag

A Windows PowerShell script that checks for MTU / path-MTU "black holes": big packets that get silently dropped while small ones go through. Typical signs are websites that hang, uploads that stall, and TLS handshakes that time out, while ping still works.

It changes no settings. It writes a report to your Desktop.

## Run

Download `mtu-diag.ps1`, then in PowerShell:

```
powershell -ExecutionPolicy Bypass -File .\mtu-diag.ps1
```

- Run as administrator to also include the firewall (WFP) check.
- Add `-Capture` to record a packet capture during the TCP tests. This needs Wireshark (tshark) installed.
- Add `-Targets 1.1.1.1,8.8.8.8` to choose which hosts to test.

## What it checks

- Network adapter, gateway, DNS and interface MTU
- Largest packet that gets through to each target, using don't-fragment pings
- Whether too-big packets are reported back (normal) or silently dropped (a black hole)
- Which hop drops the big packets
- Packet loss at different sizes
- HTTPS requests with normal and large headers, plus an upload and a download test
- Traceroute, TCP/IP settings, and leftover VPN adapters or drivers

The last section gives a verdict and, when it helps, a suggested MTU workaround.

The report includes your public IP address, ISP, and Wi-Fi name and BSSID, so check it before you share it.
