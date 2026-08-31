# Commands

The commands used to capture, parse, and evaluate traffic in this study, recorded so that the analysis can be reproduced.

Throughout, `<capture>` stands for the name of the pcap file being processed — anyone reproducing these steps should substitute their own filename, and adjust the host addresses to match their environment.

## 1. Capture

Traffic is captured at the attack source. In the containerised testbed the process network uses macvlan, so capturing at the destination misses the traffic; capturing at the source is required.

```bash
# from the attacking host (engineering workstation)
sudo tcpdump -i eth0 -w <capture>.pcap
```

A baseline capture is taken under normal operation, with no attack running, to check for false positives.

## 2. Parse with Zeek

```bash
docker run --rm -v "$HOME":/data -w /data zeek/zeek:latest \
  zeek -C -r /data/<capture>.pcap
```

This produces `modbus.log`, with fields including `id.orig_h` (source), `id.resp_h` (destination), `func` (e.g. `WRITE_SINGLE_REGISTER`), and `pdu_type` (`REQ` / `RESP`).

## 3. Validate and convert the Sigma rules

```bash
# in the virtual environment where sigma-cli is installed
sigma convert -t lucene --without-pipeline sigma_rules/unauth_modbus_write.yml
```

Repeat for each rule. This confirms the rule is valid Sigma and produces the backend query.

## 4. Evaluate against the parsed logs

The rule logic is applied to `modbus.log` to count detections. For example, the unauthorised-write rule (write requests from any source other than the authorised master):

```bash
# unauthorised writes  — Rule 1
awk '$0 !~ /^#/ && $NF=="REQ" { print }' modbus.log \
  | grep "WRITE_" | grep -v "192.168.95.2" | wc -l

# reconnaissance reads — Rule 2
awk '$0 !~ /^#/ && $NF=="REQ" { print }' modbus.log \
  | grep "READ_"  | grep -v "192.168.95.2" | wc -l

# total requests from a non-authorised source — Rule 3 (flood)
awk '$0 !~ /^#/ && $NF=="REQ" { print }' modbus.log \
  | grep -v "192.168.95.2" | wc -l
```

Field positions vary with the Zeek version, so check the `#fields` header line in `modbus.log` and adjust the column references accordingly.

## 5. External validation

The same steps are applied to the external dataset. Only the allow-listed authorised master changes: the testbed PLC address (`192.168.95.2`) is replaced with the authorised host(s) of the external environment. The rules themselves are not modified.
