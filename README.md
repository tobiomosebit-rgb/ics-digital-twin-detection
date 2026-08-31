# ICS Threat Detection in a Digital Twin

Supporting code and configuration for the MSc dissertation *"A Digital Twin Approach to Developing and Validating ICS Threat Detection Capabilities Using the MITRE ATT&CK for ICS Framework"* (MSc Cyber Security Engineering, WMG, University of Warwick, 2026).

The project develops signature-based detection rules for Modbus-based attacks inside a virtualised ICS digital twin, and validates whether those rules transfer to an independent, labelled dataset from a different ICS environment.

## Contents

| Path | Description |
|---|---|
| `sigma_rules/unauth_modbus_write.yml` | Detects unauthorised Modbus write requests from a non-authorised source (ATT&CK T0836 / T0855) |
| `sigma_rules/modbus_recon_scan.yml` | Detects read requests from a non-authorised source sweeping multiple devices (T0846) |
| `sigma_rules/modbus_dos_flood.yml` | Detects a high rate of requests from a single non-authorised source (T0814) |
| `commands.md` | The capture, parsing, and scoring commands used in the experiments |

## Environment

Experiments were run on the [GRFICSv3](https://github.com/Fortiphyd/GRFICSv2) containerised ICS testbed, which simulates a Tennessee Eastman chemical process with a PLC, HMI, engineering workstation, and segmented process/enterprise networks. Attacks were executed from the engineering workstation against Modbus field devices on the process network.

## Detection pipeline

The same four stages were applied to both the testbed captures and the external dataset:

1. **Capture** — network traffic recorded with `tcpdump` at the attack source (capture at the destination misses traffic due to macvlan routing in the containerised testbed).
2. **Parse** — the resulting pcap is parsed with Zeek, which produces a structured `modbus.log` containing the source and destination hosts, the Modbus function as a descriptive string (e.g. `WRITE_SINGLE_REGISTER`), and a request/response indicator.
3. **Detect** — the Sigma rules are validated and converted with `sigma-cli`, then their logic is evaluated against the parsed logs.
4. **Score** — detections are counted per technique and recorded in a coverage matrix of true positives, false positives, and false negatives, with baseline (attack-free) captures used to check for false positives.

## Rule design

The rules do not match on specific malicious values. Each identifies control-plane activity originating from a source other than the authorised Modbus master (the PLC), on the basis that no other host in this environment has legitimate cause to issue such commands. This makes them robust to variation in register or value.

For external validation the rules were applied **unchanged apart from the asset allow-list**, which was retargeted from the testbed PLC to the external dataset's authorised hosts — supporting the study's finding that the detection logic is portable across environments while the asset inventory is deployment-specific.

## External dataset

External validation used the CIC Modbus 2023 dataset (Canadian Institute for Cybersecurity, University of New Brunswick). The dataset is **not redistributed here** and must be obtained from the CIC directly: <https://www.unb.ca/cic/datasets/modbus-2023.html>

## Note

This repository contains the detection rules and the commands needed to reproduce the analysis. It does not contain attack tooling, captured traffic, or the external dataset.
