# Data attribution and change notices

This research package does not claim ownership of upstream catalogs, mappings or incident records. Exact source commits, download URLs, byte lengths and SHA256 digests are in `input-lock.json`.

- NIST OSCAL content: National Institute of Standards and Technology, `usnistgov/oscal-content`, content 5.2.0, release v1.5.0. CC0/public-domain notice retained as `licenses/NIST-LICENSE.md`.
- CTID mappings: Center for Threat-Informed Defense, `center-for-threat-informed-defense/mappings-explorer`. Apache License 2.0 retained as `licenses/CTID-LICENSE.txt`.
- MITRE ATT&CK: The MITRE Corporation, Enterprise ATT&CK 16.1 via `mitre-attack/attack-stix-data`. Custom terms retained as `licenses/ATTACK-LICENSE.txt`. ATT&CK names and marks retain their respective ownership. No endorsement is implied.
- VCDB: Verizon RISK / VCDB contributors, `vz-risk/VCDB`. Creative Commons Attribution-ShareAlike 4.0 International notice retained as `licenses/VCDB-LICENSE.txt`.

Changes to derived VCDB data: source-status, identifier-collision, industry and schema-version eligibility filtering; extraction of action-variety enumerations; CTID candidate mappings; ATT&CK parent/lifecycle/tactic normalization; fractional maximum technique credits; bootstrap sampling and coverage projections. Raw inputs remain byte-identical to the lock. Derived record-level outputs and adaptations retain applicable CC-BY-SA-4.0 attribution/share-alike requirements, including these change notices; separate CTID and MITRE source terms continue to apply. Source IDs and file paths are traceability keys, not a claim of independently validated event uniqueness.

The author-defined M2SBF module taxonomy comes from the repository's earlier prototype. This implementation corrects the absent CC9.1 identifier in the research-only governance-module record. CIS safeguard and SOC2 criterion identifiers are reference labels only: no full proprietary standard text is reproduced, and no audit/compliance equivalence is certified.

Upstream notices govern upstream material. This notice does not relicense unrelated existing application code. Retain notices when distributing datasets or adapted outputs and review any third-party embedded content separately.
