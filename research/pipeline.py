"""Offline, reproducible public-data runner, separate from the legacy demo.

python -m research.pipeline --inputs research-data --out research-results/run-001
Outputs are new computed evidence, never a claim of historical replication.
"""
import argparse
import csv
import hashlib
import json
import platform
from pathlib import Path
from .inputs import load_inputs
from .experiment import run_experiments
from .metrics import condensation_longest_path, project_edges_to_modules, marginal_gain_ranking


def jsonable(value):
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in sorted(value.items(), key=lambda p: str(p[0]))}
    if isinstance(value, (set, frozenset)):
        return [jsonable(v) for v in sorted(value, key=repr)]
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    return value


def canonical(value):
    return json.dumps(jsonable(value), sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(jsonable(value), indent=2, sort_keys=True, allow_nan=False) + "\n")


def graph_report(data):
    edges = sorted(data["related_edges"])
    control_graph = {c: [] for c in data["control_order"]}
    for source, target in edges:
        control_graph[source].append(target)
    control_to_module = {c: row["module"] for c, row in data["controls"].items()}
    projection = project_edges_to_modules(edges, control_to_module)
    module_graph = {m: [] for m in data["module_order"]}
    for source, target in sorted(projection["unique_projected_between"]):
        module_graph[source].append(target)
    if projection["original_within_count"] + projection["original_between_count"] != len(edges):
        raise ValueError("Graph projection did not account for every source edge")
    return {"meaning": "Explicit related-control cross-references, not prerequisite or implementation chains",
            "control_node_count": len(control_graph), "unique_directed_control_edges": len(edges),
            "self_links": sum(a == b for a, b in edges), "control_edges": edges,
            "controls": condensation_longest_path(control_graph),
            "taxonomy_module_count": len(module_graph),
            "modules_with_low_controls": len(set(control_to_module.values())),
            "module_projection": projection, "modules": condensation_longest_path(module_graph)}


def run(input_root, output, spec_path=None):
    home = Path(__file__).parent
    spec_path = Path(spec_path) if spec_path else home / "spec.json"
    spec = json.loads(spec_path.read_text())
    taxonomy = json.loads((home / "module_taxonomy.json").read_text())
    lock = json.loads((home / "input-lock.json").read_text())
    if output.exists():
        raise ValueError("Output directory already exists; use a fresh directory to preserve prior evidence")
    data = load_inputs(input_root, spec, taxonomy, lock)
    graphs = graph_report(data)
    experiment = run_experiments(data, spec)
    counts = []
    for module in taxonomy["modules"]:
        mid = module["id"]
        controls = [c for c in data["control_order"] if data["controls"][c]["module"] == mid]
        counts.append({"module_id": mid, "name": module["name"], "nist_controls": len(controls),
                       "nist_control_ids": controls, "cis_identifier_count": len(module["cis_safeguards"]),
                       "soc2_identifier_count": len(module["soc2_criteria"]),
                       "covered_parent_techniques": sorted(data["module_coverage"][mid]),
                       "coverage_count": len(data["module_coverage"][mid]),
                       "note": "CIS/SOC2 are author taxonomy identifiers, not independently validated crosswalk equivalence."})
    if sum(c["nist_controls"] for c in counts) != len(data["controls"]):
        raise ValueError("Module taxonomy loses or double-counts a selected Low control")
    for s in experiment["sector_summaries"].values():
        s["weighted_marginal_gain_companion"] = marginal_gain_ranking(data["module_coverage"], weights=s["frequencies"])
    source_hashes = {str(p.relative_to(home)): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted(home.rglob("*.py"))}
    identity = {"input_lock": lock, "specification": spec, "taxonomy": taxonomy, "source_hashes": source_hashes}
    run_id = digest(identity)
    evidence = {"counts": counts, "graphs": graphs, "audit": data["audit"],
                "control_coverage": data["control_coverage"], "experiment": experiment}
    manifest = {"schema_version": 1, "run_id": run_id, "semantic_output_sha256": digest(evidence),
                "status": "NEW research run, not recovered July outputs or historical validation",
                "legacy_repository_baseline": spec["baseline_repository_commit"],
                "python": platform.python_version(), "implementation": platform.python_implementation(),
                "input_lock_sha256": digest(lock), "specification_sha256": digest(spec),
                "taxonomy_sha256": digest(taxonomy), "source_hashes": source_hashes,
                "input_roles_verified": [f["role"] for f in lock["files"]],
                "hypotheses": "No automatic acceptance; simulation dependence and analysis chronology remain limitations"}
    output.mkdir(parents=True)
    write_json(output / "manifest.json", manifest)
    write_json(output / "effective-spec.json", spec)
    write_json(output / "input-lock.json", lock)
    write_json(output / "counts-and-crosswalk.json", counts)
    write_json(output / "graph-results.json", graphs)
    write_json(output / "input-audit.json", data["audit"])
    write_json(output / "control-coverage.json", data["control_coverage"])
    write_json(output / "experiment-results.json", experiment)
    write_json(output / "normalized-records.json", data["records"])
    with (output / "record-selection-ledger.jsonl").open("w") as stream:
        for row in data["audit_rows"]:
            stream.write(canonical(row).decode() + "\n")
    columns = ["profile_id", "suite", "milestone", "scenario", "budget_unit", "new_units",
               "remaining_units", "implemented_control_count", "covered_parent_technique_count",
               "weighted_gap", "top25_unweighted_gap"]
    with (output / "trajectories.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(experiment["trajectories"])
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(output.iterdir()) if p.is_file()}
    write_json(output / "output-checksums.json", files)
    return {"run_id": run_id, "semantic_output_sha256": manifest["semantic_output_sha256"],
            "low_controls": len(data["controls"]), "mapped_records": len(data["records"]),
            "technique_universe": len(experiment["technique_universe"]),
            "profiles": len(experiment["profiles"]), "trajectory_rows": len(experiment["trajectories"]),
            "largest_control_scc": graphs["controls"]["max_scc_size"],
            "largest_module_scc": graphs["modules"]["max_scc_size"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--spec", type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.inputs, args.out, args.spec), indent=2))


if __name__ == "__main__":
    main()
