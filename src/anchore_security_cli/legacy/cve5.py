import json
import logging
import os
import tomllib
from dataclasses import dataclass
from glob import iglob
from typing import Any

curator_to_cve5_additional_metadata = {
    "needs_review": "needsReview",
    "needs_jdk_review": "jdkReview",
    "to_dos": "toDos",
}

@dataclass(frozen=True, slots=True)
class CVERecord:
    cve_id: str
    snapshot: dict[str, Any]
    vuln: dict[str, Any]


def _construct_cpe(cpe: dict[str, str]) -> str:
    part = cpe.get("part", "a")
    vendor = cpe.get("vendor", "*")
    product = cpe.get("product", "*")
    edition = cpe.get("edition", "*")
    language = cpe.get("language", "*")
    software_edition = cpe.get("software_edition", "*")
    target_software = cpe.get("target_software", "*")
    target_hardware = cpe.get("target_hardware", "*")
    other = cpe.get("other", "*")
    return f"cpe:2.3:{part}:{vendor}:{product}:*:*:{edition}:{language}:{software_edition}:{target_software}:{target_hardware}:{other}"


def _persist(output_dir: str, cve_id: str, cve5: Any):
    components = cve_id.split("-")
    year = components[1]
    path = os.path.join(output_dir, year, f"{cve_id}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(cve5, f, ensure_ascii=False, sort_keys=True, indent=2)


def _process_cve_record(cve: CVERecord, curator: dict[str, Any], output_dir: str):  # noqa: C901, PLR0912, PLR0915
    cve5 = {
        "additionalMetadata": {
            "cveId": cve.cve_id,
            "cna": cve.snapshot["overview"]["cna"],
        },
    }

    for spec_key, cve5_key in curator_to_cve5_additional_metadata.items():
        v = curator.get(spec_key)
        if v:
            cve5["additionalMetadata"][cve5_key] = v

    description = cve.snapshot["overview"].get("description")
    if description:
        cve5["additionalMetadata"]["description"] = description

    references = cve.snapshot["overview"].get("references")
    if references:
        cve5["additionalMetadata"]["references"] = references

    remediations = cve.snapshot["overview"].get("remediations")
    if remediations:
        cve5["additionalMetadata"]["solutions"] = remediations

    enrichment_reason = cve.vuln.get("enrichment", {}).get("reason")
    if enrichment_reason:
        cve5["additionalMetadata"]["reason"] = enrichment_reason

    if "published" in cve.snapshot:
        digest_algorithm = "xxh128"
        if digest_algorithm not in cve.snapshot["digest"] and "sha256" in cve.snapshot["digest"]:
            digest_algorithm = "sha256"

        cve5["additionalMetadata"]["upstream"] = {
            "datePublished": cve.snapshot["published"].isoformat(),
            "dateReserved": cve.snapshot["reserved"].isoformat(),
            "dateUpdated": cve.snapshot["updated"].isoformat(),
            "digest": cve.snapshot["digest"][digest_algorithm],
            "digest_algorithm": digest_algorithm,
        }

    disputed = cve.vuln.get("disputed")
    if disputed:
        mark_disputed = disputed.get("override", False)
        if mark_disputed:
            cve5["additionalMetadata"]["disputed"] = True

    rejected = cve.vuln.get("rejection")
    if rejected:
        date = rejected.get("date")
        reason = rejected.get("reason")

        if date or reason:
            cve5["additionalMetadata"]["rejection"] = {}

        if date:
            cve5["additionalMetadata"]["rejection"]["date"] = date.isoformat()

        if reason:
            cve5["additionalMetadata"]["rejection"]["reason"] = reason

    suppression = cve.vuln.get("suppression")
    if suppression:
        ignore = suppression["override"]
        if ignore:
            cve5["additionalMetadata"]["ignore"] = True

    # TODO: eventually we will need to resolve the entire set of references from the aggregate view once we have that
    # so that we can process drop, override, etc.  For now we expect everything to be merge (previously add), so will
    # only consider those keys.
    references = cve.vuln.get("references", {}).get("merge")
    if not references:
        references = cve.vuln.get("references", {}).get("add")

    cve5_references = []
    if references:
        for r in references:
            cve5_references.append(
                {
                    "url": r["url"],
                },
            )

    cve5_affected: list[dict[str, Any]] = []
    # TODO: eventually need to support all of the new add/remove logic
    overrides = cve.vuln.get("products", {}).get("override", {})
    if overrides:
        for record_type, records in overrides.items():
             for r in records:
                p = {}
                cve5_affected.append(p)
                collection_url = r.get("collection_url")
                if collection_url:
                    p["collectionURL"] = collection_url

                vendor = r.get("vendor")
                if vendor:
                    p["vendor"] = vendor

                product = r.get("product")
                if product:
                    p["product"] = product

                if record_type != "cve5":
                    p["packageType"] = record_type

                match record_type:
                    case "maven" | "jenkins-plugin":
                        group_id = r.get("group_id")
                        artifact_id = r.get("artifact_id")
                        if group_id and artifact_id:
                            p["packageName"] = f"{group_id}:{artifact_id}"
                    case _:
                        package_name = r.get("package_name")
                        if package_name:
                            p["packageName"] = package_name

                source = r.get("source")
                if source:
                    p["repo"] = source[0]["url"]

                platforms = r.get("platforms")
                if platforms:
                    p["platforms"] = platforms

                modules = r.get("modules")
                if modules:
                    p["modules"] = modules

                program_files = r.get("program_files")
                if program_files:
                    p["programFiles"] = program_files

                program_routines = r.get("program_routines")
                if program_routines:
                    p["programRoutines"] = program_routines

                cpes = r.get("cpe")
                if cpes:
                    p["cpes"] = []
                    for cpe in cpes:
                        p["cpes"].append(_construct_cpe(cpe))

                versions: list[dict[str, Any]] = []
                affected = r.get("affected", [])

                if affected:
                    for a in affected:
                        a = a["version"]
                        v = {
                            "status": "affected",
                        }
                        less_than = a.get("less_than")
                        less_than_or_equal = a.get("less_than_or_equal")
                        start_inclusive = a.get("greater_than_or_equal")
                        version = a.get("equals")
                        scheme = a.get("scheme")

                        if less_than:
                            v["lessThan"] = less_than

                        if less_than_or_equal:
                            v["lessThanOrEqual"] = less_than_or_equal

                        if start_inclusive:
                            v["version"] = start_inclusive

                        if version:
                            v["version"] = version

                        if scheme:
                            v["versionType"] = scheme

                        versions.append(v)

                unaffected = r.get("unaffected", [])
                if unaffected:
                    for a in unaffected:
                        a = a["version"]
                        v = {
                            "status": "unaffected",
                        }
                        less_than = a.get("less_than")
                        less_than_or_equal = a.get("less_than_or_equal")
                        start_inclusive = a.get("greater_than_or_equal")
                        version = a.get("equals")
                        scheme = a.get("scheme")

                        if less_than:
                            v["lessThan"] = less_than

                        if less_than_or_equal:
                            v["lessThanOrEqual"] = less_than_or_equal

                        if start_inclusive:
                            v["version"] = start_inclusive

                        if version:
                            v["version"] = version

                        if scheme:
                            v["versionType"] = scheme

                        versions.append(v)

                investigating = r.get("investigating", [])
                if investigating:
                    for a in investigating:
                        a = a["version"]
                        v = {
                            "status": "unknown",
                        }
                        less_than = a.get("less_than")
                        less_than_or_equal = a.get("less_than_or_equal")
                        start_inclusive = a.get("greater_than_or_equal")
                        version = a.get("equals")
                        scheme = a.get("scheme")

                        if less_than:
                            v["lessThan"] = less_than

                        if less_than_or_equal:
                            v["lessThanOrEqual"] = less_than_or_equal

                        if start_inclusive:
                            v["version"] = start_inclusive

                        if version:
                            v["version"] = version

                        if scheme:
                            v["versionType"] = scheme

                        versions.append(v)

                if versions:
                    p["versions"] = versions

    if cve5_affected or cve5_references:
        cve5["adp"] = {
            "providerMetadata": {
                "orgId": "00000000-0000-4000-8000-000000000000",
                "shortName": "anchoreadp",
            },
        }

    if references:
        cve5["adp"]["references"] = cve5_references

    if cve5_affected:
        cve5["adp"]["affected"] = cve5_affected

    _persist(output_dir, cve.cve_id, cve5)


def _process_spec_file(spec_file: str, output_dir: str):
    with open(spec_file, "rb") as f:
        enriched = tomllib.load(f)

    curator = enriched.get("curator", {})
    if not curator:
        logging.warning(f"Skipping {spec_file}.  No curator data section found.")
        return

    vuln = enriched.get("vuln")
    if not vuln:
        logging.warning(f"Skipping {spec_file}.  No vulnerability data section found.")
        return

    snapshot = enriched.get("snapshot")
    if not snapshot:
        logging.warning(f"Skipping {spec_file}.  No snapshot section found.")
        return

    cve5_snapshot = snapshot.get("cve5", [])
    if not cve5_snapshot:
        logging.warning(f"Skipping {spec_file}.  No snapshot.cve5 section found.")
        return

    nvd_vuln = vuln.get("providers", {}).get("nvd", [])
    if not nvd_vuln:
        logging.warning(f"Skipping {spec_file}.  No vuln.providers.nvd data section found.")
        return

    snapshot_by_cve = {}

    for c in cve5_snapshot:
        snapshot_by_cve[c["id"]] = c

    cve_records = []
    for n in nvd_vuln:
        cve_id = n["id"]
        if cve_id in snapshot_by_cve:
            cve_records.append(CVERecord(
                cve_id=cve_id,
                snapshot=snapshot_by_cve[cve_id],
                vuln=n,
            ))

    for cve in cve_records:
        logging.debug(f"Start processing CVE {cve.cve_id}")
        _process_cve_record(cve, curator, output_dir)
        logging.debug(f"Finish processing CVE {cve.cve_id}")


def generate(spec_path: str, output: str):
    logging.info(f"Start generating CVE 5 from {spec_path}")

    for f in iglob(os.path.join(spec_path, "**/ANCHORE-*.toml"), recursive=True):
        logging.debug(f"Start processing spec {f}")
        _process_spec_file(f, output)
        logging.debug(f"Finish processing spec {f}")

    logging.info(f"Finish generating CVE 5 from {spec_path}")
