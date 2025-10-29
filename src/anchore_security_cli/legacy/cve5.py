import json
import logging
import os
import tomllib
from dataclasses import dataclass
from datetime import datetime
from glob import iglob
from typing import Any

curator_to_cve5_additional_metadata = {
    "needs_review": "needsReview",
    "needs_jdk_review": "jdkReview",
    "to_dos": "toDos",
}

@dataclass(frozen=True, slots=True)
class NVDRecord:
    cve_id: str
    curator: dict[str, Any]
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
    with open(os.path.join(output_dir, year, f"{cve_id}.json"), "w") as f:
        json.dump(cve5, f, ensure_ascii=False, sort_keys=True, indent=2)


def _to_legacy_datetime_format(d: datetime) -> str:
    s = d.isoformat()

    if s.endswith("000+00:00"):
        s = s.removesuffix("000+00:00") + "Z"

    return s


def _process_nvd_record(nvd: NVDRecord, curator: dict[str, Any], output_dir: str):  # noqa: C901, PLR0912, PLR0915
    cve5 = {
        "additionalMetadata": {
            "cveId": nvd.cve_id,
            "cna": nvd.curator["cna"],
        },
    }

    for spec_key, cve5_key in curator_to_cve5_additional_metadata.items():
        v = curator.get(spec_key)
        if v:
            cve5["additionalMetadata"][cve5_key] = v

    description = nvd.curator.get("description")
    if description:
        cve5["additionalMetadata"]["description"] = description

    references = nvd.curator.get("references")
    if references:
        cve5["additionalMetadata"]["references"] = references

    remediations = nvd.curator.get("remediations")
    if remediations:
        cve5["additionalMetadata"]["solutions"] = remediations

    enrichment_reason = nvd.vuln.get("enrichment", {}).get("reason")
    if enrichment_reason:
        cve5["additionalMetadata"]["reason"] = enrichment_reason

    snapshot = nvd.vuln.get("snapshot")
    if snapshot:
        cve5["additionalMetadata"]["upstream"] = {
            "datePublished": snapshot["published"].isoformat(),
            "dateReserved": snapshot["reserved"].isoformat(),
            "dateUpdated": snapshot["updated"].isoformat(),
            "digest": snapshot["digest"]["sha256"],
        }

    disputed = nvd.vuln.get("disputed")
    if disputed:
        mark_disputed = disputed.get("override", False)
        if mark_disputed:
            cve5["additionalMetadata"]["disputed"] = True

    rejected = nvd.vuln.get("rejection")
    if rejected:
        date = rejected.get("date")
        reason = rejected.get("reason")

        if date or reason:
            cve5["additionalMetadata"]["rejection"] = {}

        if date:
            cve5["additionalMetadata"]["rejection"]["date"] = date.isoformat()

        if reason:
            cve5["additionalMetadata"]["rejection"]["reason"] = reason

    suppression = nvd.vuln.get("suppression")
    if suppression:
        ignore = suppression["override"]
        if ignore:
            cve5["additionalMetadata"]["ignore"] = True

    # TODO: eventually we will need to resolve the entire set of references from the aggregate view once we have that
    # so that we can process remove, override, etc.  For now we expect everything to be add so will only consider that.
    references = nvd.vuln.get("references", {}).get("add")
    cve5_references = []
    if references:
        for r in references:
            cve5_references.append(
                {
                    "url": r["url"],
                },
            )

    cve5_affected: dict[int, dict[str, Any]] = {}
    # TODO: eventually need to support all of the new add/remove logic
    overrides = nvd.vuln.get("products", {}).get("override", {})
    if overrides:
        for idx, (record_type, records) in enumerate(overrides.items()):
             for r in records:
                p = {}
                cve5_affected[r.get("_index", idx)] = p

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

                versions: dict[int, dict[str, Any]] = {}
                affected = r.get("affected", [])

                if affected:
                    for a in affected:
                        q_index = a.get("_index", len(versions))
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

                        versions[q_index] = v

                unaffected = r.get("unaffected", [])
                if unaffected:
                    for a in unaffected:
                        q_index = a.get("_index", len(versions))
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

                        versions[q_index] = v

                investigating = r.get("investigating", [])
                if investigating:
                    for a in investigating:
                        q_index = a.get("_index", len(versions))
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

                        versions[q_index] = v

                if versions:
                    p["versions"] = [v for (k,v) in sorted(versions.items())]

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
        cve5["adp"]["affected"] = [v for (k,v) in sorted(cve5_affected.items())]

    # TODO: keep going
    _persist(output_dir, nvd.cve_id, cve5)


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

    nvd_curator = curator.get("providers", {}).get("nvd", [])
    if not nvd_curator:
        logging.warning(f"Skipping {spec_file}.  No curator.providers.nvd data section found.")
        return

    nvd_vuln = vuln.get("providers", {}).get("nvd", [])
    if not nvd_vuln:
        logging.warning(f"Skipping {spec_file}.  No vuln.providers.nvd data section found.")
        return

    curator_by_cve = {}

    for n in nvd_curator:
        curator_by_cve[n["cve_id"]] = n

    nvd_records = []
    for n in nvd_vuln:
        cve_id = n["cve_id"]
        if cve_id in curator_by_cve:
            nvd_records.append(NVDRecord(
                cve_id=cve_id,
                curator=curator_by_cve[cve_id],
                vuln=n,
            ))

    for nvd in nvd_records:
        logging.debug(f"Start processing CVE {nvd.cve_id}")
        _process_nvd_record(nvd, curator, output_dir)
        logging.debug(f"Finish processing CVE {nvd.cve_id}")


def generate(spec_path: str, output: str):
    logging.info(f"Start generating CVE 5 from {spec_path}")

    for f in iglob(os.path.join(spec_path, "**/ANCHORE-*.toml"), recursive=True):
        logging.debug(f"Start processing spec {f}")
        _process_spec_file(f, output)
        logging.debug(f"Finish processing spec {f}")

    logging.info(f"Finish generating CVE 5 from {spec_path}")
