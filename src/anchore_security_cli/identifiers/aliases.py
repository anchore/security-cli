from dataclasses import dataclass, field


def cve_to_gcve(cve_id: str) -> str | None:
    if cve_id.startswith("CVE-"):
        return cve_id.replace("CVE-", "GCVE-0-")
    return None


def gcve_to_cve(gcve_id: str) -> str | None:
    if gcve_id.startswith("GCVE-0-"):
        return gcve_id.replace("GCVE-0-", "CVE-")
    return None

@dataclass(frozen=True)
class Aliases:
    cve: list[str] = field(default_factory=list)
    gcve: list[str] = field(default_factory=list)
    github: list[str] = field(default_factory=list)
    chainguard: list[str] = field(default_factory=list)
    bitnami: list[str] = field(default_factory=list)
    psf: list[str] = field(default_factory=list)
    pypa: list[str] = field(default_factory=list)
    go: list[str] = field(default_factory=list)
    rustsec: list[str] = field(default_factory=list)
    rconsortium: list[str] = field(default_factory=list)
    openssf_malicious_packages: list[str] = field(default_factory=list)

    @classmethod
    def from_list(cls, aliases: list[str]):  # noqa: C901, PLR0912
        cve = set()
        gcve = set()
        github = set()
        chainguard = set()
        bitnami = set()
        psf = set()
        pypa = set()
        go = set()
        rustsec = set()
        rconsortium = set()
        openssf_malicious_packages = set()

        for a in aliases:
            if not a:
                continue

            if a.startswith("CVE-"):
                cve.add(a)
                gcve_id = cve_to_gcve(a)
                if gcve_id:
                    gcve.add(gcve_id)
            elif a.startswith("GCVE-"):
                gcve.add(a)
                cve_id = gcve_to_cve(a)
                if cve_id:
                    cve.add(cve_id)
            elif a.startswith("GHSA-"):
                github.add(a)
            elif a.startswith("CGA-"):
                chainguard.add(a)
            elif a.startswith("BIT-"):
                bitnami.add(a)
            elif a.startswith("PSF-"):
                psf.add(a)
            elif a.startswith("PYSEC-"):
                pypa.add(a)
            elif a.startswith("GO-"):
                go.add(a)
            elif a.startswith("RUSTSEC-"):
                rustsec.add(a)
            elif a.startswith("RSEC-"):
                rconsortium.add(a)
            elif a.startswith("MAL-"):
                openssf_malicious_packages.add(a)

        return Aliases(
            cve=list(cve),
            gcve=list(gcve),
            github=list(github),
            chainguard=list(chainguard),
            bitnami=list(bitnami),
            psf=list(psf),
            pypa=list(pypa),
            go=list(go),
            rustsec=list(rustsec),
            rconsortium=list(rconsortium),
            openssf_malicious_packages=list(openssf_malicious_packages),
        )

    def to_list(self, exclude: set[str] | None = None) -> list[str]:
        if exclude is None:
            exclude = set()

        result = set()
        for alias_key, aliases in self.__dict__.items():
            if alias_key in exclude:
                continue

            if aliases:
                result.update(aliases)
        return list(result)
