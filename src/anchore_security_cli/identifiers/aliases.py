import logging
from dataclasses import dataclass, field


def cve_to_gcve(cve_id: str) -> str | None:
    if cve_id.startswith("CVE-"):
        return cve_id.replace("CVE-", "GCVE-0-")
    return None


def gcve_to_cve(gcve_id: str) -> str | None:
    if gcve_id.startswith("GCVE-0-"):
        return gcve_id.replace("GCVE-0-", "CVE-")
    return None

def generate_all_openeuler_id_variants(openeuler_id: str) -> list[str]:
    # OESA is the OSV identifier prefix for openEuler Advisories; however, openEuler also use a different prefix
    # of openEuler-SA- elsewhere, and we want to support both, so create a list of all possible variants when passed
    # an id
    result: list[str] = [openeuler_id]

    if openeuler_id.startswith("OESA-"):
        result.append(openeuler_id.replace("OESA-", "openEuler-SA-"))
    elif openeuler_id.startswith("openEuler-SA-"):
        result.append(openeuler_id.replace("openEuler-SA-", "OESA-"))

    return result

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
    almalinux: list[str] = field(default_factory=list)
    debian: list[str] = field(default_factory=list)
    redhat: list[str] = field(default_factory=list)
    rockylinux: list[str] = field(default_factory=list)
    suse: list[str] = field(default_factory=list)
    opensuse: list[str] = field(default_factory=list)
    ubuntu: list[str] = field(default_factory=list)
    minimos: list[str] = field(default_factory=list)
    echo: list[str] = field(default_factory=list)
    openeuler: list[str] = field(default_factory=list)
    amazonlinux: list[str] = field(default_factory=list)
    oraclelinux: list[str] = field(default_factory=list)
    julia: list[str] = field(default_factory=list)
    mageia: list[str] = field(default_factory=list)
    snyk: list[str] = field(default_factory=list)
    cpan: list[str] = field(default_factory=list)
    arch: list[str] = field(default_factory=list)

    @classmethod
    def normalize(cls, alias: str) -> str:
        alias = alias.strip()
        alias = alias.replace("‑", "-")  # noqa: RUF001

        if alias.startswith("UBUNTU-CVE-"):
            alias = alias.removeprefix("UBUNTU-")
        elif alias.startswith("DEBIAN-CVE-"):
            alias = alias.removeprefix("DEBIAN-")
        elif alias.startswith("ALPINE-CVE-"):
            alias = alias.removeprefix("ALPINE-")

        return alias

    @classmethod
    def from_list(cls, aliases: list[str]):  # noqa: C901, PLR0912, PLR0915
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
        redhat = set()
        rockylinux = set()
        almalinux = set()
        debian = set()
        suse = set()
        opensuse = set()
        ubuntu = set()
        minimos = set()
        echo = set()
        openeuler = set()
        amazonlinux = set()
        oraclelinux = set()
        julia = set()
        mageia = set()
        snyk = set()
        cpan = set()
        arch = set()

        for a in aliases:
            a = cls.normalize(a)
            if not a:
                continue

            if a.startswith("CVE-"):
                cve.add(a)
                gcve_id = cve_to_gcve(a)
                if gcve_id:
                    gcve.add(gcve_id)
            elif a.startswith("GSD-"):
                # GSD is effectively dead, don't bother capturing these at the moment
                # but we also don't want them getting logged as warnings
                continue
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
            elif a.startswith(("ALSA-", "ALBA-", "ALEA-")):
                almalinux.add(a)
            elif a.startswith(("DSA-", "DTSA-", "DLA-")):
                debian.add(a)
            elif a.startswith("RHSA-"):
                redhat.add(a)
            elif a.startswith(("RLSA-", "RXSA-")):
                rockylinux.add(a)
            elif a.startswith("SUSE-"):
                suse.add(a)
            elif a.startswith("openSUSE-"):
                opensuse.add(a)
            elif a.startswith("USN-"):
                ubuntu.add(a)
            elif a.startswith("MINI-"):
                minimos.add(a)
            elif a.startswith("ECHO-"):
                echo.add(a)
            elif a.startswith(("OESA-", "openEuler-SA-")):
                for v in generate_all_openeuler_id_variants(a):
                    openeuler.add(v)
            elif a.startswith("ELSA-"):
                oraclelinux.add(a)
            elif a.startswith("ALAS"):
                amazonlinux.add(a)
            elif a.startswith("JLSEC-"):
                julia.add(a)
            elif a.startswith("MGASA-"):
                mageia.add(a)
            elif a.startswith("SNYK-"):
                snyk.add(a)
            elif a.startswith("CPANSA-"):
                cpan.add(a)
            elif a.startswith(("ASA-", "AVG-")):
                arch.add(a)
            else:
                logging.warning(f"encountered unsupported alias: {a!r}")

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
            almalinux=list(almalinux),
            debian=list(debian),
            redhat=list(redhat),
            rockylinux=list(rockylinux),
            suse=list(suse),
            opensuse=list(opensuse),
            ubuntu=list(ubuntu),
            minimos=list(minimos),
            echo=list(echo),
            openeuler=list(openeuler),
            amazonlinux=list(amazonlinux),
            oraclelinux=list(oraclelinux),
            julia=list(julia),
            mageia=list(mageia),
            snyk=list(snyk),
            cpan=list(cpan),
            arch=list(arch),
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
