from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from anchore_security_cli.identifiers.providers.almalinux import AlmaLinux
from anchore_security_cli.identifiers.providers.bitnami import Bitnami
from anchore_security_cli.identifiers.providers.chainguard import Chainguard
from anchore_security_cli.identifiers.providers.cve5 import CVE5
from anchore_security_cli.identifiers.providers.debian import Debian
from anchore_security_cli.identifiers.providers.echo import Echo
from anchore_security_cli.identifiers.providers.github import GitHub
from anchore_security_cli.identifiers.providers.go import Go
from anchore_security_cli.identifiers.providers.grypedb import GrypeDB
from anchore_security_cli.identifiers.providers.julia import Julia
from anchore_security_cli.identifiers.providers.mageia import Mageia
from anchore_security_cli.identifiers.providers.minimos import MinimOS
from anchore_security_cli.identifiers.providers.openeuler import OpenEuler
from anchore_security_cli.identifiers.providers.openssf_malicious_packages import OpenSSFMaliciousPackages
from anchore_security_cli.identifiers.providers.provider import Provider
from anchore_security_cli.identifiers.providers.psf import PSF
from anchore_security_cli.identifiers.providers.pypa import PyPA
from anchore_security_cli.identifiers.providers.rconsortium import RConsortium
from anchore_security_cli.identifiers.providers.redhat import RedHat
from anchore_security_cli.identifiers.providers.rockylinux import RockyLinux
from anchore_security_cli.identifiers.providers.rustsec import RustSec
from anchore_security_cli.identifiers.providers.suse import SUSE, OpenSUSE
from anchore_security_cli.identifiers.providers.ubuntu import Ubuntu
from anchore_security_cli.identifiers.store import CURRENT_ALLOCATION_ALIAS_KEYS


@dataclass(frozen=True)
class Providers:
    cve5: CVE5
    github: GitHub
    chainguard: Chainguard
    bitnami: Bitnami
    psf: PSF
    pypa: PyPA
    go: Go
    rustsec: RustSec
    rconsortium: RConsortium
    openssf_malicious_packages: OpenSSFMaliciousPackages
    almalinux: AlmaLinux
    debian: Debian
    redhat: RedHat
    rockylinux: RockyLinux
    suse: SUSE
    opensuse: OpenSUSE
    ubuntu: Ubuntu
    echo: Echo
    minimos: MinimOS
    openeuler: OpenEuler
    grypedb: GrypeDB
    julia: Julia
    mageia: Mageia

    def aliases_by_cve(self, cve_id: str) -> list[str]:
        results = {cve_id}
        for p in self.__dict__.values():
            if not p:
                continue
            if not isinstance(p, Provider):
                continue
            aliases = p.by_cve(cve_id)
            if aliases:
                for a in aliases:
                    results.update([a.id, *a.aliases.to_list(exclude=CURRENT_ALLOCATION_ALIAS_KEYS)])
        return list(results)

    def aliases_by_ghsa(self, ghsa_id: str) -> list[str]:
        results = {ghsa_id}
        for p in self.__dict__.values():
            if not p:
                continue
            if not isinstance(p, Provider):
                continue
            aliases = p.by_ghsa(ghsa_id)
            if aliases:
                for a in aliases:
                    results.update([a.id, *a.aliases.to_list(exclude=CURRENT_ALLOCATION_ALIAS_KEYS)])
        return list(results)

    def aliases_by_ossf(self, ossf_id: str) -> list[str]:
        results = {ossf_id}
        for p in self.__dict__.values():
            if not p:
                continue
            if not isinstance(p, Provider):
                continue
            aliases = p.by_ossf(ossf_id)
            if aliases:
                for a in aliases:
                    results.update([a.id, *a.aliases.to_list()])
        return list(results)


def fetch_all() -> Providers:
    with ThreadPoolExecutor() as executor:
        cve5 = executor.submit(CVE5)
        github = executor.submit(GitHub)
        openssf_malicious_packages = executor.submit(OpenSSFMaliciousPackages)
        ubuntu = executor.submit(Ubuntu)
        chainguard = executor.submit(Chainguard)
        bitnami = executor.submit(Bitnami)
        psf = executor.submit(PSF)
        pypa = executor.submit(PyPA)
        go = executor.submit(Go)
        rustsec = executor.submit(RustSec)
        rconsortium = executor.submit(RConsortium)
        almalinux = executor.submit(AlmaLinux)
        debian = executor.submit(Debian)
        redhat = executor.submit(RedHat)
        rockylinux = executor.submit(RockyLinux)
        suse = executor.submit(SUSE)
        opensuse = executor.submit(OpenSUSE)
        echo = executor.submit(Echo)
        minimos = executor.submit(MinimOS)
        openeuler = executor.submit(OpenEuler)
        grypedb = executor.submit(GrypeDB)
        julia = executor.submit(Julia)
        mageia = executor.submit(Mageia)

    return Providers(
        cve5=cve5.result(),
        github=github.result(),
        chainguard=chainguard.result(),
        bitnami=bitnami.result(),
        psf=psf.result(),
        pypa=pypa.result(),
        go=go.result(),
        rustsec=rustsec.result(),
        rconsortium=rconsortium.result(),
        openssf_malicious_packages=openssf_malicious_packages.result(),
        almalinux=almalinux.result(),
        debian=debian.result(),
        redhat=redhat.result(),
        rockylinux=rockylinux.result(),
        suse=suse.result(),
        opensuse=opensuse.result(),
        ubuntu=ubuntu.result(),
        echo=echo.result(),
        minimos=minimos.result(),
        openeuler=openeuler.result(),
        grypedb=grypedb.result(),
        julia=julia.result(),
        mageia=mageia.result(),
    )
