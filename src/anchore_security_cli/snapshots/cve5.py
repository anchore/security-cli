import json
import os
import shlex
import shutil
import tempfile
from glob import iglob

import requests

from anchore_security_cli.utils import execute_command, timer


class CVE5Snapshotter:
    def __init__(self, repo_root: str):
        self._github_repo = "CVEProject/cvelistV5"
        self._default_branch = "main"
        self._repo_root = repo_root

    def _process_files(self, tmp_path: str):
        for file in iglob(os.path.join(tmp_path, "**/CVE-*.json"), recursive=True):
            if not os.path.isfile(file):
                continue

            with open(file) as f:
                data = json.load(f)

            output_path = os.path.join(self._repo_root, "cves", file.removeprefix(tmp_path).removeprefix(os.sep))
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)

    def process(self, commit: bool=True, push: bool = False):
        r = requests.get(
            f"https://api.github.com/repos/{self._github_repo}/commits/{self._default_branch}",
            timeout=10,
        )

        r.raise_for_status()

        latest_commit = r.json()["sha"]
        url = f"https://github.com/{self._github_repo}/archive/{latest_commit}.zip"
        with tempfile.TemporaryDirectory() as tmp:
            with timer(f"downloading from {url}"):
                cmd = f"curl -f -L -o content.zip -X GET {shlex.quote(url)}"
                execute_command(cmd, cwd=tmp)

            with timer(f"extracting archive content from {url}"):
                execute_command("unzip content.zip", cwd=tmp)

            repo_path = os.path.join(self._repo_root, "cves")
            with timer(f"processing data from {url}"):
                if os.path.exists(repo_path):
                    shutil.rmtree(repo_path)
                tmp_path = os.path.join(tmp, f"cvelistV5-{latest_commit}", "cves")
                self._process_files(tmp_path)

            if commit:
                execute_command("git add cves", cwd=self._repo_root)
                execute_command(f'git commit -s -m "syncing data from https://github.com/{self._github_repo}/commits/{latest_commit}"', cwd=self._repo_root)  # noqa: E501

                if push:
                    execute_command("git push origin main")
