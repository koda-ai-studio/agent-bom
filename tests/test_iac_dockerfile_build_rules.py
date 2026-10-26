"""DOCKER-023..026: package install hygiene, overridden CMD/ENTRYPOINT, credential files copied in."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.iac import scan_iac_with_context
from agent_bom.iac.dockerfile import scan_dockerfile

_HARDENED_TAIL = "USER app\nHEALTHCHECK CMD true\n"


@pytest.fixture()
def scan(tmp_path: Path):
    def _scan(body: str, base: str = "FROM debian:12\n") -> list[tuple[str, int]]:
        path = tmp_path / "Dockerfile"
        path.write_text(base + body + _HARDENED_TAIL)
        return [(f.rule_id, f.line_number) for f in scan_dockerfile(path)]

    return _scan


def _lines(found: list[tuple[str, int]], rule: str) -> list[int]:
    return [line for rule_id, line in found if rule_id == rule]


class TestNoInstallRecommends:
    def test_apt_get_install_without_flag_is_flagged(self, scan) -> None:
        assert _lines(scan("RUN apt-get update && apt-get install -y curl=8.5.0-2 && rm -rf /var/lib/apt/lists/*\n"), "DOCKER-023") == [2]

    def test_flag_or_apt_option_is_the_safe_pattern(self, scan) -> None:
        body = (
            "RUN apt-get install -y --no-install-recommends curl=8.5.0-2 && rm -rf /var/lib/apt/lists/*\n"
            "RUN apt-get -o APT::Install-Recommends=false install -y git=1:2.39.5-0 && rm -rf /var/lib/apt/lists/*\n"
        )
        assert _lines(scan(body), "DOCKER-023") == []

    def test_other_package_managers_are_not_apt(self, scan) -> None:
        assert _lines(scan("RUN apk add --no-cache curl=8.11.1-r0\n", base="FROM alpine:3.20\n"), "DOCKER-023") == []

    def test_a_second_install_without_the_flag_is_still_flagged(self, scan) -> None:
        body = "RUN apt-get install -y --no-install-recommends a=1 \\\n && apt-get install -y b=2 && rm -rf /var/lib/apt/lists/*\n"
        assert _lines(scan(body), "DOCKER-023") == [2]


class TestUnpinnedPackages:
    def test_unpinned_apt_packages_are_flagged_and_named(self, tmp_path: Path) -> None:
        path = tmp_path / "Dockerfile"
        path.write_text(
            "FROM debian:12\nRUN apt-get install -y --no-install-recommends curl ca-certificates=20230311 && rm -rf /var/lib/apt/lists/*\n"
        )
        finding = next(f for f in scan_dockerfile(path) if f.rule_id == "DOCKER-024")
        assert finding.line_number == 2
        assert "curl" in finding.message
        assert "ca-certificates" not in finding.message

    def test_unpinned_apk_packages_are_flagged(self, scan) -> None:
        assert _lines(scan("RUN apk add --no-cache curl\n", base="FROM alpine:3.20\n"), "DOCKER-024") == [2]

    def test_pinned_packages_variables_and_local_debs_are_not_flagged(self, scan) -> None:
        body = (
            "RUN apt-get install -y --no-install-recommends curl=8.5.0-2 ./pkg.deb $EXTRA && rm -rf /var/lib/apt/lists/*\n"
            "RUN apk add --no-cache --virtual .build-deps gcc=13.2.1-r0 musl-dev~1.2\n"
        )
        assert _lines(scan(body), "DOCKER-024") == []

    def test_dnf_and_pip_are_out_of_scope(self, scan) -> None:
        assert _lines(scan("RUN dnf install -y httpd && dnf clean all\n", base="FROM fedora:40\n"), "DOCKER-024") == []


class TestOverriddenCmd:
    def test_earlier_cmd_and_entrypoint_in_a_stage_are_flagged(self, scan) -> None:
        body = 'CMD ["a"]\nENTRYPOINT ["x"]\nCMD ["b"]\nENTRYPOINT ["y"]\n'
        assert _lines(scan(body), "DOCKER-025") == [2, 3]

    def test_one_per_stage_is_fine(self, scan) -> None:
        body = 'CMD ["build"]\nFROM debian:12\nENTRYPOINT ["x"]\nCMD ["serve"]\n'
        assert _lines(scan(body), "DOCKER-025") == []


class TestCredentialFilesCopied:
    @pytest.mark.parametrize(
        "instruction",
        [
            "COPY .env /app/.env",
            "COPY --chown=app:app id_rsa /home/app/.ssh/id_rsa",
            "ADD .npmrc /root/",
            'COPY [".aws/credentials", "/root/.aws/credentials"]',
            "COPY config/.env.production ./",
            "COPY --from=build /root/.git-credentials /root/",
            "COPY certs/client.p12 /etc/app/",
        ],
    )
    def test_credential_file_is_flagged(self, scan, instruction: str) -> None:
        assert _lines(scan(instruction + "\n"), "DOCKER-026") == [2]

    @pytest.mark.parametrize(
        "instruction",
        [
            "COPY .env.example /app/.env.example",
            "COPY id_rsa.pub /home/app/.ssh/authorized_keys",
            "COPY ca.pem /usr/local/share/ca-certificates/",
            "COPY repo.key /etc/apt/keyrings/",
            "COPY src/ /app/src/",
            "COPY environment.py /app/",
        ],
    )
    def test_non_credential_files_are_not_flagged(self, scan, instruction: str) -> None:
        assert _lines(scan(instruction + "\n"), "DOCKER-026") == []

    def test_new_rules_do_not_fire_on_compose_files(self, tmp_path: Path) -> None:
        compose = tmp_path / "compose.yaml"
        compose.write_text("services:\n  a:\n    image: x:1\n    command: apt-get install curl\n")
        ids = {f.rule_id for f in scan_iac_with_context(compose).findings}
        assert not {"DOCKER-023", "DOCKER-024", "DOCKER-025", "DOCKER-026"} & ids
