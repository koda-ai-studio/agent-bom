"""Dockerfile scanner precision: logical lines, stages, FROM flags and secret values."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.iac.dockerfile import scan_dockerfile


@pytest.fixture()
def scan(tmp_path: Path):
    def _scan(content: str) -> list[tuple[str, int]]:
        path = tmp_path / "Dockerfile"
        path.write_text(content)
        return [(f.rule_id, f.line_number) for f in scan_dockerfile(path)]

    return _scan


def _ids(pairs: list[tuple[str, int]]) -> set[str]:
    return {rule for rule, _ in pairs}


class TestContinuationLines:
    def test_install_on_a_continuation_line_is_seen_at_the_run_line(self, scan) -> None:
        found = scan("FROM debian:12\nRUN apt-get update && \\\n    apt-get install -y curl\nUSER app\nHEALTHCHECK CMD true\n")
        assert ("DOCKER-007", 2) in found

    def test_cleanup_on_a_later_continuation_line_is_honoured(self, scan) -> None:
        content = (
            "FROM debian:12\n"
            "RUN apt-get update \\\n"
            "    && apt-get install -y --no-install-recommends curl=8.5.0-2 \\\n"
            "    # comment lines inside a continued instruction are dropped\n"
            "    && rm -rf /var/lib/apt/lists/*\n"
            "USER app\nHEALTHCHECK CMD true\n"
        )
        assert "DOCKER-007" not in _ids(scan(content))

    def test_pipe_install_split_across_lines_is_detected(self, scan) -> None:
        found = scan("FROM alpine:3.20\nRUN curl -fsSL https://example.invalid/i.sh \\\n    | sh\nUSER app\n")
        assert ("DOCKER-005", 2) in found

    def test_escape_directive_backtick_joins_lines(self, scan) -> None:
        found = scan("# escape=`\nFROM alpine:3.20\nRUN wget -qO- https://example.invalid/i.sh `\n    | bash\nUSER app\n")
        assert ("DOCKER-005", 3) in found

    def test_heredoc_body_is_part_of_the_run(self, scan) -> None:
        content = "FROM alpine:3.20\nRUN <<EOF\nset -e\nchmod 777 /srv\nEOF\nUSER app\nHEALTHCHECK CMD true\n"
        found = scan(content)
        assert ("DOCKER-012", 2) in found
        assert not any(line in (3, 4, 5) for _, line in found)

    def test_unterminated_heredoc_does_not_swallow_the_rest_of_the_file(self, scan) -> None:
        content = "FROM alpine:3.20\nRUN echo 'a <<EOF b'\nRUN chmod 777 /srv\nUSER app\nHEALTHCHECK CMD true\n"
        assert ("DOCKER-012", 3) in scan(content)

    def test_yum_and_dnf_clean_all_count_as_cleanup(self, scan) -> None:
        for manager in ("yum", "dnf"):
            content = f"FROM rockylinux:9\nRUN {manager} install -y httpd && {manager} clean all\nUSER app\nHEALTHCHECK CMD true\n"
            assert "DOCKER-007" not in _ids(scan(content)), manager

    def test_dnf_install_without_cleanup_is_flagged(self, scan) -> None:
        assert "DOCKER-007" in _ids(scan("FROM fedora:40\nRUN dnf install -y httpd\nUSER app\n"))

    def test_cache_mount_keeps_the_package_cache_out_of_the_layer(self, scan) -> None:
        content = "FROM debian:12\nRUN --mount=type=cache,target=/var/cache/apt apt-get install -y curl=8.5.0-2\nUSER app\n"
        assert "DOCKER-007" not in _ids(scan(content))


class TestFromParsing:
    def test_platform_flag_is_not_read_as_the_image(self, scan) -> None:
        found = scan("FROM --platform=$BUILDPLATFORM python:3.12-slim@sha256:" + "a" * 64 + "\nUSER app\n")
        assert not {"DOCKER-001", "DOCKER-010"} & _ids(found)

    def test_stage_alias_reference_is_not_an_unpinned_image(self, scan) -> None:
        digest = "@sha256:" + "b" * 64
        content = f"FROM golang:1.23{digest} AS build\nRUN go build\nFROM build AS test\nFROM gcr.io/distroless/static:nonroot{digest}\n"
        found = scan(content)
        assert ("DOCKER-001", 3) not in found
        assert ("DOCKER-010", 3) not in found

    def test_arg_default_is_resolved_for_the_base_image(self, scan) -> None:
        found = scan("ARG BASE=python:latest\nFROM ${BASE}\nUSER app\n")
        assert ("DOCKER-001", 2) in found

    def test_unresolvable_arg_base_is_not_guessed(self, scan) -> None:
        found = scan("ARG BASE\nFROM $BASE\nUSER app\n")
        assert not {"DOCKER-001", "DOCKER-010"} & _ids(found)


class TestFinalStageUser:
    def test_builder_stage_root_is_not_the_runtime_user(self, scan) -> None:
        content = "FROM node:22 AS build\nUSER root\nRUN npm ci\nFROM node:22-slim\nUSER node\nHEALTHCHECK CMD true\n"
        assert "DOCKER-002" not in _ids(scan(content))

    def test_root_then_non_root_in_final_stage_is_fine(self, scan) -> None:
        content = "FROM debian:12\nUSER root\nRUN id\nUSER 10001:10001\nHEALTHCHECK CMD true\n"
        assert "DOCKER-002" not in _ids(scan(content))

    def test_last_user_root_in_final_stage_is_flagged_at_its_line(self, scan) -> None:
        content = "FROM debian:12\nUSER app\nRUN id\nUSER root\nHEALTHCHECK CMD true\n"
        assert [p for p in scan(content) if p[0] == "DOCKER-002"] == [("DOCKER-002", 4)]

    def test_final_stage_without_user_is_flagged_even_if_builder_set_one(self, scan) -> None:
        content = "FROM node:22 AS build\nUSER node\nRUN npm ci\nFROM node:22-slim\nCOPY --from=build /app /app\n"
        assert ("DOCKER-002", 4) in scan(content)

    def test_final_stage_inherits_user_from_the_stage_it_extends(self, scan) -> None:
        content = "FROM node:22 AS base\nUSER node\nFROM base\nRUN npm ci\nHEALTHCHECK CMD true\n"
        assert "DOCKER-002" not in _ids(scan(content))

    def test_nonroot_tagged_base_is_not_flagged_for_missing_user(self, scan) -> None:
        assert "DOCKER-002" not in _ids(scan("FROM gcr.io/distroless/static-debian12:nonroot\nCOPY app /app\n"))


class TestEnvSecrets:
    def test_second_pair_on_an_env_line_is_checked(self, scan) -> None:
        value = "-".join(("plain", "text", "value"))
        assert ("DOCKER-003", 2) in scan(f"FROM alpine:3.20\nENV MODE=prod DB_PASSWORD={value}\nUSER app\n")

    def test_secret_file_paths_and_interpolation_are_not_secrets(self, scan) -> None:
        content = "FROM alpine:3.20\nENV DB_PASSWORD_FILE=/run/secrets/db API_TOKEN=${API_TOKEN} SECRET_DIR=/etc/app/secrets\nUSER app\n"
        assert "DOCKER-003" not in _ids(scan(content))

    def test_buildkit_secret_mount_is_the_safe_pattern(self, scan) -> None:
        content = "FROM node:22-slim\nRUN --mount=type=secret,id=npm_token,env=NPM_TOKEN npm ci\nUSER node\nHEALTHCHECK CMD true\n"
        assert not {"DOCKER-003", "DOCKER-015", "DOCKER-026"} & _ids(scan(content))


class TestWorkdir:
    def test_variable_workdir_is_not_relative(self, scan) -> None:
        assert "DOCKER-018" not in _ids(scan("FROM alpine:3.20\nWORKDIR $HOME/app\nWORKDIR ${APP_ROOT}\nUSER app\n"))
