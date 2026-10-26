"""Gradle variable-version resolution and honest coverage gaps."""

from __future__ import annotations

import textwrap
from pathlib import Path

from agent_bom.parsers import parse_gradle_packages
from agent_bom.scanners.state import capture_coverage_warnings

ROOT_BUILD = textwrap.dedent("""\
    ext {
        jacksonVersion = '2.15.4'
        logbackVersion = "1.2.11"
    }
    ext.guavaVersion = '32.1.3-jre'
    allprojects { repositories { mavenCentral() } }
""")

MODULE_BUILD = textwrap.dedent("""\
    def localVersion = '1.7.36'
    dependencies {
        implementation "com.fasterxml.jackson.core:jackson-databind:$jacksonVersion"
        implementation "ch.qos.logback:logback-classic:${logbackVersion}"
        api "com.google.guava:guava:${guavaVersion}"
        implementation "org.slf4j:slf4j-api:$localVersion"
        implementation "io.grpc:grpc-core:$grpcVersion"
        implementation "io.micrometer:micrometer-core:${undefinedVersion}"
        implementation "org.apache.commons:commons-lang3"
        implementation project(':temporal-serviceclient')
    }
""")


def _project(tmp_path: Path) -> Path:
    (tmp_path / "settings.gradle").write_text("include 'temporal-sdk'\n")
    (tmp_path / "build.gradle").write_text(ROOT_BUILD)
    (tmp_path / "gradle.properties").write_text("grpcVersion=1.58.1\n# comment\n")
    module = tmp_path / "temporal-sdk"
    module.mkdir()
    (module / "build.gradle").write_text(MODULE_BUILD)
    return module


def _details(warnings: list[dict]) -> str:
    return " | ".join(str(w.get("detail")) for w in warnings)


def test_variable_versions_resolve_from_root_ext_and_gradle_properties(tmp_path):
    module = _project(tmp_path)
    with capture_coverage_warnings():
        pkgs = {p.name: p.version for p in parse_gradle_packages(module)}

    assert pkgs["com.fasterxml.jackson.core:jackson-databind"] == "2.15.4"
    assert pkgs["ch.qos.logback:logback-classic"] == "1.2.11"
    assert pkgs["com.google.guava:guava"] == "32.1.3-jre"
    assert pkgs["org.slf4j:slf4j-api"] == "1.7.36"
    assert pkgs["io.grpc:grpc-core"] == "1.58.1"
    assert "io.micrometer:micrometer-core" not in pkgs
    assert not any("$" in v for v in pkgs.values())


def test_unresolved_or_versionless_coordinates_record_coverage_gap(tmp_path):
    module = _project(tmp_path)
    with capture_coverage_warnings() as warnings:
        parse_gradle_packages(module)

    details = _details(warnings)
    assert all(w["reason"] == "manifest_parse_error" for w in warnings)
    assert "micrometer-core" in details
    assert "commons-lang3" in details


def test_build_without_lockfile_records_transitive_gap(tmp_path):
    (tmp_path / "build.gradle").write_text("dependencies {\n    implementation 'junit:junit:4.13.2'\n}\n")
    with capture_coverage_warnings() as warnings:
        pkgs = parse_gradle_packages(tmp_path)

    assert [p.name for p in pkgs] == ["junit:junit"]
    assert any("gradle.lockfile" in str(w["detail"]) for w in warnings)


def test_lockfile_build_records_no_transitive_gap(tmp_path):
    (tmp_path / "build.gradle").write_text("dependencies {\n    implementation 'junit:junit:4.13.2'\n}\n")
    (tmp_path / "gradle.lockfile").write_text("junit:junit:4.13.2=compileClasspath\nempty=\n")
    with capture_coverage_warnings() as warnings:
        parse_gradle_packages(tmp_path)

    assert warnings == []


def test_kotlin_dsl_val_and_extra_variables_resolve(tmp_path):
    (tmp_path / "gradle.lockfile").write_text("empty=\n")
    (tmp_path / "build.gradle.kts").write_text(
        textwrap.dedent("""\
            val okhttpVersion = "4.12.0"
            extra["nettyVersion"] = "4.1.100.Final"
            dependencies {
                implementation("com.squareup.okhttp3:okhttp:$okhttpVersion")
                implementation("io.netty:netty-handler:${property("nettyVersion")}")
            }
        """)
    )
    pkgs = {p.name: p.version for p in parse_gradle_packages(tmp_path)}
    assert pkgs["com.squareup.okhttp3:okhttp"] == "4.12.0"
    assert pkgs["io.netty:netty-handler"] == "4.1.100.Final"
