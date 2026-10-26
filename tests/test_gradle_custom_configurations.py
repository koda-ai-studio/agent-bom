"""Gradle dependencies declared through shadow/custom configurations and map notation."""

from __future__ import annotations

import textwrap

from agent_bom.parsers import parse_gradle_packages
from agent_bom.scanners.state import capture_coverage_warnings

GROOVY_BUILD = textwrap.dedent("""\
    plugins {
        id 'com.github.johnrengelman.shadow' version '8.1.1'
        id("org.example.plugin:not-a-dep:1.0")
    }
    ext {
        grpcVersion = '1.58.1'
    }
    configurations { payloadGeneratorsImplementation }
    repositories { maven { url 'https://repo.example.com:8443/maven2' } }
    dependencies {
        shadow "io.grpc:grpc-netty-shaded:$grpcVersion"
        shadow 'com.google.protobuf:protobuf-java:3.25.1'
        payloadGeneratorsImplementation "org.slf4j:slf4j-api:1.7.36"
        integrationTestImplementation group: 'junit', name: 'junit', version: '4.13.2'
        implementation group: "com.google.guava", name: "guava", version: "32.1.3-jre"
        shadow "io.micrometer:micrometer-core:${undefinedVersion}"
        implementation platform('io.grpc:grpc-bom:1.58.1')
        classpath 'com.android.tools.build:gradle:8.2.0'
    }
    tasks.register('x') { println 'a:b:c' }
""")


def _parse(tmp_path):
    (tmp_path / "build.gradle").write_text(GROOVY_BUILD)
    with capture_coverage_warnings() as warnings:
        pkgs = {p.name: p.version for p in parse_gradle_packages(tmp_path)}
    return pkgs, " | ".join(str(w.get("detail")) for w in warnings)


def test_shadow_and_custom_configurations_are_scanned(tmp_path):
    pkgs, _ = _parse(tmp_path)
    assert pkgs["io.grpc:grpc-netty-shaded"] == "1.58.1"
    assert pkgs["com.google.protobuf:protobuf-java"] == "3.25.1"
    assert pkgs["org.slf4j:slf4j-api"] == "1.7.36"


def test_map_notation_dependencies_are_scanned(tmp_path):
    pkgs, _ = _parse(tmp_path)
    assert pkgs["junit:junit"] == "4.13.2"
    assert pkgs["com.google.guava:guava"] == "32.1.3-jre"


def test_non_dependency_dsl_calls_are_not_packages(tmp_path):
    pkgs, details = _parse(tmp_path)
    assert "org.example.plugin:not-a-dep" not in pkgs
    assert "io.grpc:grpc-bom" not in pkgs
    assert "com.android.tools.build:gradle" not in pkgs
    assert "a:b" not in pkgs
    assert "repo.example.com" not in details
    assert "a:b:c" not in details


def test_unresolved_custom_configuration_coordinates_are_named_in_gap(tmp_path):
    pkgs, details = _parse(tmp_path)
    assert "io.micrometer:micrometer-core" not in pkgs
    assert "micrometer-core" in details
    assert "gradle.lockfile" in details


def test_kotlin_string_invoked_custom_configuration(tmp_path):
    (tmp_path / "gradle.lockfile").write_text("empty=\n")
    (tmp_path / "build.gradle.kts").write_text(
        textwrap.dedent("""\
            val payloadGeneratorsImplementation by configurations.creating
            dependencies {
                payloadGeneratorsImplementation("org.slf4j:slf4j-api:1.7.36")
                "shadow"("io.netty:netty-handler:4.1.100.Final")
                implementation(group = "com.squareup.okhttp3", name = "okhttp", version = "4.12.0")
            }
        """)
    )
    pkgs = {p.name: p.version for p in parse_gradle_packages(tmp_path)}
    assert pkgs == {
        "org.slf4j:slf4j-api": "1.7.36",
        "io.netty:netty-handler": "4.1.100.Final",
        "com.squareup.okhttp3:okhttp": "4.12.0",
    }
