"""Local parent POM <dependencies> and <dependencyManagement> are inherited."""

from __future__ import annotations

from pathlib import Path

from agent_bom.parsers.compiled_parsers import parse_maven_packages
from agent_bom.scanners.state import capture_coverage_warnings

NS = 'xmlns="http://maven.apache.org/POM/4.0.0"'

PARENT = f"""<project {NS}>
  <groupId>net.example</groupId>
  <artifactId>driver-parent</artifactId>
  <version>3.13.0</version>
  <packaging>pom</packaging>
  <properties>
    <jackson.version>2.13.2</jackson.version>
    <netty.version>4.1.70.Final</netty.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>${{jackson.version}}</version>
      </dependency>
      <dependency>
        <groupId>io.netty</groupId>
        <artifactId>netty-codec-http</artifactId>
        <version>${{netty.version}}</version>
      </dependency>
      <dependency>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
        <version>4.13.1</version>
        <scope>test</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>1.7.30</version>
    </dependency>
  </dependencies>
</project>
"""

CHILD = f"""<project {NS}>
  <parent>
    <groupId>net.example</groupId>
    <artifactId>driver-parent</artifactId>
    <version>3.13.0</version>
    <relativePath>./parent-pom.xml</relativePath>
  </parent>
  <artifactId>driver</artifactId>
  <properties>
    <netty.version>4.1.94.Final</netty.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
    <dependency>
      <groupId>io.netty</groupId>
      <artifactId>netty-codec-http</artifactId>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
    </dependency>
    <dependency>
      <groupId>org.unmanaged</groupId>
      <artifactId>mystery</artifactId>
    </dependency>
  </dependencies>
</project>
"""


def _project(tmp_path: Path) -> Path:
    (tmp_path / ".git").mkdir()
    (tmp_path / "parent-pom.xml").write_text(PARENT)
    (tmp_path / "pom.xml").write_text(CHILD)
    return tmp_path


def test_versionless_dependencies_take_parent_managed_versions(tmp_path):
    with capture_coverage_warnings():
        pkgs = {p.name: p for p in parse_maven_packages(_project(tmp_path))}

    assert pkgs["com.fasterxml.jackson.core:jackson-databind"].version == "2.13.2"
    assert pkgs["io.netty:netty-codec-http"].version == "4.1.94.Final"
    assert pkgs["junit:junit"].version == "4.13.1"
    assert pkgs["junit:junit"].is_direct is False


def test_parent_dependencies_are_inherited(tmp_path):
    with capture_coverage_warnings():
        pkgs = {p.name: p.version for p in parse_maven_packages(_project(tmp_path))}
    assert pkgs["org.slf4j:slf4j-api"] == "1.7.30"


def test_unmanaged_versionless_dependency_still_records_partial_coverage(tmp_path):
    with capture_coverage_warnings() as warnings:
        pkgs = {p.name for p in parse_maven_packages(_project(tmp_path))}
    assert "org.unmanaged:mystery" not in pkgs
    assert any("unresolved" in str(w["detail"]) for w in warnings)


def test_child_managed_version_overrides_parent(tmp_path):
    _project(tmp_path)
    child = CHILD.replace(
        "<dependencies>",
        "<dependencyManagement><dependencies><dependency><groupId>junit</groupId><artifactId>junit</artifactId>"
        "<version>4.13.2</version></dependency></dependencies></dependencyManagement>\n  <dependencies>",
        1,
    )
    (tmp_path / "pom.xml").write_text(child)
    with capture_coverage_warnings():
        pkgs = {p.name: p.version for p in parse_maven_packages(tmp_path)}
    assert pkgs["junit:junit"] == "4.13.2"
