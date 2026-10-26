"""A .csproj with XML entity declarations is refused, never expanded, and the scan says NuGet was not read."""

from __future__ import annotations

from agent_bom.parsers import dotnet_parsers

_ENTITY_BOMB = """<?xml version="1.0"?>
<!DOCTYPE p [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>
<Project><ItemGroup><PackageReference Include="&b;" Version="1.0.0" /></ItemGroup></Project>
"""


def test_entity_declarations_are_refused_with_a_coverage_warning(tmp_path, monkeypatch) -> None:
    (tmp_path / "app.csproj").write_text(_ENTITY_BOMB)
    warnings: list[dict] = []
    monkeypatch.setattr(dotnet_parsers, "record_manifest_parse_warning", lambda **kw: warnings.append(kw))
    assert dotnet_parsers._parse_csproj_files(tmp_path) == []
    assert [w["path"].endswith("app.csproj") for w in warnings] == [True]


def test_plain_csproj_still_parses(tmp_path) -> None:
    (tmp_path / "app.csproj").write_text(
        '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>'
    )
    assert [(p.name, p.version) for p in dotnet_parsers._parse_csproj_files(tmp_path)] == [("Newtonsoft.Json", "13.0.3")]
