"""Scoped npm packages: an owned scope is not a typosquat of its own unscoped name."""

import pytest

from agent_bom.malicious import check_typosquat
from agent_bom.models import Package
from agent_bom.scanners.package_coverage import _flag_suspicious_packages

OFFICIAL_SCOPED_NPM = [
    "@rollup/plugin-babel",
    "@rollup/plugin-commonjs",
    "@rollup/plugin-node-resolve",
    "@rollup/plugin-terser",
    "@rollup/plugin-json",
    "@rollup/plugin-replace",
    "@rollup/plugin-typescript",
    "@babel/core",
    "@babel/preset-env",
    "@babel/cli",
    "@types/node",
    "@types/react",
    "@types/express",
    "@angular/core",
    "@angular/cli",
    "@vue/compiler-sfc",
    "@vue/cli-service",
    "@nestjs/core",
    "@nestjs/cli",
    "@aws-sdk/client-s3",
    "@mui/material",
    "@testing-library/react",
    "@typescript-eslint/parser",
    "@sentry/node",
    "@sentry/cli",
    "@tanstack/react-query",
    "@storybook/react",
    "@storybook/cli",
    "@emotion/react",
    "@reduxjs/toolkit",
    "@octokit/rest",
    "@prisma/client",
    "@google-cloud/storage",
    "@azure/identity",
    "@vitejs/plugin-react",
    "@sveltejs/kit",
    "@jest/core",
    "@swc/core",
    "@grpc/grpc-js",
    "@apollo/client",
]


@pytest.mark.parametrize("name", OFFICIAL_SCOPED_NPM)
def test_official_scoped_npm_packages_are_not_typosquats(name):
    assert check_typosquat(name, "npm") is None


@pytest.mark.parametrize(
    ("name", "ecosystem", "target"),
    [
        ("reqeusts", "pypi", "requests"),
        ("expresss", "npm", "express"),
        ("lodahs", "npm", "lodash"),
        # A lookalike scope is not the project's own namespace.
        ("@rolup/plugin-babel", "npm", "rollup-plugin-babel"),
        ("@rollupp/plugin-commonjs", "npm", "rollup-plugin-commonjs"),
        # A squat of a popular name published under an unrelated scope.
        ("@evil/expresss", "npm", "express"),
    ],
)
def test_real_squats_still_flagged(name, ecosystem, target):
    assert check_typosquat(name, ecosystem) == target


def test_package_coverage_does_not_flag_official_scoped_package_as_malicious():
    pkgs = [Package(name=name, version="1.0.0", ecosystem="npm") for name in OFFICIAL_SCOPED_NPM]
    _flag_suspicious_packages(pkgs)
    flagged = {p.name: p.malicious_reason for p in pkgs if p.is_malicious}
    assert flagged == {}


def test_package_coverage_still_flags_scope_lookalike():
    pkg = Package(name="@rolup/plugin-babel", version="1.0.0", ecosystem="npm")
    _flag_suspicious_packages([pkg])
    assert pkg.is_malicious is True
    assert pkg.malicious_reason == "Possible typosquat of 'rollup-plugin-babel'"
