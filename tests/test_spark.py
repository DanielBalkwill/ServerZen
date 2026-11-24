"""Tests for the PySpark scale-out layer.

The *logic* Spark distributes (`scan_partition`) is pure Python and tested
directly — no Spark needed. The end-to-end Spark job is tested too, but only
when PySpark (and a JDK) are available; otherwise that one test is skipped.

Run:  pytest serverzen/tests/test_spark.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from serverzen.spark.scan import _FIELDS, _clean_uri, scan_partition  # noqa: E402

VULN = (
    "import subprocess\n"
    "OPENAI_API_KEY = 'sk-ABCdef0123456789ABCdef0123456789'\n"
    "def run(cmd):\n"
    "    return subprocess.run(cmd, shell=True)\n"
)


def test_scan_partition_finds_checks_without_spark():
    out = list(scan_partition([{"path": "a.py", "value": VULN}]))
    checks = {d["check"] for d in out}
    assert "dangerous-exec" in checks
    assert "hardcoded-secret" in checks
    for d in out:                       # every row carries the full, flat schema
        assert set(d) == set(_FIELDS)
        assert isinstance(d["line"], int)


def test_scan_partition_skips_empty_source():
    assert list(scan_partition([{"path": "x.py", "value": None}])) == []


def test_scan_partition_respects_safe_markers():
    egress = "import httpx\nhttpx.get(url)\n"
    assert any(d["check"] == "unguarded-egress"
               for d in scan_partition([{"path": "e.py", "value": egress}]))
    guarded = egress + "make_safe_client(url)\n"
    assert not any(d["check"] == "unguarded-egress"
                   for d in scan_partition([{"path": "e.py", "value": guarded}]))


def test_clean_uri_handles_windows_and_object_store():
    assert _clean_uri("file:/C:/code/app.py") == "C:/code/app.py"
    assert _clean_uri("s3://bucket/app.py") == "s3://bucket/app.py"


def test_end_to_end_spark_job(tmp_path):
    pytest.importorskip("pyspark")
    from pyspark.sql import SparkSession

    from serverzen.spark.scan import posture_by_path, scan_paths

    (tmp_path / "vuln.py").write_text(VULN)
    (tmp_path / "clean.py").write_text("x = 1\n")

    spark = (SparkSession.builder.master("local[2]").appName("serverzen-test")
             .config("spark.ui.enabled", "false").getOrCreate())
    try:
        df = scan_paths(spark, str(tmp_path))
        checks = {r["check"] for r in df.collect()}
        assert "dangerous-exec" in checks and "hardcoded-secret" in checks
        assert df.schema.names == list(_FIELDS)
        grades = [r["grade"] for r in posture_by_path(df).collect()]
        assert grades and all(g in {"A", "B", "C", "D", "F"} for g in grades)
    finally:
        spark.stop()
