"""Distributed ServerZEN scanning with PySpark.

The whole design rests on one property of the core: ``serverzen.checks.run_file``
is a *pure function* — ``(path, source) -> list[Finding]``, no shared state, no
I/O. That makes it trivially distributable: Spark reads the source files, and
each executor runs the exact same checks the single-machine CLI runs, in
parallel, over a whole code estate.

Nothing here imports PySpark at module load (every ``pyspark`` import is inside
the function that needs it), so this module — and the pure ``scan_partition``
the cluster actually runs — can be imported and unit-tested without a Spark
install. That is deliberate: the logic Spark distributes is plain Python you can
test in milliseconds.
"""
from __future__ import annotations

import re
from urllib.parse import unquote, urlparse

from serverzen.checks import DEFAULT_SAFE_MARKERS

# Flat, typed output columns. Declaring them (rather than letting Spark infer a
# schema) avoids an extra pass over the data and keeps the contract explicit.
_FIELDS = ("check", "severity", "path", "line", "message", "confidence", "cwe", "owasp", "atlas")

# Mirrors serverzen.report so a Spark-side grade matches the single-node tool.
_RISK_WEIGHT = {"HIGH": 10, "MEDIUM": 3, "LOW": 1, "INFO": 0}
_SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _require_pyspark() -> None:
    try:
        import pyspark  # noqa: F401
    except ImportError as exc:  # pragma: no cover - only hit without pyspark
        raise ImportError(
            "serverzen.spark needs PySpark. Install it with:  pip install 'serverzen[spark]'  "
            "(PySpark also needs a JDK 8/11/17 on PATH)."
        ) from exc


def _clean_uri(path: str) -> str:
    """Turn a Hadoop ``input_file_name()`` URI into a plain path.

    Spark reports e.g. ``file:/C:/code/app.py`` or ``s3://bucket/app.py``. Local
    ``file:`` URIs become real OS paths; object-store URIs are left untouched.
    """
    if path and path.startswith("file:"):
        p = unquote(urlparse(path).path)
        if re.match(r"^/[A-Za-z]:", p):   # Windows: "/C:/x" -> "C:/x"
            p = p[1:]
        return p
    return path


def scan_partition(rows, safe_markers=DEFAULT_SAFE_MARKERS):
    """Run ServerZEN over an iterable of ``{"path", "value"}`` rows.

    This is the function Spark runs on each partition — but it is plain Python
    with no Spark types, so it is exactly what the unit tests exercise. Yields
    one dict per finding, keyed by :data:`_FIELDS`.
    """
    from serverzen.checks import run_file, finding_dict  # imported on the executor
    sm = tuple(safe_markers)
    for row in rows:
        path = row["path"]
        source = row["value"]
        if not source:
            continue
        for finding in run_file(path, source, safe_markers=sm):
            d = finding_dict(finding)
            yield {k: d[k] for k in _FIELDS}


def findings_schema():
    """The explicit Spark schema for a findings DataFrame (order = :data:`_FIELDS`)."""
    _require_pyspark()
    from pyspark.sql import types as T
    S = T.StringType
    return T.StructType([
        T.StructField("check", S(), False),
        T.StructField("severity", S(), False),
        T.StructField("path", S(), False),
        T.StructField("line", T.IntegerType(), False),
        T.StructField("message", S(), True),
        T.StructField("confidence", S(), True),
        T.StructField("cwe", S(), True),
        T.StructField("owasp", S(), True),
        T.StructField("atlas", S(), True),
    ])


def scan_paths(spark, *roots, safe_markers=DEFAULT_SAFE_MARKERS, recursive=True):
    """Scan one or more roots and return a findings DataFrame.

    ``roots`` are anything Spark's file reader understands: a local directory, a
    single file, or an object-store prefix on a cluster (``s3://``, ``abfss://``,
    ``gs://``). Only ``*.py`` files are read.
    """
    _require_pyspark()
    from pyspark.sql import functions as F
    sm = tuple(safe_markers)

    reader = (spark.read
              .option("wholetext", "true")        # one row per file; whole file in `value`
              .option("pathGlobFilter", "*.py"))   # only Python sources
    if recursive:
        reader = reader.option("recursiveFileLookup", "true")

    src = (reader.text(list(roots))
           .withColumn("path", F.input_file_name())
           .select("path", "value"))

    def _emit(part):
        rows = ({"path": _clean_uri(r["path"]), "value": r["value"]} for r in part)
        for d in scan_partition(rows, sm):
            yield tuple(d[k] for k in _FIELDS)

    # mapPartitions, not a per-row UDF: import serverzen and parse once per
    # partition instead of paying Python<->JVM round-trips per file.
    rdd = src.rdd.mapPartitions(_emit)
    return spark.createDataFrame(rdd, findings_schema())


# ── aggregations ─────────────────────────────────────────────────────────────
def _case_from(mapping, default=0):
    """Build a CASE WHEN column over the `severity` column from a {level: value} map."""
    from pyspark.sql import functions as F
    expr = None
    for level, value in mapping.items():
        branch = F.col("severity") == level
        expr = F.when(branch, value) if expr is None else expr.when(branch, value)
    return expr.otherwise(default) if expr is not None else F.lit(default)


def by_check(findings):
    """Count findings grouped by check and severity, worst first."""
    _require_pyspark()
    from pyspark.sql import functions as F
    return findings.groupBy("check", "severity").count().orderBy(F.desc("count"), "check")


def by_severity(findings):
    """Count findings grouped by severity."""
    _require_pyspark()
    from pyspark.sql import functions as F
    return findings.groupBy("severity").count().orderBy(F.desc("count"))


def filter_min_severity(findings, level):
    """Keep only findings at or above ``level`` (INFO < LOW < MEDIUM < HIGH)."""
    _require_pyspark()
    from pyspark.sql import functions as F
    threshold = _SEV_RANK.get(level.upper(), 0)
    return findings.filter(_case_from(_SEV_RANK, 0) >= F.lit(threshold))


def posture_by_path(findings, path_col="path"):
    """Per-file risk score, finding count and A–F grade — the "worst files" view.

    The weights and grade thresholds match ``serverzen.report`` exactly, so a
    file's cluster-side grade equals the one the single-node CLI would give it.
    Files with no findings don't appear here (they aren't in the findings set);
    they are implicitly grade A.
    """
    _require_pyspark()
    from pyspark.sql import functions as F
    agg = (findings.groupBy(path_col)
           .agg(F.sum(_case_from(_RISK_WEIGHT, 0)).alias("risk_score"),
                F.count(F.lit(1)).alias("findings")))
    grade = (F.when(F.col("risk_score") == 0, "A")
             .when(F.col("risk_score") <= 5, "B")
             .when(F.col("risk_score") <= 15, "C")
             .when(F.col("risk_score") <= 30, "D")
             .otherwise("F"))
    return agg.withColumn("grade", grade).orderBy(F.desc("risk_score"))
