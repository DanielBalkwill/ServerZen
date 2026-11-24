"""Optional PySpark scale-out layer for ServerZEN.

ServerZEN's core is a fast, single-machine, dependency-free scanner. This
subpackage fans that *same* pure analysis (``serverzen.checks.run_file``) across
a Spark cluster, so you can scan a very large code estate — tens of thousands of
repos, a giant monorepo, a bucket of source in object storage — in one job and
get a typed findings DataFrame back.

Requires the optional dependency::

    pip install 'serverzen[spark]'

Nothing here is imported by ``import serverzen``; the core stays stdlib-only.
Importing this subpackage does *not* require PySpark — only calling the
Spark-facing functions does (the pure ``scan_partition`` runs anywhere).

See ``docs/SPARK.md`` for architecture, cluster usage, and when NOT to use it.
"""
from serverzen.spark.scan import (
    by_check,
    by_severity,
    filter_min_severity,
    findings_schema,
    posture_by_path,
    scan_partition,
    scan_paths,
)

__all__ = [
    "scan_paths",
    "scan_partition",
    "findings_schema",
    "by_check",
    "by_severity",
    "posture_by_path",
    "filter_min_severity",
]
