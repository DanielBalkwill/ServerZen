"""CLI for the PySpark scale-out layer.

Run locally (needs a JDK on PATH)::

    pip install 'serverzen[spark]'
    python -m serverzen.spark ./some/code/tree --show 25

On a cluster, submit it and point at object storage::

    spark-submit --py-files serverzen.zip -m serverzen.spark \\
        s3://bucket/repos --out s3://bucket/out/findings.parquet
"""
from __future__ import annotations

import argparse


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        "serverzen-spark", description="Distributed ServerZEN scan over a code estate.")
    ap.add_argument("roots", nargs="+",
                    help="dirs/files/prefixes to scan (local path, s3://, abfss://, gs://)")
    ap.add_argument("--out", help="write the findings DataFrame as Parquet here")
    ap.add_argument("--summary-out", help="write the per-file posture summary as Parquet here")
    ap.add_argument("--min-severity", choices=["INFO", "LOW", "MEDIUM", "HIGH"],
                    help="drop findings below this severity")
    ap.add_argument("--safe-marker", action="append", default=[], metavar="NAME",
                    help="treat a file mentioning NAME as having guarded egress (repeatable)")
    ap.add_argument("--show", type=int, default=20,
                    help="rows of the posture summary to print (0 = none)")
    args = ap.parse_args(argv)

    from pyspark.sql import SparkSession

    from serverzen.checks import DEFAULT_SAFE_MARKERS
    from serverzen.spark.scan import by_check, filter_min_severity, posture_by_path, scan_paths

    spark = SparkSession.builder.appName("serverzen-scan").getOrCreate()
    try:
        markers = DEFAULT_SAFE_MARKERS + tuple(args.safe_marker)
        findings = scan_paths(spark, *args.roots, safe_markers=markers)
        if args.min_severity:
            findings = filter_min_severity(findings, args.min_severity)
        findings = findings.cache()

        total = findings.count()
        print(f"\nServerZEN (Spark): {total} finding(s) across {len(args.roots)} root(s)\n")
        if total:
            print("By check:")
            by_check(findings).show(50, truncate=False)
            if args.show:
                print("Worst files (posture):")
                posture_by_path(findings).show(args.show, truncate=False)

        if args.out:
            findings.write.mode("overwrite").parquet(args.out)
            print(f"findings -> {args.out}")
        if args.summary_out:
            posture_by_path(findings).write.mode("overwrite").parquet(args.summary_out)
            print(f"summary  -> {args.summary_out}")
    finally:
        spark.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
