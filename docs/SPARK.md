# ServerZEN at scale — PySpark

ServerZEN's core is a fast, single-machine, dependency-free scanner. This layer
distributes that **same** analysis across a Spark cluster, so you can scan a
whole **code estate** — tens of thousands of repos, a giant monorepo, or a
bucket of source in object storage — in one job.

> Optional extra, never a core dependency: `pip install 'serverzen[spark]'`.
> `import serverzen` never pulls PySpark.

## Why this works (the one idea)

Every ServerZEN check is a **pure function** — `run_file(path, source) -> list[Finding]`,
no shared state, no I/O. So parallelising is almost free: Spark reads the files,
and each executor runs the identical checks the CLI runs. The code the cluster
executes, `scan_partition`, is plain Python with no Spark types — which is why it
is unit-tested in milliseconds without a Spark install.

```
roots (local dir | s3:// | abfss:// | gs://)
   │  spark.read.text(wholetext, pathGlobFilter=*.py, recursiveFileLookup)
   ▼
DataFrame[path, value=whole-file-source]
   │  .rdd.mapPartitions(scan_partition)   ← serverzen.checks.run_file, per executor
   ▼
findings DataFrame[check, severity, path, line, message, confidence, cwe, owasp, atlas]
   │  by_check() · by_severity() · posture_by_path()   → Parquet / Delta / dashboard
   ▼
"worst files across the estate", grouped, graded, queryable
```

## When to use it — and when **not** to

Reach for Spark **only** at estate scale. For a single repo the JVM start-up and
serialization cost dwarf the actual work — just run `serverzen scan .`. Knowing
this is the point, not a caveat:

| Situation | Use |
|---|---|
| One repo, a PR, a pre-commit hook, CI on one project | the **core** CLI / API |
| Thousands of repos, a monorepo, an org-wide estate, a bucket of source | this **Spark** layer |

## Run it

Locally (needs a JDK 8/11/17 on `PATH`):

```bash
pip install 'serverzen[spark]'
python -m serverzen.spark ./path/to/repos --show 25
```

Write the results out as Parquet (then query them from anywhere):

```bash
python -m serverzen.spark ./repos \
  --out findings.parquet --summary-out posture.parquet --min-severity MEDIUM
```

On a cluster, submit it and point at object storage. ServerZEN must be importable
on the **executors** — ship it with `--py-files` (a zip/wheel) or bake it into the
image:

```bash
spark-submit --py-files serverzen.zip -m serverzen.spark \
  s3://acme-src/repos --out s3://acme-sec/out/findings.parquet
```

## Use it from code

```python
from pyspark.sql import SparkSession
from serverzen.spark import scan_paths, posture_by_path, by_check

spark = SparkSession.builder.getOrCreate()
findings = scan_paths(spark, "s3://acme-src/repos").cache()

by_check(findings).show()                 # what's wrong, by class
posture_by_path(findings).show(50, False) # worst files, A–F graded

# group by repo: derive it from the path and aggregate however you like
import pyspark.sql.functions as F
repo = F.regexp_extract("path", r".*/repos/([^/]+)/", 1)
findings.withColumn("repo", repo).groupBy("repo", "severity").count().show()
```

The grade weights and thresholds match `serverzen.report` exactly, so a file's
cluster-side grade equals the one the single-node CLI would give it.

## Learning roadmap (good FDE exercises)

This layer is a deliberate on-ramp to the Spark skills a forward-deployed
engineer uses. Each phase is a self-contained exercise with a clear checkpoint.

- **Phase 1 — distributed scan ✅ (shipped).** `scan_paths` → findings DataFrame,
  `mapPartitions` runner, typed schema, `by_check` / `posture_by_path`, a CLI.
- **Phase 2 — persist & report.** Write findings to **Delta/Parquet**, partition by
  `severity` (or date), and build a couple of dashboard queries ("new HIGHs this
  week", "worst 20 repos"). *Checkpoint:* a Parquet/Delta table + 3 saved queries.
- **Phase 3 — incremental / streaming.** Re-scan only changed files; then a
  **Structured Streaming** job that scans files as they land in a watched prefix.
  *Checkpoint:* a streaming query writing findings continuously.
- **Phase 4 — performance.** Handle **skew** (one 2 MB generated file in a
  partition of tiny ones), **broadcast** the safe-marker set, and compare
  `mapPartitions` vs an **Arrow `mapInPandas`** runner on a big tree. *Checkpoint:*
  a short before/after timing note.
- **Phase 5 — productionise.** Run it on a real cluster (EMR / Dataproc /
  Databricks / Glue), read from object storage, package ServerZEN for the
  executors, and schedule it. *Checkpoint:* a scheduled job writing to a table.

## Design rules (same as the core)

1. **Spark is an optional extra, never a core dependency** — the fast path stays
   stdlib-only and offline.
2. **Never send scanned code off the cluster** — the whole point of running *in*
   the client's Spark environment is that their source never leaves it.
3. **The distributed logic stays pure and testable** — `scan_partition` is plain
   Python; the Spark wiring is thin.
