"""CLI entry point for URL feature extraction.

Transforms Phase 1A processed URL datasets into feature datasets.

Usage
-----
    # Feature-extract the whole processed directory
    python -m ml.features.cli_extract \
        --input data/processed/train.jsonl \
        --output data/features/train.jsonl

    # Full pipeline: train + val + test + archive
    python -m ml.features.cli_extract \
        --input data/processed --output data/features
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from ml.features.schema import SCHEMA_VERSION, FeatureRecord, get_schema_info
from ml.features.url_features import URLFeatureExtractor

logger = logging.getLogger(__name__)


def _sample_from_line(line: str) -> dict[str, Any]:
    """Load a single JSONL sample line."""
    data = json.loads(line)
    if isinstance(data, dict):
        return data
    return {}


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="PhishGuard URL Feature Extraction (Phase 1B)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to Phase 1A processed JSONL file or directory",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output directory / file for feature JSONL data",
    )
    parser.add_argument(
        "--field-url",
        default="normalized_input",
        help="JSON field name containing the URL in input records",
    )
    parser.add_argument(
        "--field-sample-id",
        default="sample_id",
        help="JSON field name containing the sample ID",
    )
    parser.add_argument(
        "--field-split",
        default="split",
        help="JSON field name containing the split tag",
    )
    parser.add_argument(
        "--field-label",
        default="label",
        help="JSON field name containing the label",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Batch size for processing (default: 1000)",
    )
    parser.add_argument(
        "--show-schema-info",
        action="store_true",
        help="Print schema info and exit",
    )

    args = parser.parse_args(argv)

    # Schema-info requested?
    if args.show_schema_info:
        info = get_schema_info()
        print(json.dumps(info, indent=2))
        return 0

    # Build extractor
    extractor = URLFeatureExtractor(schema_version=SCHEMA_VERSION)

    # Load input
    input_path = args.input

    # Determine if input is a directory or a file
    input_files: list[Path]
    if input_path.is_dir():
        input_files = sorted(input_path.glob("*.jsonl"))
        if not input_files:
            logger.error("No .jsonl files found in %s", input_path)
            print(
                f"Error: No .jsonl files found in {input_path}", file=sys.stderr
            )
            return 1
    else:
        input_files = [input_path] if input_path.exists() else []

    # Ensure output dir exists
    out_dir = args.output.parent if args.output.is_dir() else Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Process
    total_processed = 0
    total_failed = 0

    for infile in input_files:
        logger.info("Processing %s", infile)

        try:
            with open(infile, encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            logger.error("Failed to read %s: %s", infile, e)
            continue

        batch_records: list[FeatureRecord] = []
        for idx, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue

            try:
                sample = _sample_from_line(line)

                url = sample.get(args.field_url, "")
                sample_id = sample.get(args.field_sample_id, "")
                split_val = sample.get(args.field_split, None)
                label = sample.get(args.field_label, None)

                # Sanity: skip empty URLs
                if not url or not url.strip():
                    # Still emit a zero-filled record
                    url = url or "<empty>"

                record = extractor.extract(
                    url,
                    sample_id=sample_id,
                    split=split_val,
                    label=label,
                )
                batch_records.append(record)
                total_processed += 1

                # Write batch
                if len(batch_records) >= args.batch_size:
                    _write_records(
                        batch_records, out_dir / f"features_{total_processed}.jsonl"
                    )
                    batch_records = []

            except Exception as e:
                logger.error(
                    "Error processing line %d in %s: %s", idx + 1, infile, e
                )
                total_failed += 1
                continue

        # Flush remaining batch
        if batch_records:
            _write_records(
                batch_records, out_dir / f"features_{total_processed}_final.jsonl"
            )

    # Summary
    print("\n" + "=" * 60)
    print("Feature extraction complete")
    print("=" * 60)
    print(f"Total processed:   {total_processed}")
    print(f"Total failed:      {total_failed}")
    print(f"Schema version:    {SCHEMA_VERSION}")
    print(f"Output:            {args.output}")

    return 0


def _write_records(records: list[FeatureRecord], output_path: Path) -> None:
    """Write *records* as JSONL to *output_path*."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for record in records:
            d = record.to_dict()
            # Ensure features dict is included (already in to_dict)
            f.write(json.dumps(d, ensure_ascii=False) + "\n")


def main() -> None:
    """Entry point for setuptools console_scripts."""
    sys.exit(_main())


if __name__ == "__main__":
    main()
