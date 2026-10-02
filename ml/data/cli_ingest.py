"""Command-line interface for dataset ingestion pipeline."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from ml.data.pipeline import DatasetPipeline
from phishguard.config import get_config
from phishguard.logging import setup_logging


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="PhishGuard Dataset Ingestion Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  python -m ml.data.cli_ingest --phishtank data/raw/phishtank.csv --tranco data/raw/tranco.csv

  # With metadata
  python -m ml.data.cli_ingest \\
    --phishtank data/raw/phishtank.csv \\
    --phishtank-version 2026-08-29 \\
    --tranco data/raw/tranco.csv \\
    --tranco-list-id XYZ123 \\
    --output data/processed
        """,
    )

    parser.add_argument(
        "--phishtank",
        type=Path,
        required=True,
        help="Path to PhishTank CSV file",
    )

    parser.add_argument(
        "--phishtank-version",
        type=str,
        help="PhishTank version ID (e.g., date)",
    )

    parser.add_argument(
        "--tranco",
        type=Path,
        required=True,
        help="Path to Tranco CSV file",
    )

    parser.add_argument(
        "--tranco-list-id",
        type=str,
        help="Tranco list ID",
    )

    parser.add_argument(
        "--tranco-list-date",
        type=str,
        help="Tranco list publication date (ISO format: YYYY-MM-DD)",
    )

    parser.add_argument(
        "--output",
        type=Path,
        help="Output directory for processed datasets (default: from config)",
    )

    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Setup logging
    setup_logging(level=args.log_level)

    # Validate input files
    if not args.phishtank.exists():
        print(f"Error: PhishTank file not found: {args.phishtank}", file=sys.stderr)
        return 1

    if not args.tranco.exists():
        print(f"Error: Tranco file not found: {args.tranco}", file=sys.stderr)
        return 1

    # Parse optional date
    tranco_list_date = None
    if args.tranco_list_date:
        try:
            tranco_list_date = datetime.fromisoformat(args.tranco_list_date)
        except ValueError:
            print(
                f"Error: Invalid date format for --tranco-list-date: {args.tranco_list_date}",
                file=sys.stderr,
            )
            print("Expected format: YYYY-MM-DD", file=sys.stderr)
            return 1

    # Load config
    config = get_config()

    # Initialize pipeline
    pipeline = DatasetPipeline(config)

    try:
        # Run pipeline
        manifest_path = pipeline.run(
            phishtank_file=args.phishtank,
            tranco_file=args.tranco,
            phishtank_version=args.phishtank_version,
            tranco_list_id=args.tranco_list_id,
            tranco_list_date=tranco_list_date,
            output_dir=args.output,
        )

        print("\n" + "=" * 60)
        print("SUCCESS: Dataset ingestion complete")
        print("=" * 60)
        print(f"Manifest: {manifest_path}")
        print("\nGenerated files:")
        output_dir = args.output or config.data_dir / "processed"

        for split in ["train", "val", "test", "archive"]:
            split_file = output_dir / f"{split}.jsonl"
            if split_file.exists():
                print(f"  {split_file}")

        return 0

    except Exception as e:
        print(f"\nERROR: Pipeline failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
