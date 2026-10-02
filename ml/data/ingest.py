"""Source-specific ingesters for PhishTank and Tranco datasets."""

from __future__ import annotations

import csv
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from phishguard.types import InputType

from .schema import Sample, SourceMetadata
from .utils import extract_registrable_domain, normalize_url

logger = logging.getLogger(__name__)


class PhishTankIngester:
    """Ingest PhishTank verified phishing URLs.

    Expected CSV format:
    - phish_id
    - url
    - phish_detail_url
    - submission_time
    - verified
    - verification_time
    - online
    - target
    """

    SOURCE_NAME = "phishtank"
    SOURCE_TYPE = "phishing_urls"
    SOURCE_URL = "https://www.phishtank.com/developer_info.php"
    LICENSE = "Free for research and non-commercial use with attribution"
    USAGE_TERMS = "Commercial use requires approval"
    LABEL_DEFINITION = "Binary: phishing (positive class). All entries verified by community."

    def __init__(self, verified_only: bool = True, online_only: bool = False) -> None:
        """Initialize PhishTank ingester.

        Parameters
        ----------
        verified_only : bool
            Only include verified entries (recommended: True)
        online_only : bool
            Only include entries that were online at verification (optional: False)
        """
        self.verified_only = verified_only
        self.online_only = online_only

    def ingest(self, raw_file: Path) -> Iterator[Sample]:
        """Ingest PhishTank CSV file.

        Parameters
        ----------
        raw_file : Path
            Path to PhishTank CSV file

        Yields
        ------
        Sample
            Parsed and normalized samples
        """
        logger.info("Ingesting PhishTank data from %s", raw_file)
        ingestion_time = datetime.now(UTC)

        try:
            with open(raw_file, encoding="utf-8") as f:
                reader = csv.DictReader(f)

                for row_num, row in enumerate(reader, start=1):
                    try:
                        # Filter by verification status
                        if self.verified_only and row.get("verified", "").lower() != "yes":
                            continue

                        # Filter by online status (optional)
                        if self.online_only and row.get("online", "").lower() != "yes":
                            continue

                        # Extract required fields
                        phish_id = row.get("phish_id", "")
                        url = row.get("url", "").strip()

                        if not phish_id or not url:
                            logger.warning(
                                "Row %d: missing phish_id or url, skipping", row_num
                            )
                            continue

                        # Parse timestamp (verification_time preferred over submission_time)
                        timestamp = None
                        for time_field in ["verification_time", "submission_time"]:
                            time_str = row.get(time_field, "").strip()
                            if time_str:
                                try:
                                    # PhishTank uses ISO 8601 format
                                    timestamp = datetime.fromisoformat(
                                        time_str.replace("Z", "+00:00")
                                    )
                                    break
                                except (ValueError, AttributeError):
                                    pass

                        # Normalize URL
                        try:
                            normalized = normalize_url(url)
                        except Exception as e:
                            logger.warning(
                                "Row %d: URL normalization failed: %s, skipping", row_num, e
                            )
                            continue

                        # Extract registrable domain
                        domain = extract_registrable_domain(normalized)

                        # Build sample
                        sample = Sample(
                            sample_id=str(uuid4()),
                            source=self.SOURCE_NAME,
                            source_id=phish_id,
                            input_type=InputType.URL,
                            raw_input=url,
                            normalized_input=normalized,
                            label="phishing",
                            label_confidence=1.0,  # Verified entries
                            timestamp=timestamp,
                            ingestion_time=ingestion_time,
                            registrable_domain=domain,
                            metadata={
                                "target": row.get("target", ""),
                                "phish_detail_url": row.get("phish_detail_url", ""),
                                "online": row.get("online", ""),
                            },
                        )

                        yield sample

                    except Exception as e:
                        logger.error("Row %d: unexpected error: %s, skipping", row_num, e)
                        continue

        except FileNotFoundError:
            logger.error("PhishTank file not found: %s", raw_file)
            raise
        except Exception as e:
            logger.error("Failed to read PhishTank file: %s", e)
            raise

    def get_metadata(
        self,
        raw_file: Path,
        retrieval_timestamp: datetime,
        version_id: str | None,
        samples_ingested: int,
        samples_after_validation: int,
        samples_after_deduplication: int,
    ) -> SourceMetadata:
        """Generate source metadata for manifest.

        Parameters
        ----------
        raw_file : Path
            Path to raw file
        retrieval_timestamp : datetime
            When the file was retrieved
        version_id : str | None
            Version identifier (e.g., date)
        samples_ingested : int
            Total samples ingested
        samples_after_validation : int
            Samples remaining after validation
        samples_after_deduplication : int
            Samples remaining after deduplication

        Returns
        -------
        SourceMetadata
            Metadata object for manifest
        """
        from .schema import compute_file_hash

        return SourceMetadata(
            source_name=self.SOURCE_NAME,
            source_type=self.SOURCE_TYPE,
            retrieval_timestamp=retrieval_timestamp,
            source_url=self.SOURCE_URL,
            version_id=version_id,
            format="csv",
            license=self.LICENSE,
            usage_terms=self.USAGE_TERMS,
            label_definition=self.LABEL_DEFINITION,
            raw_file_path=str(raw_file),
            raw_file_hash_sha256=compute_file_hash(raw_file) if raw_file.exists() else None,
            samples_ingested=samples_ingested,
            samples_after_validation=samples_after_validation,
            samples_after_deduplication=samples_after_deduplication,
        )


class TrancoIngester:
    """Ingest Tranco top-ranked domains as benign URLs.

    Expected CSV format:
    - rank (integer)
    - domain (e.g., example.com)
    """

    SOURCE_NAME = "tranco"
    SOURCE_TYPE = "benign_urls"
    SOURCE_URL = "https://tranco-list.eu/"
    LICENSE = "Free for research and commercial use"
    USAGE_TERMS = "No restrictions"
    LABEL_DEFINITION = (
        "Binary: benign (negative class). Assumed benign based on popularity ranking. "
        "Distant supervision - some domains may host phishing on subdomains or compromised pages."
    )

    def __init__(self, top_n: int | None = None) -> None:
        """Initialize Tranco ingester.

        Parameters
        ----------
        top_n : int | None
            Limit to top N domains (None = all)
        """
        self.top_n = top_n

    def ingest(
        self, raw_file: Path, list_date: datetime | None = None
    ) -> Iterator[Sample]:
        """Ingest Tranco CSV file.

        Parameters
        ----------
        raw_file : Path
            Path to Tranco CSV file
        list_date : datetime | None
            Publication date of Tranco list (used as timestamp)

        Yields
        ------
        Sample
            Parsed and normalized samples
        """
        logger.info("Ingesting Tranco data from %s", raw_file)
        ingestion_time = datetime.now(UTC)

        try:
            with open(raw_file, encoding="utf-8") as f:
                reader = csv.reader(f)

                for row_num, row in enumerate(reader, start=1):
                    try:
                        if len(row) < 2:
                            logger.warning("Row %d: insufficient columns, skipping", row_num)
                            continue

                        rank_str, domain = row[0].strip(), row[1].strip()

                        if not rank_str or not domain:
                            logger.warning("Row %d: missing rank or domain, skipping", row_num)
                            continue

                        # Parse rank
                        try:
                            rank = int(rank_str)
                        except ValueError:
                            logger.warning("Row %d: invalid rank '%s', skipping", row_num, rank_str)
                            continue

                        # Limit to top N if specified
                        if self.top_n and rank > self.top_n:
                            break

                        # Convert domain to full URL
                        url = f"https://{domain}/"

                        # Normalize URL
                        try:
                            normalized = normalize_url(url)
                        except Exception as e:
                            logger.warning(
                                "Row %d: URL normalization failed: %s, skipping", row_num, e
                            )
                            continue

                        # Extract registrable domain
                        reg_domain = extract_registrable_domain(normalized)

                        # Build sample
                        sample = Sample(
                            sample_id=str(uuid4()),
                            source=self.SOURCE_NAME,
                            source_id=f"tranco_rank_{rank}",
                            input_type=InputType.URL,
                            raw_input=url,
                            normalized_input=normalized,
                            label="benign",
                            label_confidence=0.9,  # Distant supervision
                            timestamp=list_date,
                            ingestion_time=ingestion_time,
                            registrable_domain=reg_domain,
                            metadata={"rank": rank},
                        )

                        yield sample

                    except Exception as e:
                        logger.error("Row %d: unexpected error: %s, skipping", row_num, e)
                        continue

        except FileNotFoundError:
            logger.error("Tranco file not found: %s", raw_file)
            raise
        except Exception as e:
            logger.error("Failed to read Tranco file: %s", e)
            raise

    def get_metadata(
        self,
        raw_file: Path,
        retrieval_timestamp: datetime,
        list_id: str | None,
        list_date: datetime | None,
        samples_ingested: int,
        samples_after_validation: int,
        samples_after_deduplication: int,
    ) -> SourceMetadata:
        """Generate source metadata for manifest.

        Parameters
        ----------
        raw_file : Path
            Path to raw file
        retrieval_timestamp : datetime
            When the file was retrieved
        list_id : str | None
            Tranco list ID
        list_date : datetime | None
            Tranco list publication date
        samples_ingested : int
            Total samples ingested
        samples_after_validation : int
            Samples remaining after validation
        samples_after_deduplication : int
            Samples remaining after deduplication

        Returns
        -------
        SourceMetadata
            Metadata object for manifest
        """
        from .schema import compute_file_hash

        version_info = list_id or (list_date.date().isoformat() if list_date else None)

        return SourceMetadata(
            source_name=self.SOURCE_NAME,
            source_type=self.SOURCE_TYPE,
            retrieval_timestamp=retrieval_timestamp,
            source_url=self.SOURCE_URL,
            version_id=version_info,
            format="csv",
            license=self.LICENSE,
            usage_terms=self.USAGE_TERMS,
            label_definition=self.LABEL_DEFINITION,
            raw_file_path=str(raw_file),
            raw_file_hash_sha256=compute_file_hash(raw_file) if raw_file.exists() else None,
            samples_ingested=samples_ingested,
            samples_after_validation=samples_after_validation,
            samples_after_deduplication=samples_after_deduplication,
        )
