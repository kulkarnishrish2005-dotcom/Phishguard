"""Deduplication utilities for dataset samples."""

from __future__ import annotations

import logging
from collections import defaultdict

from .schema import Sample
from .utils import compute_structural_fingerprint

logger = logging.getLogger(__name__)


class Deduplicator:
    """Remove exact and near-duplicate samples."""

    def __init__(self, campaign_threshold: int = 100, campaign_sample_size: int = 15) -> None:
        """Initialize deduplicator.

        Parameters
        ----------
        campaign_threshold : int
            If a structural fingerprint has more than this many samples,
            treat as a phishing campaign and subsample
        campaign_sample_size : int
            Number of representatives to keep per campaign
        """
        self.campaign_threshold = campaign_threshold
        self.campaign_sample_size = campaign_sample_size

        # Statistics
        self.tier1_removed = 0  # Exact duplicates
        self.tier2_removed = 0  # Near-duplicates
        self.label_conflicts_removed = 0  # Label disagreements

    def deduplicate_exact(self, samples: list[Sample]) -> list[Sample]:
        """Remove exact duplicates based on normalized_input hash.

        Tier 1: Exact duplicate detection.

        If multiple samples have the same normalized_input:
        - If labels disagree: discard all (label noise)
        - If labels agree: keep the one with highest label_confidence,
          or earliest timestamp if confidence is equal

        Parameters
        ----------
        samples : list[Sample]
            Samples to deduplicate

        Returns
        -------
        list[Sample]
            Deduplicated samples
        """
        logger.info("Tier 1: Removing exact duplicates")

        # Group by hash of normalized_input
        hash_groups: dict[str, list[Sample]] = defaultdict(list)
        for sample in samples:
            content_hash = sample.compute_hash()
            hash_groups[content_hash].append(sample)

        deduplicated: list[Sample] = []

        for content_hash, group in hash_groups.items():
            if len(group) == 1:
                # No duplicates
                deduplicated.append(group[0])
                continue

            # Check for label conflicts
            labels = {s.label for s in group}
            if len(labels) > 1:
                # Label disagreement - discard all
                logger.warning(
                    "Label conflict for hash %s: %s (discarding %d samples)",
                    content_hash[:8],
                    labels,
                    len(group),
                )
                self.label_conflicts_removed += len(group)
                continue

            # Labels agree - keep best representative
            # Sort by confidence (desc), then timestamp (asc for earliest)
            group_sorted = sorted(
                group,
                key=lambda s: (
                    -s.label_confidence,
                    s.timestamp if s.timestamp else s.ingestion_time,
                ),
            )
            deduplicated.append(group_sorted[0])
            self.tier1_removed += len(group) - 1

        logger.info(
            "Tier 1 complete: %d exact duplicates removed, %d label conflicts discarded",
            self.tier1_removed,
            self.label_conflicts_removed,
        )

        return deduplicated

    def deduplicate_near(self, samples: list[Sample]) -> list[Sample]:
        """Remove near-duplicates using structural fingerprinting.

        Tier 2: Near-duplicate detection (phishing campaigns).

        Groups phishing URLs by structural fingerprint (domain + path structure + query keys).
        If a fingerprint has > campaign_threshold samples, subsample to campaign_sample_size
        representatives, preserving temporal diversity.

        Benign URLs are NOT aggressively deduplicated (more diverse).

        Parameters
        ----------
        samples : list[Sample]
            Samples to deduplicate

        Returns
        -------
        list[Sample]
            Deduplicated samples
        """
        logger.info("Tier 2: Removing near-duplicates (phishing campaigns)")

        # Separate phishing and benign
        phishing_samples = [s for s in samples if s.label == "phishing"]
        benign_samples = [s for s in samples if s.label == "benign"]

        # Group phishing by structural fingerprint
        fingerprint_groups: dict[str, list[Sample]] = defaultdict(list)
        for sample in phishing_samples:
            try:
                fingerprint = compute_structural_fingerprint(sample.normalized_input)
                fingerprint_groups[fingerprint].append(sample)
            except Exception as e:
                logger.warning(
                    "Failed to compute fingerprint for %s: %s",
                    sample.normalized_input[:50],
                    e,
                )
                fingerprint_groups["_error"].append(sample)

        # Subsample large campaigns
        deduplicated_phishing: list[Sample] = []
        for fingerprint, group in fingerprint_groups.items():
            if len(group) <= self.campaign_threshold:
                # Not a campaign, keep all
                deduplicated_phishing.extend(group)
            else:
                # Campaign detected - subsample
                logger.info(
                    "Campaign detected: fingerprint %s has %d samples, subsampling to %d",
                    fingerprint[:8],
                    len(group),
                    self.campaign_sample_size,
                )

                # Sort by timestamp for temporal diversity
                group_sorted = sorted(
                    group,
                    key=lambda s: s.timestamp if s.timestamp else s.ingestion_time,
                )

                # Take evenly spaced samples across temporal range
                if len(group_sorted) <= self.campaign_sample_size:
                    representatives = group_sorted
                else:
                    step = len(group_sorted) / self.campaign_sample_size
                    indices = [int(i * step) for i in range(self.campaign_sample_size)]
                    representatives = [group_sorted[i] for i in indices]

                deduplicated_phishing.extend(representatives)
                self.tier2_removed += len(group) - len(representatives)

        # Combine with benign (not deduplicated at near-duplicate level)
        deduplicated = deduplicated_phishing + benign_samples

        logger.info("Tier 2 complete: %d near-duplicates removed", self.tier2_removed)

        return deduplicated

    def get_stats(self) -> dict[str, int]:
        """Get deduplication statistics.

        Returns
        -------
        dict[str, int]
            Statistics dictionary
        """
        return {
            "tier1_exact_duplicates_removed": self.tier1_removed,
            "tier2_near_duplicates_removed": self.tier2_removed,
            "label_conflicts_discarded": self.label_conflicts_removed,
        }
