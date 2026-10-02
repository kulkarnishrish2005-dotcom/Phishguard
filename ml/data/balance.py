"""Class imbalance handling for dataset splits."""

from __future__ import annotations

import logging
import random

from .schema import Sample, SplitType

logger = logging.getLogger(__name__)


class ClassBalancer:
    """Balance training set classes while preserving natural test distribution."""

    def __init__(self, target_ratio: float = 0.20, random_seed: int = 42) -> None:
        """Initialize class balancer.

        Parameters
        ----------
        target_ratio : float
            Target ratio of phishing to total (default: 0.20, i.e., 1:4 phishing:benign)
        random_seed : int
            Random seed for reproducibility
        """
        self.target_ratio = target_ratio
        self.random_seed = random_seed
        self.rng = random.Random(random_seed)

    def balance_training_set(
        self, train_samples: list[Sample]
    ) -> tuple[list[Sample], list[Sample]]:
        """Balance training set to target ratio via undersampling.

        Process:
        1. Separate phishing and benign samples
        2. Discover actual counts at runtime (no hardcoding)
        3. Compute target benign count: n_benign_target = n_phishing * 4
        4. Subsample benign samples to target count
        5. Return balanced training set and archived benign samples

        Parameters
        ----------
        train_samples : list[Sample]
            Original training samples

        Returns
        -------
        Tuple[list[Sample], list[Sample]]
            (balanced_train_samples, archived_benign_samples)
        """
        logger.info("Balancing training set to 1:4 ratio (target: %.1f%% phishing)", self.target_ratio * 100)

        # Separate classes
        phishing = [s for s in train_samples if s.label == "phishing"]
        benign = [s for s in train_samples if s.label == "benign"]

        n_phishing = len(phishing)
        n_benign = len(benign)

        logger.info(
            "Original training set: %d phishing, %d benign (ratio 1:%.1f)",
            n_phishing,
            n_benign,
            n_benign / n_phishing if n_phishing > 0 else 0,
        )

        if n_phishing == 0:
            logger.warning("No phishing samples in training set, cannot balance")
            return train_samples, []

        # Target 1:4 ratio (phishing:benign = 1:4)
        target_benign_count = n_phishing * 4

        if n_benign <= target_benign_count:
            logger.info("Benign count (%d) <= target (%d), no undersampling needed", n_benign, target_benign_count)
            return train_samples, []

        # Undersample benign class
        logger.info(
            "Undersampling benign class from %d to %d (archiving %d samples)",
            n_benign,
            target_benign_count,
            n_benign - target_benign_count,
        )

        # Deterministic shuffle
        benign_shuffled = benign.copy()
        self.rng.shuffle(benign_shuffled)

        # Split into kept and archived
        kept_benign = benign_shuffled[:target_benign_count]
        archived_benign = benign_shuffled[target_benign_count:]

        # Mark archived samples
        for s in archived_benign:
            s.split = SplitType.ARCHIVE.value

        # Combine kept samples
        balanced_train = phishing + kept_benign

        # Deterministic shuffle of final training set
        self.rng.shuffle(balanced_train)

        final_phishing = len(phishing)
        final_benign = len(kept_benign)

        logger.info(
            "Balanced training set: %d phishing, %d benign (ratio 1:%.1f, %.1f%% phishing)",
            final_phishing,
            final_benign,
            final_benign / final_phishing if final_phishing > 0 else 0,
            100 * final_phishing / len(balanced_train),
        )

        return balanced_train, archived_benign

    def compute_class_weights(self, samples: list[Sample]) -> dict[str, float]:
        """Compute class weights for model training.

        Uses the standard formula:
        weight_class = n_samples / (n_classes * n_samples_class)

        Parameters
        ----------
        samples : list[Sample]
            Samples to compute weights from

        Returns
        -------
        dict[str, float]
            Mapping of label -> weight
        """
        n_total = len(samples)
        if n_total == 0:
            return {"phishing": 1.0, "benign": 1.0}

        n_phishing = sum(1 for s in samples if s.label == "phishing")
        n_benign = sum(1 for s in samples if s.label == "benign")

        if n_phishing == 0 or n_benign == 0:
            return {"phishing": 1.0, "benign": 1.0}

        # Standard scikit-learn class weight formula
        weight_phishing = n_total / (2.0 * n_phishing)
        weight_benign = n_total / (2.0 * n_benign)

        logger.info(
            "Computed class weights: phishing=%.2f, benign=%.2f",
            weight_phishing,
            weight_benign,
        )

        return {"phishing": weight_phishing, "benign": weight_benign}
