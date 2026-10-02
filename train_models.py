"""Train ML models for PhishGuard phishing detection - synthetic demo data."""

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, roc_auc_score, precision_recall_curve, auc
import joblib
import json
import xgboost as xgb


def main():
    np.random.seed(42)
    n_samples = 1000

    # Generate 42 features matching Phase 1B schema
    url_length = np.random.normal(80, 30, n_samples).astype(int)
    hostname_length = np.random.normal(25, 15, n_samples).astype(int)
    path_length = np.random.normal(35, 20, n_samples).astype(int)
    query_length = np.random.normal(20, 15, n_samples).astype(int)
    fragment_length = np.random.exponential(5, n_samples).astype(int)
    digit_count = np.random.poisson(8, n_samples)
    digit_ratio = digit_count / (url_length + 1e-8)
    alpha_count = np.random.poisson(50, n_samples)
    alpha_ratio = alpha_count / (url_length + 1e-8)
    special_char_count = np.random.poisson(15, n_samples)
    special_char_ratio = special_char_count / (url_length + 1e-8)
    url_token_count = np.random.poisson(10, n_samples)
    suspicious_keyword_count = np.random.poisson(3, n_samples)
    has_suspicious_keyword = (suspicious_keyword_count > 0).astype(int)

    subdomain_count = np.random.poisson(2, n_samples)
    path_depth = np.random.poisson(4, n_samples)
    query_param_count = np.random.poisson(5, n_samples)
    has_fragment = np.random.binomial(1, 0.3, n_samples).astype(int)
    has_port = np.random.binomial(1, 0.15, n_samples).astype(int)
    is_ip_host = np.random.binomial(1, 0.05, n_samples).astype(int)
    is_https = np.random.binomial(1, 0.7, n_samples).astype(int)
    hostname_token_count = np.random.poisson(3, n_samples)
    path_max_segment_length = np.random.exponential(15, n_samples).astype(int)
    query_max_value_length = np.random.exponential(25, n_samples).astype(int)

    is_punycode = np.random.binomial(1, 0.12, n_samples).astype(int)
    pct_encoded_count = np.random.poisson(6, n_samples)
    pct_encoded_ratio = pct_encoded_count / (url_length + 1e-8)
    has_at_sign = np.random.binomial(1, 0.08, n_samples).astype(int)
    has_double_slash_redirect = np.random.binomial(1, 0.05, n_samples).astype(int)
    has_hex_encoding_in_host = np.random.binomial(1, 0.04, n_samples).astype(int)
    hostname_entropy = np.random.normal(3.5, 1.0, n_samples)
    hostname_consonant_ratio = np.random.uniform(0.3, 0.8, n_samples)
    hostname_digit_ratio = np.random.uniform(0.0, 0.4, n_samples)
    has_shortener_pattern = np.random.binomial(1, 0.06, n_samples).astype(int)
    has_data_uri = np.random.binomial(1, 0.02, n_samples).astype(int)

    tld = np.random.choice([1, 2, 3, 4, 5], n_samples)
    tld_length = np.random.randint(2, 8, n_samples)
    registrable_domain_length = np.random.randint(8, 35, n_samples)
    domain_token_count = np.random.poisson(2, n_samples)
    domain_has_hyphen = np.random.binomial(1, 0.25, n_samples).astype(int)
    domain_has_digit = np.random.binomial(1, 0.2, n_samples).astype(int)
    subdomain_length = np.random.exponential(12, n_samples).astype(int)

    X = pd.DataFrame({
        'url_length': url_length,
        'hostname_length': hostname_length,
        'path_length': path_length,
        'query_length': query_length,
        'fragment_length': fragment_length,
        'digit_count': digit_count,
        'digit_ratio': digit_ratio,
        'alpha_count': alpha_count,
        'alpha_ratio': alpha_ratio,
        'special_char_count': special_char_count,
        'special_char_ratio': special_char_ratio,
        'url_token_count': url_token_count,
        'suspicious_keyword_count': suspicious_keyword_count,
        'has_suspicious_keyword': has_suspicious_keyword,
        'subdomain_count': subdomain_count,
        'path_depth': path_depth,
        'query_param_count': query_param_count,
        'has_fragment': has_fragment,
        'has_port': has_port,
        'is_ip_host': is_ip_host,
        'is_https': is_https,
        'hostname_token_count': hostname_token_count,
        'path_max_segment_length': path_max_segment_length,
        'query_max_value_length': query_max_value_length,
        'is_punycode': is_punycode,
        'pct_encoded_count': pct_encoded_count,
        'pct_encoded_ratio': pct_encoded_ratio,
        'has_at_sign': has_at_sign,
        'has_double_slash_redirect': has_double_slash_redirect,
        'has_hex_encoding_in_host': has_hex_encoding_in_host,
        'hostname_entropy': hostname_entropy,
        'hostname_consonant_ratio': hostname_consonant_ratio,
        'hostname_digit_ratio': hostname_digit_ratio,
        'has_shortener_pattern': has_shortener_pattern,
        'has_data_uri': has_data_uri,
        'tld': tld,
        'tld_length': tld_length,
        'registrable_domain_length': registrable_domain_length,
        'domain_token_count': domain_token_count,
        'domain_has_hyphen': domain_has_hyphen,
        'domain_has_digit': domain_has_digit,
        'subdomain_length': subdomain_length,
    })

    # Linear score for phishing signal
    score = (
        0.35 * has_suspicious_keyword +
        0.30 * is_punycode +
        0.25 * is_ip_host +
        0.25 * has_at_sign +
        0.20 * has_shortener_pattern +
        0.20 * has_double_slash_redirect +
        0.15 * domain_has_hyphen +
        0.15 * (subdomain_count > 2).astype(int) +
        0.15 * (hostname_entropy > 3.8).astype(int) +
        0.10 * (digit_ratio > 0.15).astype(int) +
        0.10 * (url_length > 90).astype(int) +
        np.random.normal(0, 0.25, n_samples)
    )

    # Threshold so ~25% are phishing
    threshold = np.percentile(score, 75)
    y = (score >= threshold).astype(int)

    print(f"Dataset: {n_samples} samples, Phishing: {y.sum()} ({y.mean():.1%}), Benign: {(1-y).sum()} ({(1-y).mean():.1%})")

    # Split: train (60%), val (20%), test (20%)
    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.4, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp)

    print(f"Train: {len(X_train)} ({y_train.mean():.1%} phishing)")
    print(f"Val: {len(X_val)} ({y_val.mean():.1%} phishing)")
    print(f"Test: {len(X_test)} ({y_test.mean():.1%} phishing)")

    # ============================================================
    # Model 1: Logistic Regression
    # ============================================================
    print("\n=== Training Logistic Regression ===")
    lr = Pipeline([
        ('scaler', StandardScaler()),
        ('clf', LogisticRegression(max_iter=1000, random_state=42, class_weight='balanced', solver='lbfgs'))
    ])
    lr.fit(X_train, y_train)
    lr_probs = lr.predict_proba(X_test)[:, 1]
    lr_roc_auc = roc_auc_score(y_test, lr_probs)
    precision, recall, _ = precision_recall_curve(y_test, lr_probs)
    lr_pr_auc = auc(recall, precision)
    y_pred = lr.predict(X_test)
    print(f"Test Acc={lr.score(X_test, y_test):.3f}, ROC-AUC={lr_roc_auc:.3f}, PR-AUC={lr_pr_auc:.3f}")
    print(classification_report(y_test, y_pred, target_names=['BENIGN', 'PHISHING']))

    # ============================================================
    # Model 2: Random Forest
    # ============================================================
    print("\n=== Training Random Forest ===")
    rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, class_weight='balanced', n_jobs=-1)
    rf.fit(X_train, y_train)
    rf_probs = rf.predict_proba(X_test)[:, 1]
    rf_roc_auc = roc_auc_score(y_test, rf_probs)
    precision2, recall2, _ = precision_recall_curve(y_test, rf_probs)
    rf_pr_auc = auc(recall2, precision2)
    y_pred_rf = rf.predict(X_test)
    print(f"Test Acc={rf.score(X_test, y_test):.3f}, ROC-AUC={rf_roc_auc:.3f}, PR-AUC={rf_pr_auc:.3f}")
    print(classification_report(y_test, y_pred_rf, target_names=['BENIGN', 'PHISHING']))

    # ============================================================
    # Model 3: XGBoost
    # ============================================================
    print("\n=== Training XGBoost ===")
    xgb_model = xgb.XGBClassifier(
        n_estimators=100, max_depth=6, learning_rate=0.1,
        random_state=42, eval_metric='logloss',
        tree_method='hist'
    )
    xgb_model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)
    xgb_probs = xgb_model.predict_proba(X_test)[:, 1]
    xgb_roc_auc = roc_auc_score(y_test, xgb_probs)
    precision3, recall3, _ = precision_recall_curve(y_test, xgb_probs)
    xgb_pr_auc = auc(recall3, precision3)
    y_pred_xgb = xgb_model.predict(X_test)
    print(f"Test Acc={xgb_model.score(X_test, y_test):.3f}, ROC-AUC={xgb_roc_auc:.3f}, PR-AUC={xgb_pr_auc:.3f}")
    print(classification_report(y_test, y_pred_xgb, target_names=['BENIGN', 'PHISHING']))

    # ============================================================
    # Save all models and metadata
    # ============================================================
    print("\n=== Saving models and artifacts ===")
    import os
    os.makedirs('ml/models', exist_ok=True)

    joblib.dump(lr, 'ml/models/lr_phishguard.pkl')
    joblib.dump(rf, 'ml/models/rf_phishguard.pkl')
    joblib.dump(xgb_model, 'ml/models/xgb_phishguard.pkl')
    print("  - Logistic Regression saved to ml/models/lr_phishguard.pkl")
    print("  - Random Forest saved to ml/models/rf_phishguard.pkl")
    print("  - XGBoost saved to ml/models/xgb_phishguard.pkl")

    feature_definitions = {
        "schema_version": "1.0.0",
        "feature_count": 42,
        "categories": {
            "lexical": 14,
            "structural": 10,
            "obfuscation": 11,
            "domain": 7
        },
        "feature_names": list(X.columns),
    }
    with open('ml/models/schema.json', 'w') as f:
        json.dump(feature_definitions, f, indent=2)
    print("  - Schema saved (42 features, 4 categories)")

    class_info = {
        "positive_class": "phishing",
        "negative_class": "benign",
        "train_phishing_count": int(y_train.sum()),
        "train_benign_count": int((1 - y_train).sum()),
        "train_ratio": f"{int(y_train.sum())}:{int((1-y_train).sum())}",
        "test_phishing_count": int(y_test.sum()),
        "test_benign_count": int((1 - y_test).sum()),
        "test_ratio": f"Natural: {y_test.mean():.1%} phishing / {(1 - y_test).mean():.1%} benign",
        "metrics": {
            "logistic_regression": {
                "test_accuracy": float(lr.score(X_test, y_test)),
                "roc_auc": float(lr_roc_auc),
                "pr_auc": float(lr_pr_auc)
            },
            "random_forest": {
                "test_accuracy": float(rf.score(X_test, y_test)),
                "roc_auc": float(rf_roc_auc),
                "pr_auc": float(rf_pr_auc)
            },
            "xgboost": {
                "test_accuracy": float(xgb_model.score(X_test, y_test)),
                "roc_auc": float(xgb_roc_auc),
                "pr_auc": float(xgb_pr_auc)
            }
        }
    }
    with open('ml/models/class_info.json', 'w') as f:
        json.dump(class_info, f, indent=2)
    print("  - Class info and actual metrics saved to ml/models/class_info.json")

    print("\nAll models and artifacts saved successfully!")


if __name__ == "__main__":
    main()
