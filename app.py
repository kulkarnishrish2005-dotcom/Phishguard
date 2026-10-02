"""PhishGuard Local Demonstration Web UI.

Streamlit-based local prototype for URL, Text/Email, and Screenshot OCR phishing analysis.
URL analysis does not fetch submitted URLs; OCR dependencies may retrieve missing model files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from PIL import Image
import streamlit as st

from ml.features.schema import FEATURE_CATEGORIES, FEATURE_DEFINITIONS, SCHEMA_VERSION
from ml.inference.risk_engine import evaluate_risk
from ml.inference.url_inference import URLInferenceEngine
from phishguard.unified_result import UnifiedAnalysisResult
from services.nlp.text_detector import TextPhishingDetector
from services.ocr.ocr_service import ScreenshotOCRAnalyzer

# Page configuration
st.set_page_config(
    page_title="PhishGuard | Analysis Console",
    page_icon=str(Path(__file__).resolve().parent / "assets" / "phishguard-favicon.png"),
    layout="wide",
    initial_sidebar_state="expanded",
)

# Application styling
st.markdown("""
<style>
:root {
    color-scheme: dark;
    --pg-bg: #121514;
    --pg-panel: #1a1d1a;
    --pg-panel-raised: #242824;
    --pg-border: #353b36;
    --pg-text: #e6ece6;
    --pg-muted: #a3aca4;
    --pg-accent: #45c6a0;
    --pg-danger: #ef6b73;
}
html, body, [data-testid="stAppViewContainer"] {
    background: var(--pg-bg);
    color: var(--pg-text);
    font-family: "Bahnschrift", "Segoe UI Variable", "Segoe UI", sans-serif;
}
[data-testid="stHeader"] {
    background: var(--pg-bg);
}
[data-testid="stSidebar"] {
    background: var(--pg-panel);
    border-right: 1px solid var(--pg-border);
    width: 300px !important;
    min-width: 300px !important;
}
[data-testid="stMainBlockContainer"] {
    max-width: 1500px;
    padding-top: 2rem;
}
h1, h2, h3, h4, h5 {
    color: var(--pg-text);
    font-family: "Bahnschrift", "Segoe UI Variable", "Segoe UI", sans-serif;
    font-weight: 650;
}
p, li, label, [data-testid="stCaptionContainer"] {
    color: var(--pg-muted);
}
.sidebar-brand {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 2px 0 22px;
    border-bottom: 1px solid var(--pg-border);
    margin-bottom: 22px;
}
.brand-mark {
    display: grid;
    place-items: center;
    width: 38px;
    height: 38px;
    border: 1px solid var(--pg-accent);
    border-radius: 3px;
    color: var(--pg-accent);
    font: 700 13px "Cascadia Code", Consolas, monospace;
    letter-spacing: 0;
}
.brand-name {
    color: var(--pg-text);
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 0;
}
.brand-detail {
    color: var(--pg-muted);
    display: block;
    font: 10px "Cascadia Code", Consolas, monospace;
    margin-top: 3px;
}
.main-header {
    align-items: baseline;
    border-bottom: 1px solid var(--pg-border);
    color: var(--pg-text);
    display: flex;
    flex-wrap: wrap;
    font-size: 1.7rem;
    font-weight: 700;
    gap: 10px;
    margin-bottom: 0.5rem;
    padding-bottom: 18px;
}
.sub-header {
    color: var(--pg-muted);
    font-size: 0.98rem;
    margin: 0.4rem 0 1.5rem;
}
.badge-safe {
    background-color: #17352f;
    border: 1px solid #286c5c;
    color: #78d9bf;
    padding: 5px 9px;
    border-radius: 2px;
	font-weight: 700;
    font-size: 0.9rem;
	display: inline-block;
}
.badge-suspicious {
    background-color: #3b3120;
    border: 1px solid #77613b;
    color: #e9c47c;
    padding: 5px 9px;
    border-radius: 2px;
	font-weight: 700;
    font-size: 0.9rem;
	display: inline-block;
}
.badge-phishing {
    background-color: #3d2429;
    border: 1px solid #82434b;
    color: #ff9098;
    padding: 5px 9px;
    border-radius: 2px;
	font-weight: 700;
    font-size: 0.9rem;
	display: inline-block;
}
[data-testid="stTabs"] [role="tablist"] {
    border-bottom: 1px solid var(--pg-border);
}
[data-testid="stTabs"] button[role="tab"] {
    border-radius: 2px 2px 0 0;
    color: var(--pg-muted);
    font-weight: 600;
}
[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
    border-bottom-color: var(--pg-accent);
    color: var(--pg-text);
}
[data-testid="stButton"] button {
    background: var(--pg-panel-raised);
    border: 1px solid #48514a;
    border-radius: 3px;
    color: var(--pg-text);
    font-weight: 600;
    white-space: nowrap;
}
[data-testid="stButton"] button:hover {
    border-color: var(--pg-accent);
    color: var(--pg-accent);
}
[data-testid="stTextInput"] input, [data-testid="stTextArea"] textarea,
[data-testid="stSelectbox"] [data-baseweb="select"] > div {
    background: #151916;
    border-color: #48514a;
    border-radius: 3px;
    color: var(--pg-text);
}
[data-testid="stMetric"] {
    background: transparent;
    border-left: 2px solid var(--pg-border);
    padding: 4px 12px;
}
[data-testid="stMetricLabel"] p {
    color: var(--pg-muted);
}
[data-testid="stMetricValue"] {
    color: var(--pg-text);
}
[data-testid="stAlert"] {
    background: var(--pg-panel);
    border: 1px solid var(--pg-border);
    border-radius: 3px;
}
[data-testid="stExpander"] {
    border: 1px solid var(--pg-border);
    border-radius: 3px;
}
code, pre, [data-testid="stJson"] {
    font-family: "Cascadia Code", Consolas, monospace;
}
@media (max-width: 700px) {
    [data-testid="stMainBlockContainer"] {
        padding: 1.2rem 1rem 2rem;
    }
    .main-header {
        font-size: 1.35rem;
    }
}
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def load_engines():
    """Load core ML and service engines."""
    url_engine = URLInferenceEngine()
    nlp_engine = TextPhishingDetector()
    ocr_engine = ScreenshotOCRAnalyzer()
    return url_engine, nlp_engine, ocr_engine


@st.cache_data
def load_demo_data():
    """Load sample demo records."""
    demo_dir = Path(__file__).resolve().parent / "data" / "demo"
    urls_file = demo_dir / "urls.json"
    emails_file = demo_dir / "emails.json"

    urls_data = []
    emails_data = []
    if urls_file.exists():
        with open(urls_file, "r", encoding="utf-8") as f:
            urls_data = json.load(f)
    if emails_file.exists():
        with open(emails_file, "r", encoding="utf-8") as f:
            emails_data = json.load(f)
    return urls_data, emails_data


def render_verdict_badge(verdict: str):
    """Render colored verdict badge."""
    v_upper = verdict.upper()
    if "SAFE" in v_upper:
        st.markdown(f'<span class="badge-safe">VERDICT: SAFE</span>', unsafe_allow_html=True)
    elif "SUSPICIOUS" in v_upper:
        st.markdown(f'<span class="badge-suspicious">VERDICT: SUSPICIOUS</span>', unsafe_allow_html=True)
    else:
        st.markdown(f'<span class="badge-phishing">VERDICT: PHISHING</span>', unsafe_allow_html=True)


def render_evidence_table(evidence_list):
    """Render structured evidence items."""
    if not evidence_list:
        st.info("No notable threat indicators detected.")
        return

    st.markdown("#### Supporting Security Evidence")
    for idx, item in enumerate(evidence_list, 1):
        indicator = item.get("indicator", "") if isinstance(item, dict) else item.indicator
        desc = item.get("description", "") if isinstance(item, dict) else item.description
        weight = item.get("weight", 0.0) if isinstance(item, dict) else item.weight

        st.markdown(f"**{indicator.replace('_', ' ').title()}** (`weight: {weight:.2f}`)")
        st.markdown(f"&nbsp;&nbsp;&nbsp;&nbsp;↳ *{desc}*")


def main():
    url_engine, nlp_engine, ocr_engine = load_engines()
    demo_urls, demo_emails = load_demo_data()

    # Sidebar Information
    with st.sidebar:
        st.markdown(
            '<div class="sidebar-brand"><span class="brand-mark">PG</span>'
            '<span><span class="brand-name">PHISHGUARD</span>'
            '<span class="brand-detail">THREAT ANALYSIS</span></span></div>',
            unsafe_allow_html=True,
        )
        st.markdown("### Analysis modules")
        st.markdown(
            "URL classification with 42 engineered features, rule-based message analysis, "
            "and screenshot OCR with evidence-based risk assessment."
        )
        st.markdown("---")

        st.markdown("### URL classifier")
        selected_model = st.selectbox(
            "Model",
            ["random_forest", "xgboost", "logistic_regression"],
            index=0,
            format_func=lambda x: {
                "random_forest": "Random Forest",
                "xgboost": "XGBoost",
                "logistic_regression": "Logistic Regression (L2)",
            }[x],
        )

        st.markdown("---")
        st.caption("VERSION 0.1.0 | Research prototype")

    # Header
    st.markdown(
        '<div class="main-header"><span>PhishGuard</span><span>/</span>'
        '<span>Analysis console</span></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
    '<div class="sub-header">URL, email, and screenshot analysis with evidence-based risk assessment.</div>',
    unsafe_allow_html=True,
    )

    tabs = st.tabs([
        "URL Analysis",
        "Text / Email Analysis",
        "Screenshot OCR Analysis",
        "System & Metrics",
        "Privacy Policy",
        "Terms & Conditions",
    ])

    # =========================================================================
    # TAB 1: URL ANALYSIS
    # =========================================================================
    with tabs[0]:
        st.markdown("### URL Structural ML Analysis")
        st.caption("Operates exclusively on 42 deterministic URL string features without network resolution.")

        # Preset selector
        if demo_urls:
            url_options = ["-- Custom URL Input --"] + [f"[{item['category']}] {item['url']}" for item in demo_urls]
            selected_url_preset = st.selectbox("Select a benchmark sample or enter your own:", url_options)
            if selected_url_preset != "-- Custom URL Input --":
                preset_idx = url_options.index(selected_url_preset) - 1
                default_url_val = demo_urls[preset_idx]["url"]
            else:
                default_url_val = "http://login.paypal.account-verification.secure-auth-gateway.com/signin?user=auth_token"
        else:
            default_url_val = "https://example.com"

        input_url = st.text_input("Enter URL to analyze:", value=default_url_val)

        col_btn, _ = st.columns([1, 4])
        with col_btn:
            analyze_url_btn = st.button("Analyze URL", key="btn_url", width="stretch")

        if analyze_url_btn and input_url:
            with st.spinner("Extracting 42 features & computing inference..."):
                pred = url_engine.predict(input_url, model_name=selected_model)
                risk = evaluate_risk(pred.features, pred.probability, pred.model_name)
                unified = UnifiedAnalysisResult.from_url_prediction(pred, risk)

            st.markdown("---")

            # Result Header Row
            col1, col2, col3, col4 = st.columns([2, 2, 2, 2])
            with col1:
                render_verdict_badge(risk.verdict)
            with col2:
                st.metric(
                    label="Threat Risk Score",
                    value=f"{risk.risk_score} / 100",
                    delta="HIGH RISK" if risk.risk_score >= 65 else ("MEDIUM" if risk.risk_score >= 35 else "LOW RISK"),
                    delta_color="inverse" if risk.risk_score >= 35 else "normal",
                )
            with col3:
                st.metric(
                    label=f"ML Probability ({pred.model_name})",
                    value=f"{pred.probability:.1%}",
                    help="Statistical probability of positive (phishing) class from the ML classifier.",
                )
            with col4:
                st.metric(
                    label="Extracted Features",
                    value=f"{len(pred.features)} features",
                    help="42 features across Lexical, Structural, Obfuscation, and Domain categories.",
                )

            st.info(f" **Assessment Summary:** {risk.summary}")

            # Two-column layout: Evidence & Feature Breakdown
            col_ev, col_feat = st.columns([1, 1])

            with col_ev:
                render_evidence_table(risk.evidence)

            with col_feat:
                st.markdown("#### Key Extracted Features")
                key_feat_names = [
                    "is_ip_host", "is_punycode", "has_at_sign", "has_double_slash_redirect",
                    "has_suspicious_keyword", "suspicious_keyword_count", "subdomain_count",
                    "path_depth", "has_port", "hostname_entropy", "url_length",
                    "domain_has_hyphen", "has_shortener_pattern", "registrable_domain_length"
                ]
                feat_display = {k: pred.features.get(k) for k in key_feat_names if k in pred.features}
                st.json(feat_display)
                with st.expander("View all 42 extracted features"):
                    st.json(pred.features)
                with st.expander(" View Unified JSON Output"):
                    st.json(unified.to_dict())
        elif analyze_url_btn:
            st.warning("Enter a URL before starting analysis.")

    # =========================================================================
    # TAB 2: TEXT / EMAIL ANALYSIS
    # =========================================================================
    with tabs[1]:
        st.markdown("### Email / Message NLP Analysis")
        st.caption("Evaluates text for urgency tactics, credential harvesting lures, and financial social engineering patterns.")

        if demo_emails:
            email_options = ["-- Custom Message Input --"] + [f"[{item['category']}] {item['title']}" for item in demo_emails]
            selected_email_preset = st.selectbox("Select a benchmark email or enter your own:", email_options)
            if selected_email_preset != "-- Custom Message Input --":
                preset_idx = email_options.index(selected_email_preset) - 1
                default_text_val = demo_emails[preset_idx]["text"]
            else:
                default_text_val = "Subject: URGENT: Verify your account immediately\n\nPlease login within 24 hours to prevent account suspension:\nhttp://login.microsoft.security-verify.evil-portal.com/auth"
        else:
            default_text_val = "Enter email text here..."

        input_text = st.text_area("Email / Message Body:", value=default_text_val, height=180)

        col_btn2, _ = st.columns([1, 4])
        with col_btn2:
            analyze_text_btn = st.button("Analyze Text", key="btn_text", width="stretch")

        if analyze_text_btn and input_text:
            with st.spinner("Analyzing semantic and lexical indicators..."):
                text_res = nlp_engine.detect(input_text)
                unified_text = UnifiedAnalysisResult.from_text_result(text_res)

            st.markdown("---")

            col1, col2, col3, col4 = st.columns([2, 2, 2, 2])
            with col1:
                render_verdict_badge(text_res.threat_level.value)
            with col2:
                st.metric(
                    label="Threat Risk Score",
                    value=f"{text_res.risk_score} / 100",
                    delta="HIGH" if text_res.risk_score >= 60 else ("MEDIUM" if text_res.risk_score >= 30 else "LOW"),
                    delta_color="inverse" if text_res.risk_score >= 30 else "normal",
                )
            with col3:
                st.metric(
                    label="Urgency Pressure",
                    value=f"{text_res.urgency_score:.2f}",
                    help="Score reflecting artificial deadlines and threat of consequences.",
                )
            with col4:
                st.metric(
                    label="Credential Request",
                    value=f"{text_res.credential_harvesting_score:.2f}",
                    help="Score reflecting requests for credentials, passwords, or PII.",
                )

            st.info(f" **Assessment Summary:** {text_res.summary}")

            col_t_ev, col_t_urls = st.columns([1, 1])

            with col_t_ev:
                render_evidence_table(text_res.evidence)

            with col_t_urls:
                st.markdown("#### Extracted URLs & Auto-Analysis")
                if text_res.found_urls:
                    for url in text_res.found_urls:
                        with st.expander(f"URL: {url[:50]}...", expanded=True):
                            u_pred = url_engine.predict(url, model_name=selected_model)
                            u_risk = evaluate_risk(u_pred.features, u_pred.probability, u_pred.model_name)
                            st.markdown(f"**Verdict:** `{u_risk.verdict}` | **Risk Score:** `{u_risk.risk_score}/100` | **Model Prob:** `{u_pred.probability:.1%}`")
                            st.markdown(f"*{u_risk.summary}*")
                else:
                    st.write("No embedded URLs found in message body.")

            with st.expander(" View Unified JSON Output"):
                st.json(unified_text.to_dict())
        elif analyze_text_btn:
            st.warning("Enter message text before starting analysis.")

    # TAB 3: SCREENSHOT OCR ANALYSIS
    # =========================================================================
    with tabs[2]:
        st.markdown("### Screenshot OCR Analysis Pipeline")
        st.caption("Extracts visual text using local OCR and pipes results into NLP and URL threat engines.")

        col_up, col_preset = st.columns([1, 1])
        with col_up:
            uploaded_file = st.file_uploader("Upload screenshot image (PNG, JPG):", type=["png", "jpg", "jpeg"])
        with col_preset:
            demo_img_options = [
                "-- Select Demo Screenshot --",
                "Phishing Security Alert (phishing_alert_screenshot.png)",
                "Clean Team Sync (clean_message_screenshot.png)",
            ]
            selected_img_preset = st.selectbox("Or choose a pre-generated demo image:", demo_img_options)

        target_image = None
        img_source_name = "custom_upload"

        demo_dir = Path(__file__).resolve().parent / "data" / "demo"
        if uploaded_file is not None:
            target_image = Image.open(uploaded_file)
            img_source_name = uploaded_file.name
        elif selected_img_preset != "-- Select Demo Screenshot --":
            if "phishing" in selected_img_preset:
                p = demo_dir / "phishing_alert_screenshot.png"
            else:
                p = demo_dir / "clean_message_screenshot.png"
            if p.exists():
                target_image = Image.open(p)
                img_source_name = p.name

        if target_image is not None:
            col_preview, col_proc = st.columns([1, 1])
            with col_preview:
                st.image(target_image, caption=f"Target Screenshot ({img_source_name})", width="stretch")

            with col_proc:
                if st.button("Run OCR & Multimodal Analysis", key="btn_ocr", width="stretch"):
                    with st.spinner("Extracting text via local OCR & evaluating multimodal signals..."):
                        ocr_res = ocr_engine.analyze_screenshot(target_image, source_label=img_source_name)
                        unified_ocr = UnifiedAnalysisResult.from_screenshot_result(ocr_res)

                    st.markdown("---")
                    render_verdict_badge(ocr_res.threat_level.value)
                    st.metric("Screenshot Risk Score", f"{ocr_res.risk_score} / 100")
                    st.info(f" **Assessment Summary:** {ocr_res.summary}")

                    st.markdown("#### Extracted OCR Text")
                    st.text_area("OCR Text Content", ocr_res.extracted_text, height=120, disabled=True)

                    render_evidence_table(ocr_res.evidence)

                    with st.expander(" View Unified JSON Output"):
                        st.json(unified_ocr.to_dict())
        else:
            st.info("Upload a screenshot or select a demo image to begin.")

    # =========================================================================
    # TAB 4: SYSTEM & METRICS
    # =========================================================================
    with tabs[3]:
        st.markdown("### System Architecture, Feature Schema & ML Performance")

        col_m1, col_m2 = st.columns([1, 1])

        with col_m1:
            st.markdown("#### URL ML Model Performance Metrics")
            st.caption("Trained on domain-aware stratified splits with held-out test evaluation.")

            class_info_path = Path(__file__).resolve().parent / "ml" / "models" / "class_info.json"
            if class_info_path.exists():
                with open(class_info_path, "r") as f:
                    c_info = json.load(f)

                st.markdown(f"- **Positive Class:** `{c_info.get('positive_class')}`")
                st.markdown(f"- **Train Split:** `{c_info.get('train_phishing_count')} phishing / {c_info.get('train_benign_count')} benign` ({c_info.get('train_ratio')})")
                st.markdown(f"- **Test Split:** `{c_info.get('test_phishing_count')} phishing / {c_info.get('test_benign_count')} benign` ({c_info.get('test_ratio')})")

                metrics = c_info.get("metrics", {})
                if metrics:
                    st.markdown("##### Held-Out Test Evaluation")
                    m_df_data = []
                    for model_k, vals in metrics.items():
                        m_df_data.append({
                            "Model": model_k.replace("_", " ").title(),
                            "Test Accuracy": f"{vals.get('test_accuracy', 0):.3f}",
                            "ROC-AUC": f"{vals.get('roc_auc', 0):.3f}",
                            "PR-AUC": f"{vals.get('pr_auc', 0):.3f}",
                        })
                    st.table(m_df_data)
                else:
                    st.write("Model metrics metadata file not found.")

        with col_m2:
            st.markdown(f"#### 42-Feature URL Schema (`v{SCHEMA_VERSION}`)")
            st.markdown("""
            | Category | Features | Description |
            |---|---|---|
            | **Lexical** | 14 | Lengths, character ratios, token counts, suspicious keywords |
            | **Structural** | 10 | Subdomain depth, path depth, IP hostnames, custom ports, HTTPS |
            | **Obfuscation** | 11 | Punycode IDN, percent-encoding, @ redirection, entropy, shorteners |
            | **Domain** | 7 | Hash-encoded TLD, eTLD+1 lengths, domain hyphens, domain digits |
            """)

            with st.expander("View Full 42-Feature Definitions"):
                schema_summary = [
                    {"Name": f.name, "Type": f.feature_type.value, "Category": f.category.value, "Description": f.description}
                    for f in FEATURE_DEFINITIONS
                ]
                st.table(schema_summary)

    # =========================================================================
    # TAB 5: PRIVACY POLICY
    # =========================================================================
    with tabs[4]:
        st.markdown("### Privacy Policy")
        st.warning("Draft for review. This page is not ready to serve as a published legal notice.")
        st.caption("Describes behavior visible in this repository. Hosting and operational practices require confirmation.")

        st.markdown("#### Data processed by the application")
        st.markdown(
            "- **URLs:** The URL feature extractor and selected classifier analyze the submitted string. "
            "The URL inference code does not fetch or resolve the submitted URL.\n"
            "- **Text and email:** A local rule-based lexical detector evaluates the submitted text. "
            "URLs found in the text are passed to URL analysis.\n"
            "- **Screenshots:** The OCR service tries locally installed OCR engines, then analyzes extracted text "
            "and discovered URLs using the text and URL analysis paths."
        )

        st.markdown("#### Transmission, storage, and retention")
        st.markdown(
            "The repository contains no external inference API integration or application-defined durable "
            "retention policy. Inputs are sent from the browser to the server running Streamlit so the app can "
            "analyze them. This repository does not establish how a hosting provider, reverse proxy, server "
            "logs, backups, or monitoring retain or process that traffic. Streamlit usage-stat collection is "
            "disabled in this project's configuration; that setting does not control hosting or network logs."
        )

        st.markdown("#### OCR and external dependencies")
        st.markdown(
            "OCR depends on which local backend and model files are available. EasyOCR may obtain model files "
            "when they are not already present, depending on its environment and configuration. Confirm model "
            "installation, network access, and any third-party processing before deployment."
        )

        st.markdown("#### Items requiring operator review")
        st.markdown(
            "Before publication, specify the operator and contact method, hosting and logging configuration, "
            "retention and deletion practices, OCR model acquisition behavior, analytics or telemetry settings, "
            "and the policy effective date. These details are not established by this repository."
        )

    # =========================================================================
    # TAB 6: TERMS & CONDITIONS
    # =========================================================================
    with tabs[5]:
        st.markdown("### Terms & Conditions")
        st.warning("Draft for review. Operator identity, governing terms, and effective date are not yet provided.")
        st.caption("Complete the marked items with accurate operator and deployment information before publication.")

        st.markdown("#### 1. Service description")
        st.markdown(
            "PhishGuard is a research prototype that analyzes URLs, text or email content, and screenshots. "
            "It returns model- or rule-based classifications, risk scores, and supporting evidence."
        )

        st.markdown("#### 2. Output limitations")
        st.markdown(
            "Results are automated assessments and can be incomplete or incorrect, including false positives "
            "and false negatives. They are not a guarantee that content is safe or malicious and should not "
            "be the sole basis for a security decision."
        )

        st.markdown("#### 3. User-provided content")
        st.markdown(
            "Submit only content you are authorized to analyze. You are responsible for deciding whether the "
            "content is appropriate for the selected deployment and its data-handling practices."
        )

        st.markdown("#### 4. Operator and terms requiring review")
        st.markdown(
            "- **Operator / legal entity:** [REVIEW: provide the responsible operator]\n"
            "- **Contact method:** [REVIEW: provide a monitored contact address or other channel]\n"
            "- **Effective date:** [REVIEW: provide the date these terms take effect]\n"
            "- **Governing law, venue, and dispute terms:** [REVIEW: obtain appropriate legal guidance and complete, if applicable]\n"
            "- **Hosting, availability, support, and data-retention terms:** [REVIEW: describe the actual deployment]"
        )


if __name__ == "__main__":
    main()