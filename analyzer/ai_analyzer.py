import re

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


# =========================
# Model Settings
# =========================

MODEL_NAME = "Hybrid Rules + TF-IDF + Logistic Regression v3"

CONFIDENCE_THRESHOLD = 0.30
MARGIN_THRESHOLD = 0.04


# =========================
# Training Data
# =========================

TRAINING_DATA = [

    # PHISHING
    ("phishing email asks users to verify their account using a suspicious login link", "phishing"),
    ("fake login page stealing usernames and passwords", "phishing"),
    ("credential harvesting campaign targeting company employees", "phishing"),
    ("malicious email impersonating a company and requesting password verification", "phishing"),
    ("users received phishing messages containing fraudulent authentication links", "phishing"),
    ("attackers sent password reset emails to steal user credentials", "phishing"),
    ("oauth consent phishing campaign attempts to hijack user accounts", "phishing"),
    ("fake microsoft login page used to collect employee credentials", "phishing"),
    ("fraudulent authentication portal asks victims to enter passwords", "phishing"),
    ("social engineering campaign uses fake cloud login pages", "phishing"),

    # MALWARE
    ("malware campaign distributing malicious executable files", "malware"),
    ("trojan infection detected on employee computers", "malware"),
    ("ransomware attack encrypting files and demanding payment", "malware"),
    ("malicious software downloaded from a compromised website", "malware"),
    ("new malware variant targeting windows devices", "malware"),
    ("stealer malware collects browser passwords and cookies", "malware"),
    ("malicious powershell command installs malware on the victim device", "malware"),
    ("remote access trojan provides attackers control of infected systems", "malware"),
    ("malware loader downloads additional malicious payloads", "malware"),
    ("malicious repository distributes credential stealing malware", "malware"),

    # DATA LEAK
    ("database containing customer information leaked online", "data_leak"),
    ("hacker claims to have stolen company employee records", "data_leak"),
    ("sensitive corporate data published on a hacking forum", "data_leak"),
    ("customer emails and passwords exposed in a data breach", "data_leak"),
    ("confidential documents allegedly leaked from the organization", "data_leak"),
    ("millions of customer records were stolen from company systems", "data_leak"),
    ("personal information including social security numbers was exposed", "data_leak"),
    ("attackers stole names addresses and financial account details", "data_leak"),
    ("stolen database was offered for sale on a hacking forum", "data_leak"),
    ("company confirms attackers accessed and exfiltrated sensitive data", "data_leak"),

    # FAKE DOMAIN
    ("fake domain registered to impersonate the official company website", "fake_domain"),
    ("lookalike website using a domain similar to the organization", "fake_domain"),
    ("typosquatting domain discovered targeting company customers", "fake_domain"),
    ("fraudulent domain created to imitate the official login portal", "fake_domain"),
    ("suspicious domain pretending to represent the organization", "fake_domain"),
    ("attackers registered a lookalike domain for brand impersonation", "fake_domain"),
    ("domain name differs by one character from the official company domain", "fake_domain"),
    ("malicious website copies the branding of the official organization", "fake_domain"),
    ("newly registered domain is being used for company impersonation", "fake_domain"),
    ("brand impersonation campaign uses domains similar to the official domain", "fake_domain"),

    # CYBER INCIDENT
    ("company systems affected by a cybersecurity incident", "cyber_incident"),
    ("organization reports unauthorized access to its network", "cyber_incident"),
    ("security breach detected on corporate infrastructure", "cyber_incident"),
    ("attackers exploited a vulnerability in the company server", "cyber_incident"),
    ("cyber attack caused disruption to online services", "cyber_incident"),
    ("attackers gained unauthorized access to internal company systems", "cyber_incident"),
    ("organization confirmed compromise of corporate infrastructure", "cyber_incident"),
    ("security incident disrupted business operations", "cyber_incident"),
    ("company investigated suspicious access to its internal network", "cyber_incident"),
    ("incident response team contained an active intrusion in company systems", "cyber_incident"),

    # BENIGN
    ("company announced a new product today", "benign"),
    ("software application received a normal feature update", "benign"),
    ("organization published its annual financial report", "benign"),
    ("new employees joined the company this month", "benign"),
    ("technology conference will take place next week", "benign"),
    ("join our cybersecurity webinar about privacy and data protection", "benign"),
    ("cybersecurity conference announces speakers and registration details", "benign"),
    ("security company is looking for advertisers and sponsors", "benign"),
    ("researchers published a general report about cybersecurity trends", "benign"),
    ("security awareness training course is available for employees", "benign"),
    ("new cybersecurity podcast discusses industry trends", "benign"),
    ("company promotes its threat intelligence product and services", "benign"),
    ("webinar explores how artificial intelligence is changing cybersecurity", "benign"),
    ("company announces a new partnership with a security vendor", "benign"),
    ("organization publishes best practices for cyber threat intelligence", "benign"),
]


TRAINING_TEXTS = [
    item[0]
    for item in TRAINING_DATA
]


TRAINING_LABELS = [
    item[1]
    for item in TRAINING_DATA
]


# =========================
# AI Model
# =========================

MODEL = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            ngram_range=(1, 2),
            sublinear_tf=True
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=2000,
            random_state=42,
            class_weight="balanced"
        )
    )
])


MODEL.fit(
    TRAINING_TEXTS,
    TRAINING_LABELS
)


# =========================
# Helper Functions
# =========================

def clean_text(text):

    if not text:
        return ""

    text = re.sub(
        r"[\u200b\u200c\u200d\ufeff]",
        " ",
        str(text)
    )

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


def get_keywords(keywords):

    if not keywords:
        return []


    if isinstance(keywords, str):

        raw_keywords = re.split(
            r"[,،;\n]+",
            keywords
        )

    elif isinstance(keywords, (list, tuple, set)):

        raw_keywords = keywords

    else:

        raw_keywords = [
            str(keywords)
        ]


    cleaned_keywords = []
    seen = set()

    for keyword in raw_keywords:

        clean_keyword = clean_text(
            keyword
        ).lower()

        if not clean_keyword:
            continue


        if clean_keyword in seen:
            continue


        cleaned_keywords.append(
            clean_keyword
        )

        seen.add(
            clean_keyword
        )


    return cleaned_keywords


def contains_phrase(text, phrase):

    clean_source_text = clean_text(
        text
    )

    clean_phrase = clean_text(
        phrase
    )

    if not clean_source_text or not clean_phrase:
        return False


    pattern = (
        r"(?<![A-Za-z0-9_])"
        + re.escape(clean_phrase)
        + r"(?![A-Za-z0-9_])"
    )

    return re.search(
        pattern,
        clean_source_text,
        re.IGNORECASE
    ) is not None


def calculate_relevance(text, keywords):

    keyword_list = get_keywords(
        keywords
    )

    if not keyword_list:
        return "Low"


    matched_keywords = 0

    for keyword in keyword_list:

        if contains_phrase(
            text,
            keyword
        ):

            matched_keywords += 1


    if matched_keywords >= 3:
        return "Critical"

    if matched_keywords == 2:
        return "High"

    if matched_keywords == 1:
        return "Medium"

    return "Low"


def create_summary(
    text,
    max_length=300
):

    clean_source_text = clean_text(
        text
    )

    if not clean_source_text:
        return ""


    sentences = re.split(
        r"(?<=[.!?؟])\s+",
        clean_source_text
    )


    summary = sentences[0] if sentences else clean_source_text


    if len(summary) > max_length:

        summary = (
            summary[:max_length].rstrip()
            + "..."
        )


    return summary


def normalize_confidence(value):

    try:

        confidence = float(value)

    except Exception:

        return 0.0


    if confidence > 1 and confidence <= 100:
        confidence = confidence / 100


    if confidence < 0:
        return 0.0

    if confidence > 1:
        return 1.0

    return confidence


# =========================
# Hybrid Rule Engine
# =========================

THREAT_RULES = {

    "phishing": [
        (r"\bphishing\b", 4),
        (r"\bcredential[- ]harvesting\b", 4),
        (r"\bfake login\b", 4),
        (r"\bfraudulent login\b", 4),
        (r"\bcredential theft\b", 3),
        (r"\bsteal(?:ing)? credentials\b", 3),
        (r"\boauth consent phishing\b", 5),
        (r"\bpassword reset\b", 2),
        (r"\bhijack(?:ing)? accounts?\b", 2),
        (r"\bmalicious login page\b", 4),
        (r"\bسرقة بيانات الدخول\b", 4),
        (r"\bتصيد\b", 4),
    ],

    "malware": [
        (r"\bmalware\b", 4),
        (r"\bransomware\b", 5),
        (r"\btrojan\b", 4),
        (r"\bstealer\b", 4),
        (r"\bmalicious payload\b", 4),
        (r"\bmalicious executable\b", 4),
        (r"\bmalicious powershell\b", 4),
        (r"\binfected systems?\b", 3),
        (r"\bbackdoor\b", 3),
        (r"\bبرمجية خبيثة\b", 4),
        (r"\bفدية\b", 5),
    ],

    "data_leak": [
        (r"\bdata breach\b", 5),
        (r"\bdata leak\b", 5),
        (r"\bleaked data\b", 4),
        (r"\bstolen data\b", 4),
        (r"\bdata was stolen\b", 4),
        (r"\bpersonal data\b", 2),
        (r"\bpersonal information\b", 2),
        (r"\bsensitive data\b", 3),
        (r"\bexposed data\b", 4),
        (r"\bexfiltrat(?:ed|ion)\b", 4),
        (r"\bcustomer records?\b", 2),
        (r"\bتسريب بيانات\b", 5),
        (r"\bبيانات مسربة\b", 5),
    ],

    "fake_domain": [
        (r"\bfake domain\b", 5),
        (r"\blookalike domain\b", 5),
        (r"\btyposquatting\b", 5),
        (r"\bdeceptive domain\b", 4),
        (r"\bimpersonation domain\b", 4),
        (r"\bbrand impersonation\b", 3),
        (r"\bfake website\b", 3),
        (r"\bموقع مزيف\b", 4),
        (r"\bنطاق مزيف\b", 5),
    ],

    "cyber_incident": [
        (r"\bhacked\b", 4),
        (r"\bsecurity breach\b", 4),
        (r"\bcyber attack\b", 4),
        (r"\bunauthorized access\b", 4),
        (r"\bcompromised\b", 3),
        (r"\bcompromise\b", 3),
        (r"\bintrusion\b", 4),
        (r"\bexploited (?:a )?vulnerability\b", 4),
        (r"\bactive exploitation\b", 4),
        (r"\bremote code execution\b", 3),
        (r"\bzero[- ]day\b", 3),
        (r"\bCVE-\d{4}-\d+\b", 3),
        (r"\bاختراق\b", 4),
        (r"\bثغرة\b", 3),
    ]
}


BENIGN_RULES = [
    r"\bwebinar\b",
    r"\bconference\b",
    r"\bpodcast\b",
    r"\bnewsletter\b",
    r"\badvertisers?\b",
    r"\bsponsors?\b",
    r"\bregistration details\b",
    r"\bfree online event\b",
    r"\bnew partnership\b",
    r"\bproduct launch\b",
    r"\bproduct announcement\b",
    r"\btraining course\b",
    r"\bawareness\b",
    r"\bbest practices\b",
]


def rule_based_classification(text):

    normalized_text = clean_text(
        text
    ).lower()


    if not normalized_text:

        return {
            "classification": "benign",
            "confidence": 0.0,
            "rule_score": 0
        }


    scores = {}

    for threat_type, rules in THREAT_RULES.items():

        score = 0
        matches = []

        for pattern, weight in rules:

            if re.search(
                pattern,
                normalized_text,
                re.IGNORECASE
            ):

                score += weight
                matches.append(
                    pattern
                )


        scores[threat_type] = {
            "score": score,
            "matches": matches
        }


    ranked = sorted(
        scores.items(),
        key=lambda item: item[1]["score"],
        reverse=True
    )


    best_type = ranked[0][0]
    best_score = ranked[0][1]["score"]

    second_score = ranked[1][1]["score"]


    benign_match = any(
        re.search(
            pattern,
            normalized_text,
            re.IGNORECASE
        )
        for pattern in BENIGN_RULES
    )


    if best_score >= 4:

        # Heuristic confidence, not a calibrated probability.
        heuristic_confidence = min(
            0.95,
            0.70 + (best_score * 0.04)
        )


        if (
            second_score > 0
            and best_score - second_score <= 1
        ):

            return {
                "classification": None,
                "confidence": None,
                "rule_score": best_score
            }


        return {
            "classification": best_type,
            "confidence": heuristic_confidence,
            "rule_score": best_score
        }


    if benign_match and best_score == 0:

        return {
            "classification": "benign",
            "confidence": 0.85,
            "rule_score": 0
        }


    return {
        "classification": None,
        "confidence": None,
        "rule_score": best_score
    }


def ml_classification(text):

    probabilities = MODEL.predict_proba(
        [text]
    )[0]

    classes = MODEL.classes_

    sorted_indexes = (
        probabilities.argsort()[::-1]
    )

    best_index = sorted_indexes[0]
    second_index = sorted_indexes[1]


    classification = str(
        classes[best_index]
    )

    confidence_score = float(
        probabilities[best_index]
    )

    second_score = float(
        probabilities[second_index]
    )

    confidence_margin = (
        confidence_score - second_score
    )


    if (
        confidence_score < CONFIDENCE_THRESHOLD
        or confidence_margin < MARGIN_THRESHOLD
    ):

        classification = "uncertain"


    return classification, confidence_score


# =========================
# Main Analysis Function
# =========================

def analyze_content(
    text,
    organization_keywords=""
):

    clean_source_text = clean_text(
        text
    )


    if not clean_source_text:

        return {
            "model_name": MODEL_NAME,
            "classification": "benign",
            "relevance": "Low",
            "confidence_score": 0.0,
            "summary": ""
        }


    rule_result = rule_based_classification(
        clean_source_text
    )


    if rule_result["classification"]:

        relevance = calculate_relevance(
            clean_source_text,
            organization_keywords
        )

        summary = create_summary(
            clean_source_text
        )


        return {
            "model_name": MODEL_NAME,
            "classification": rule_result["classification"],
            "relevance": relevance,
            "confidence_score": round(
                normalize_confidence(
                    rule_result["confidence"]
                ),
                4
            ),
            "summary": summary
        }


    classification, confidence_score = ml_classification(
        clean_source_text
    )


    relevance = calculate_relevance(
        clean_source_text,
        organization_keywords
    )

    summary = create_summary(
        clean_source_text
    )


    return {
        "model_name": MODEL_NAME,
        "classification": classification,
        "relevance": relevance,
        "confidence_score": round(
            normalize_confidence(
                confidence_score
            ),
            4
        ),
        "summary": summary
    }
