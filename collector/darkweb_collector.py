import json
import os
import time
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse, parse_qs
from urllib.request import Request, urlopen


# =========================
# Helpers
# =========================

def clean_text(value, default=""):

    if value is None:
        return default

    return str(value).strip()


def now_iso():

    return datetime.utcnow().isoformat()


def split_keywords(keywords):

    if not keywords:
        return []

    if not isinstance(keywords, str):
        keywords = str(keywords)

    parts = []

    for chunk in keywords.replace("،", ",").replace(";", ",").split(","):

        clean_chunk = clean_text(chunk)

        if clean_chunk:
            parts.append(clean_chunk)

    return parts


def looks_like_strong_selector(value):

    text = clean_text(value).lower()

    if not text:
        return False

    if " " in text:
        return False

    if "@" in text and "." in text:
        return True

    if text.startswith("http://") or text.startswith("https://"):
        return True

    if "." in text and len(text) >= 4:
        return True

    parts = text.split(".")

    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return True

    return False


def extract_indicator_from_source(source, organization):

    raw_value = clean_text(getattr(source, "url", ""))

    if not raw_value:
        return clean_text(getattr(organization, "domain", ""))

    parsed = urlparse(raw_value)

    if parsed.scheme in ["darkweb", "intelx"]:

        query = parse_qs(parsed.query)

        if query.get("q"):
            return clean_text(query["q"][0])

        indicator = "".join([
            parsed.netloc,
            parsed.path
        ]).strip("/")

        return clean_text(indicator)

    return raw_value


def build_search_terms(source, organization, keywords):

    candidates = []

    candidates.append(
        extract_indicator_from_source(source, organization)
    )

    candidates.append(
        clean_text(getattr(organization, "domain", ""))
    )

    for keyword in split_keywords(keywords):
        candidates.append(keyword)

    seen = set()
    search_terms = []

    for candidate in candidates:

        clean_candidate = clean_text(candidate).strip("/")

        if not clean_candidate:
            continue

        candidate_key = clean_candidate.lower()

        if candidate_key in seen:
            continue

        if looks_like_strong_selector(clean_candidate):

            search_terms.append(clean_candidate)
            seen.add(candidate_key)

        # تمت إزالة القيد القديم (كان يتوقف عند 3 مصطلحات) ليقوم بجمع كل المصطلحات المتاحة
        if len(search_terms) >= 20:
            break

    return search_terms


def request_json(url, method="GET", api_key=None, timeout=20):

    headers = {
        "Accept": "application/json",
        "User-Agent": "OSINT-Collector-Demo/1.0"
    }

    if api_key:
        headers["X-Key"] = api_key

    request = Request(
        url,
        data=b"" if method.upper() == "POST" else None,
        headers=headers,
        method=method.upper()
    )

    with urlopen(
        request,
        timeout=timeout
    ) as response:

        raw_data = response.read().decode("utf-8", errors="replace")

        if not raw_data:
            return {}

        return json.loads(raw_data)


# =========================
# Intelligence X API
# =========================

def get_intelx_settings():

    api_url = clean_text(
        os.getenv("INTELX_API_URL"),
        "https://free.intelx.io"
    ).rstrip("/")

    api_key = clean_text(
        os.getenv("INTELX_API_KEY")
    )

    buckets = clean_text(
        os.getenv("INTELX_BUCKETS"),
        "darknet,leaks.public,pastes"
    )

    try:
        # رفع القيمة الافتراضية إلى 50 نتيجة قابلة للتوسعة بلا قيود صارمة
        max_results = int(os.getenv("INTELX_MAX_RESULTS", "50"))
    except Exception:
        max_results = 50

    if max_results < 1:
        max_results = 50

    # تمت إزالة القيد الذي كان يمنع تجاوز 10 نتائج نهائياً

    return {
        "api_url": api_url,
        "api_key": api_key,
        "buckets": buckets,
        "max_results": max_results
    }


def start_intelx_search(term, settings):

    params = {
        "term": term,
        "maxresults": settings["max_results"],
        "buckets": settings["buckets"],
        "timeout": 10,
        "datefrom": "",
        "dateto": "",
        "sort": 4,
        "media": 0
    }

    url = (
        f'{settings["api_url"]}/intelligent/search?'
        f'{urlencode(params)}'
    )

    data = request_json(
        url,
        method="POST",
        api_key=settings["api_key"],
        timeout=25
    )

    return clean_text(
        data.get("id")
    )


def fetch_intelx_results(search_id, settings):

    collected_records = []

    # تم زيادة عدد محاولات جلب النتائج من السيرفر لسحب أكبر كمية متاحة
    for _ in range(10):

        params = {
            "id": search_id,
            "limit": settings["max_results"],
            "media": 0,
            "statistics": 0,
            "previewlines": 5,
            "k": settings["api_key"]
        }

        url = (
            f'{settings["api_url"]}/intelligent/search/result?'
            f'{urlencode(params)}'
        )

        data = request_json(
            url,
            method="GET",
            api_key=settings["api_key"],
            timeout=25
        )

        records = data.get("records") or []

        if isinstance(records, list) and records:
            collected_records.extend(records)

        status = data.get("status")

        if status in [1, 2, 4]:
            break

        time.sleep(1.0)

    return collected_records


def terminate_intelx_search(search_id, settings):

    if not search_id:
        return

    try:

        params = {
            "id": search_id,
            "k": settings["api_key"]
        }

        url = (
            f'{settings["api_url"]}/intelligent/search/terminate?'
            f'{urlencode(params)}'
        )

        request_json(
            url,
            method="GET",
            api_key=settings["api_key"],
            timeout=10
        )

    except Exception:
        return


def record_to_item(record, term, organization):

    title = clean_text(
        record.get("name"),
        "Intelligence X Dark Web Result"
    )

    bucket = clean_text(
        record.get("bucketh") or record.get("bucket"),
        "Unknown bucket"
    )

    description = clean_text(
        record.get("description"),
        "No public preview available for this result."
    )

    date_value = clean_text(
        record.get("date") or record.get("added"),
        now_iso()
    )

    xscore = record.get("xscore")

    system_id = clean_text(
        record.get("systemid") or record.get("randomid")
    )

    organization_name = clean_text(
        getattr(organization, "name", "Organization")
    )

    organization_domain = clean_text(
        getattr(organization, "domain", "")
    )

    content = (
        f"Dark Web intelligence result collected from Intelligence X. "
        f"Search selector: {term}. "
        f"Organization: {organization_name}. "
        f"Domain: {organization_domain}. "
        f"Bucket: {bucket}. "
        f"Title: {title}. "
        f"Description: {description}. "
        f"X-Score: {xscore if xscore is not None else 'N/A'}. "
        f"This result may indicate leaked data, exposed credentials, pastes, "
        f"darknet mentions, or underground references related to the organization."
    )

    result_url = (
        "https://intelx.io/?s="
        + quote(term)
    )

    if system_id:
        result_url += "#" + quote(system_id)

    return {
        "title": f"Intelligence X - {title}",
        "content": content,
        "url": result_url,
        "data_type": "darkweb",
        "collected_at": date_value
    }


def collect_from_intelx(source, organization, keywords):

    settings = get_intelx_settings()

    if not settings["api_key"]:
        raise Exception("INTELX_API_KEY is missing")

    search_terms = build_search_terms(
        source,
        organization,
        keywords
    )

    if not search_terms:
        raise Exception(
            "No valid Intelligence X selector found. Use a domain, email, IP, or URL."
        )

    items = []

    for term in search_terms:

        search_id = None

        try:

            search_id = start_intelx_search(
                term,
                settings
            )

            if not search_id:
                continue

            records = fetch_intelx_results(
                search_id,
                settings
            )

            for record in records:

                items.append(
                    record_to_item(
                        record,
                        term,
                        organization
                    )
                )

                # السماح بجلب عناصر مفتوحة دون تقييدها بـ 5 أو 10 عناصر فقط
                if len(items) >= settings["max_results"] * 2:
                    break

        finally:

            terminate_intelx_search(
                search_id,
                settings
            )

        if len(items) >= settings["max_results"] * 2:
            break

    return items


# =========================
# Safe Demo Fallback (Extended)
# =========================

def build_mock_items(source, organization, keywords):

    organization_name = clean_text(
        getattr(organization, "name", "Organization")
    )

    domain = clean_text(
        getattr(organization, "domain", "example.com")
    ) or "example.com"

    keyword_text = clean_text(keywords, domain)

    indicator = extract_indicator_from_source(
        source,
        organization
    ) or domain

    base_url = "darkweb://demo/"

    # تمت زيادة قوالب المحاكاة لتوليد مجموعة بيانات أكبر بكثير عند استخدام الـ Mock بدلاً من الاقتصار على 5 عناصر
    templates = [
        {
            "title": "Dark Web - Possible Leaked Credentials",
            "content": f"Possible leaked credentials mentioning {domain} were detected in a dark web style source. Intelligence item references login access and exposed accounts related to {organization_name}. Keywords: {keyword_text}."
        },
        {
            "title": "Dark Web - Underground Forum Mention",
            "content": f"An underground forum style discussion mentioned {organization_name} and {domain}. Discussion indicates reconnaissance, phishing preparation, or credential abuse risk. Keywords: {keyword_text}."
        },
        {
            "title": "Dark Web - Paste Exposure Signal",
            "content": f"A paste style source contained references to {domain}, usernames, emails, and authentication material. Treated as a possible data leak signal requiring triage. Keywords: {keyword_text}."
        },
        {
            "title": "Dark Web - Ransomware Leak Mention",
            "content": f"A ransomware leak style mention was associated with {organization_name}. Item includes references to sensitive files, breach claims, and external exposure around {domain}."
        },
        {
            "title": "Dark Web - Suspicious Access Offer",
            "content": f"A suspicious access offer referenced assets connected to {domain}. Suggests possible initial access broker activity and should be investigated."
        },
        {
            "title": "Dark Web - API Keys Exposure Leak",
            "content": f"Found plain text API tokens and database connection strings associated with infrastructure of {domain} in underground repositories."
        },
        {
            "title": "Dark Web - Corporate Database Dump",
            "content": f"Unverified SQL database dump claiming to contain customer records and internal staff credentials tied to {organization_name}."
        },
        {
            "title": "Dark Web - Insider Threat Discussion",
            "content": f"Private chat logs discussing potential internal bypass techniques and VPN access details targeting systems under {domain}."
        },
        {
            "title": "Dark Web - Phishing Kit Deployment",
            "content": f"Identified a newly hosted phishing landing page mimicking the corporate portal of {organization_name} designed for credential harvesting."
        },
        {
            "title": "Dark Web - Source Code Repository Leak",
            "content": f"Leaked proprietary source code snippets and internal configuration files referencing {domain} services found on deep web forums."
        }
    ]

    items = []

    for index, template in enumerate(templates, start=1):

        items.append({
            "title": template["title"],
            "content": template["content"],
            "url": f"{base_url}{quote(domain)}/{index}",
            "data_type": "darkweb",
            "collected_at": now_iso()
        })

    return items


# =========================
# Main collector
# =========================

def collect_darkweb(source, organization, keywords):

    mode = clean_text(
        os.getenv("DARKWEB_MODE"),
        "mock"
    ).lower()

    fallback = clean_text(
        os.getenv("DARKWEB_FALLBACK"),
        "mock"
    ).lower()

    if mode == "real":

        try:

            intelx_items = collect_from_intelx(
                source,
                organization,
                keywords
            )

            if intelx_items:

                return {
                    "data_type": "darkweb",
                    "provider": "Intelligence X",
                    "mode": "real",
                    "items": intelx_items
                }

            if fallback != "mock":

                return {
                    "data_type": "darkweb",
                    "provider": "Intelligence X",
                    "mode": "real",
                    "items": []
                }

        except (HTTPError, URLError, TimeoutError, Exception):

            if fallback != "mock":
                raise

    return {
        "data_type": "darkweb",
        "provider": "Demo Dataset",
        "mode": "mock",
        "items": build_mock_items(
            source,
            organization,
            keywords
        )
    }