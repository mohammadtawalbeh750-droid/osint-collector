import logging
import re
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


logger = logging.getLogger(__name__)


DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9,ar;q=0.8"
}


UNWANTED_TAGS = [
    "script",
    "style",
    "noscript",
    "nav",
    "header",
    "footer",
    "aside",
    "form",
    "button",
    "svg",
    "iframe",
    "input",
    "select",
    "textarea",
    "canvas"
]


UNWANTED_SELECTORS = [
    ".infobox",
    ".navbox",
    ".sidebar",
    ".metadata",
    ".advertisement",
    ".ads",
    ".ad",
    ".cookie",
    ".cookies",
    ".newsletter",
    ".subscribe",
    ".social-share",
    ".share",
    ".menu",
    ".breadcrumb",
    ".related",
    ".comments",
    ".comment",
    "#comments",
    "#cookie",
    "#cookies",
    "[aria-hidden='true']"
]


CONTENT_SELECTORS = [
    "main",
    "article",
    "[role='main']",
    "#main",
    "#content",
    "#mw-content-text",
    ".mw-parser-output",
    ".post-content",
    ".entry-content",
    ".article-content",
    ".article-body",
    ".story-body",
    ".content"
]


def clean_whitespace(text):

    if not text:
        return ""

    text = re.sub(
        r"\s+",
        " ",
        str(text)
    )

    return text.strip()


def ensure_url(url):

    clean_url = str(url or "").strip()

    if not clean_url:
        raise ValueError(
            "URL is empty"
        )

    parsed_url = urlparse(
        clean_url
    )

    if not parsed_url.scheme:

        clean_url = (
            "https://" + clean_url
        )

        parsed_url = urlparse(
            clean_url
        )


    if parsed_url.scheme not in [
        "http",
        "https"
    ]:
        raise ValueError(
            "Only http and https URLs are supported"
        )


    if not parsed_url.netloc:
        raise ValueError(
            "Invalid URL"
        )


    return clean_url


def remove_unwanted_elements(soup):

    for tag in soup(
        UNWANTED_TAGS
    ):
        tag.decompose()


    for tag in soup.find_all(
        "table"
    ):
        tag.decompose()


    for selector in UNWANTED_SELECTORS:

        for tag in soup.select(
            selector
        ):
            tag.decompose()


def get_page_title(soup, fallback_url):

    if soup.title:

        title = clean_whitespace(
            soup.title.get_text(
                separator=" ",
                strip=True
            )
        )

        if title:
            return title


    heading = soup.find(
        ["h1", "h2"]
    )

    if heading:

        title = clean_whitespace(
            heading.get_text(
                separator=" ",
                strip=True
            )
        )

        if title:
            return title


    return fallback_url


def find_content_area(soup):

    for selector in CONTENT_SELECTORS:

        area = soup.select_one(
            selector
        )

        if area:

            text = clean_whitespace(
                area.get_text(
                    separator=" ",
                    strip=True
                )
            )

            if len(text) >= 100:
                return area


    return soup.body or soup


def collect_website(url):

    clean_url = ""

    try:

        clean_url = ensure_url(
            url
        )


        response = requests.get(
            clean_url,
            timeout=15,
            headers=DEFAULT_HEADERS,
            allow_redirects=True
        )

        response.raise_for_status()


        content_type = response.headers.get(
            "content-type",
            ""
        ).lower()

        if (
            "text/html" not in content_type and
            "application/xhtml" not in content_type and
            content_type
        ):

            return {
                "title": "Unsupported Content Type",
                "content": (
                    f"Unsupported content type: {content_type}"
                ),
                "url": response.url or clean_url,
                "data_type": "error"
            }


        if response.encoding is None:
            response.encoding = response.apparent_encoding


        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )


        title = get_page_title(
            soup,
            response.url or clean_url
        )


        remove_unwanted_elements(
            soup
        )


        content_area = find_content_area(soup)


        content = clean_whitespace(
            content_area.get_text(
                separator=" ",
                strip=True
            )
        )


        if not content:

            return {
                "title": title,
                "content": "No readable content found",
                "url": response.url or clean_url,
                "data_type": "error"
            }


        return {
            "title": title,
            "content": content[:50000],
            "url": response.url or clean_url,
            "data_type": "website"
        }


    except requests.exceptions.Timeout:

        return {
            "title": "Collection Failed",
            "content": "Request timed out",
            "url": clean_url or url,
            "data_type": "error"
        }


    except requests.exceptions.RequestException as error:

        logger.warning(
            "Web collection request failed for %s: %s",
            clean_url or url,
            error
        )

        return {
            "title": "Collection Failed",
            "content": str(error),
            "url": clean_url or url,
            "data_type": "error"
        }


    except Exception as error:

        logger.exception(
            "Web collection failed for %s",
            clean_url or url
        )

        return {
            "title": "Collection Failed",
            "content": str(error),
            "url": clean_url or url,
            "data_type": "error"
        }
