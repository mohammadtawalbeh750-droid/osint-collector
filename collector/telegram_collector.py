import logging
import re
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


logger = logging.getLogger(__name__)


TELEGRAM_HEADERS = {
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


CHANNEL_REGEX = re.compile(
    r"^[A-Za-z0-9_]{5,32}$"
)


def clean_text(value):

    if value is None:
        return ""

    return re.sub(
        r"\s+",
        " ",
        str(value)
    ).strip()


def normalize_channel(channel):
    """
    Convert a Telegram URL or username to a public channel username.
    Supports:
    - https://t.me/channel
    - https://t.me/s/channel
    - http://t.me/channel
    - @channel
    - channel
    """

    raw_channel = clean_text(channel)

    if not raw_channel:
        raise ValueError(
            "Telegram channel is empty"
        )


    raw_channel = raw_channel.split("?")[0]
    raw_channel = raw_channel.split("#")[0]
    raw_channel = raw_channel.strip("/")


    if raw_channel.startswith("@"):
        raw_channel = raw_channel[1:]


    parsed = urlparse(raw_channel)

    if parsed.netloc:

        host = parsed.netloc.lower()

        if host not in [
            "t.me",
            "www.t.me",
            "telegram.me",
            "www.telegram.me"
        ]:

            raise ValueError(
                "Unsupported Telegram host"
            )


        path_parts = [
            part for part in parsed.path.split("/")
            if part
        ]


        if path_parts and path_parts[0].lower() == "s":
            path_parts = path_parts[1:]


        if not path_parts:

            raise ValueError(
                "Telegram channel name is missing"
            )


        raw_channel = path_parts[0]


    else:

        raw_channel = raw_channel.replace(
            "https://t.me/s/",
            ""
        )

        raw_channel = raw_channel.replace(
            "https://t.me/",
            ""
        )

        raw_channel = raw_channel.replace(
            "http://t.me/s/",
            ""
        )

        raw_channel = raw_channel.replace(
            "http://t.me/",
            ""
        )

        raw_channel = raw_channel.replace(
            "t.me/s/",
            ""
        )

        raw_channel = raw_channel.replace(
            "t.me/",
            ""
        )

        raw_channel = raw_channel.strip("/")


    if raw_channel.startswith("+"):

        raise ValueError(
            "Private invite links are not supported. Use a public Telegram channel username."
        )


    if not CHANNEL_REGEX.match(raw_channel):

        raise ValueError(
            "Invalid Telegram channel username"
        )


    return raw_channel


def extract_message_text(element):

    text_element = element.select_one(
        ".tgme_widget_message_text"
    )

    if not text_element:
        return ""


    for unwanted in text_element.select(
        ".tgme_widget_message_text > .tgme_widget_message_link_preview"
    ):
        unwanted.decompose()


    return clean_text(
        text_element.get_text(
            separator=" ",
            strip=True
        )
    )


def extract_message_date(element):

    time_element = element.select_one(
        ".tgme_widget_message_date time"
    )

    if not time_element:
        return ""


    return (
        time_element.get("datetime")
        or time_element.get("title")
        or time_element.get_text(strip=True)
        or ""
    )


def extract_channel_title(soup, fallback_title):

    title_element = soup.select_one(
        ".tgme_channel_info_header_title"
    )

    if title_element:

        title = clean_text(
            title_element.get_text(
                separator=" ",
                strip=True
            )
        )

        if title:
            return title


    meta_title = soup.select_one(
        "meta[property='og:title']"
    )

    if meta_title and meta_title.get("content"):

        title = clean_text(
            meta_title.get("content")
        )

        if title:
            return title


    return fallback_title


def collect_telegram(channel, limit=50):
    """
    Collect posts from a public Telegram channel using the public web preview.
    This does not require API ID, API hash, phone number, or Telegram session.
    """

    channel_name = ""

    try:

        channel_name = normalize_channel(
            channel
        )


        try:

            safe_limit = int(limit)

        except Exception:

            safe_limit = 50


        safe_limit = max(
            1,
            min(safe_limit, 100)
        )


        messages = []
        seen_posts = set()

        before_id = None
        soup = None
        max_pages = 10
        pages_checked = 0


        with requests.Session() as session:

            session.headers.update(
                TELEGRAM_HEADERS
            )


            while (
                len(messages) < safe_limit and
                pages_checked < max_pages
            ):

                pages_checked += 1

                page_url = (
                    f"https://t.me/s/{channel_name}"
                )

                if before_id:
                    page_url += (
                        f"?before={before_id}"
                    )


                response = session.get(
                    page_url,
                    timeout=15
                )

                response.raise_for_status()


                soup = BeautifulSoup(
                    response.text,
                    "html.parser"
                )


                message_elements = soup.select(
                    ".tgme_widget_message"
                )


                if not message_elements:
                    break


                page_ids = []


                for element in message_elements:

                    data_post = element.get(
                        "data-post"
                    )

                    if not data_post:
                        continue


                    try:

                        post_channel, message_id_text = (
                            data_post.rsplit(
                                "/",
                                1
                            )
                        )

                        message_id = int(
                            message_id_text
                        )

                    except Exception:

                        continue


                    page_ids.append(
                        message_id
                    )


                    message_key = (
                        f"{post_channel}/{message_id}"
                    )


                    if message_key in seen_posts:
                        continue


                    text = extract_message_text(
                        element
                    )

                    if not text:
                        continue


                    message_date = extract_message_date(
                        element
                    )


                    direct_url = (
                        f"https://t.me/{post_channel}/{message_id}"
                    )


                    messages.append({
                        "message_id": message_id,
                        "date": message_date,
                        "text": text,
                        "url": direct_url
                    })


                    seen_posts.add(
                        message_key
                    )


                    if len(messages) >= safe_limit:
                        break


                if not page_ids:
                    break


                oldest_id = min(
                    page_ids
                )


                if (
                    before_id is not None and
                    oldest_id >= before_id
                ):
                    break


                before_id = oldest_id


        messages.sort(
            key=lambda item: item["message_id"]
        )


        if len(messages) > safe_limit:

            messages = messages[-safe_limit:]


        title = channel_name

        if soup:

            title = extract_channel_title(
                soup,
                channel_name
            )


        return {
            "title": title,
            "messages": messages,
            "url": f"https://t.me/{channel_name}",
            "data_type": "telegram"
        }


    except requests.exceptions.Timeout:

        return {
            "title": "Telegram Collection Failed",
            "messages": [],
            "url": channel,
            "data_type": "error",
            "error": "Telegram request timed out"
        }


    except requests.exceptions.RequestException as error:

        logger.warning(
            "Telegram collection request failed for %s: %s",
            channel_name or channel,
            error
        )

        return {
            "title": "Telegram Collection Failed",
            "messages": [],
            "url": channel,
            "data_type": "error",
            "error": str(error)
        }


    except Exception as error:

        logger.exception(
            "Telegram collection failed for %s",
            channel_name or channel
        )

        return {
            "title": "Telegram Collection Failed",
            "messages": [],
            "url": channel,
            "data_type": "error",
            "error": str(error)
        }
