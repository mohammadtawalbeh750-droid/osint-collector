import re
from html import unescape


# =========================
# Text Cleaning
# =========================

def clean_text(text):
    """
    Clean collected OSINT text before keyword filtering.
    """

    if not text:
        return ""

    text = unescape(
        str(text)
    )

    # Remove invisible characters
    text = re.sub(
        r"[\u200b\u200c\u200d\ufeff]",
        " ",
        text
    )

    # Remove Wikipedia references like [1], [25], [a]
    text = re.sub(
        r"\[\s*(?:\d+|[a-zA-Z])\s*\]",
        " ",
        text
    )

    # Remove common wiki/editor notes
    text = re.sub(
        r"\[\s*(?:edit|update|citation needed)\s*\]",
        " ",
        text,
        flags=re.IGNORECASE
    )

    # Remove repeated separators
    text = re.sub(
        r"[-_=]{3,}",
        " ",
        text
    )

    # Normalize whitespace
    text = re.sub(
        r"\s+",
        " ",
        text
    )

    # Clean spaces before punctuation, English + Arabic
    text = re.sub(
        r"\s+([.,!?؟،:؛])",
        r"\1",
        text
    )

    return text.strip()


# =========================
# Keywords
# =========================

def get_keywords(keywords):
    """
    Convert organization keywords to a clean list.
    Supports comma, Arabic comma, semicolon, and new lines.
    """

    if not keywords:
        return []


    if isinstance(
        keywords,
        str
    ):

        raw_keywords = re.split(
            r"[,،;\n]+",
            keywords
        )

    elif isinstance(
        keywords,
        (list, tuple, set)
    ):

        raw_keywords = keywords

    else:

        raw_keywords = [
            str(keywords)
        ]


    clean_keywords = []
    seen_keywords = set()

    for keyword in raw_keywords:

        clean_keyword = clean_text(
            keyword
        )

        if not clean_keyword:
            continue

        keyword_key = clean_keyword.casefold()

        if keyword_key in seen_keywords:
            continue

        clean_keywords.append(
            clean_keyword
        )

        seen_keywords.add(
            keyword_key
        )


    return clean_keywords


def contains_keyword(text, keyword):
    """
    Check if keyword exists in the text.
    Works with English, Arabic, numbers, and multi-word keywords.
    """

    clean_keyword = clean_text(
        keyword
    )

    clean_source_text = clean_text(
        text
    )

    if not clean_keyword or not clean_source_text:
        return False


    pattern = (
        r"(?<![A-Za-z0-9_])"
        + re.escape(clean_keyword)
        + r"(?![A-Za-z0-9_])"
    )

    return re.search(
        pattern,
        clean_source_text,
        flags=re.IGNORECASE
    ) is not None


# =========================
# Sentence Splitting
# =========================

def split_sentences(text):
    """
    Split text into readable snippets.
    Supports English and Arabic punctuation.
    """

    clean_source_text = clean_text(
        text
    )

    if not clean_source_text:
        return []


    sentences = re.split(
        r"(?<=[.!?؟])\s+|(?<=[。])\s+",
        clean_source_text
    )


    clean_sentences = []

    for sentence in sentences:

        clean_sentence = clean_text(
            sentence
        )

        if clean_sentence:

            clean_sentences.append(
                clean_sentence
            )


    return clean_sentences


# =========================
# Filtering
# =========================

def rank_sentence(sentence, keywords):

    score = 0
    matched = []

    for keyword in keywords:

        if contains_keyword(
            sentence,
            keyword
        ):

            score += 1
            matched.append(
                keyword
            )


    return score, matched


def select_default_sentences(sentences):

    selected = []
    total_length = 0

    max_snippets = 6
    max_total_chars = 3000
    max_sentence_chars = 1200

    for sentence in sentences:

        if len(sentence) > max_sentence_chars:
            continue


        new_length = (
            total_length
            + len(sentence)
            + 2
        )


        if new_length > max_total_chars:
            break


        selected.append(
            sentence
        )

        total_length = new_length


        if len(selected) >= max_snippets:
            break


    return selected


def filter_by_keywords(text, keywords):
    """
    Extract complete relevant snippets based on organization keywords.
    If no keywords exist, return the first clean readable snippets.
    """

    clean_source_text = clean_text(
        text
    )

    keyword_list = get_keywords(
        keywords
    )

    sentences = split_sentences(
        clean_source_text
    )

    max_snippets = 8
    max_total_chars = 5000
    max_sentence_chars = 1500


    if not clean_source_text:
        return "", []


    if not sentences:

        if len(clean_source_text) <= max_total_chars:
            return clean_source_text, []

        return clean_source_text[:max_total_chars].strip(), []


    if not keyword_list:

        selected = select_default_sentences(
            sentences
        )

        return "\n\n".join(selected), []


    matched_keywords = []

    for keyword in keyword_list:

        if contains_keyword(
            clean_source_text,
            keyword
        ):

            matched_keywords.append(
                keyword
            )


    ranked_sentences = []

    for index, sentence in enumerate(sentences):

        if len(sentence) > max_sentence_chars:
            continue


        score, sentence_matches = rank_sentence(
            sentence,
            keyword_list
        )


        if score > 0:

            ranked_sentences.append({
                "index": index,
                "score": score,
                "text": sentence,
                "matches": sentence_matches
            })


    if not ranked_sentences:

        return "", matched_keywords


    ranked_sentences.sort(
        key=lambda item: (
            item["score"],
            -item["index"]
        ),
        reverse=True
    )


    selected_snippets = []
    selected_set = set()
    total_length = 0


    for item in ranked_sentences:

        sentence = item["text"]

        sentence_key = sentence.casefold()

        if sentence_key in selected_set:
            continue


        new_length = (
            total_length
            + len(sentence)
            + 2
        )


        if new_length > max_total_chars:
            continue


        selected_snippets.append(
            sentence
        )

        selected_set.add(
            sentence_key
        )

        total_length = new_length


        if len(selected_snippets) >= max_snippets:
            break


    filtered_text = "\n\n".join(
        selected_snippets
    )


    return filtered_text, matched_keywords


# =========================
# Main Processing Function
# =========================

def process_content(text, keywords):
    """
    Run Processing stage:
    1. Cleaning
    2. Keyword filtering
    3. Return processed content + matched keywords
    """

    cleaned_text = clean_text(
        text
    )

    filtered_text, matched_keywords = filter_by_keywords(
        cleaned_text,
        keywords
    )

    return {
        "content": filtered_text,
        "matched_keywords": matched_keywords
    }
