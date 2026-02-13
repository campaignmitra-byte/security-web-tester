from __future__ import annotations

from collections import deque
from urllib.parse import parse_qs, urljoin, urlparse

MAX_DEPTH = 2
TIMEOUT_SECONDS = 10


def _is_internal_link(base_netloc: str, candidate_url: str) -> bool:
    parsed = urlparse(candidate_url)
    return parsed.netloc == "" or parsed.netloc == base_netloc


def _normalize_url(base_url: str, href: str) -> str:
    return urljoin(base_url, href.split("#", 1)[0])


def discover_targets(base_url: str) -> dict:
    """Crawl a target website and discover pages, forms, params, and endpoints."""

    import requests
    from bs4 import BeautifulSoup

    parsed_base = urlparse(base_url)
    if not parsed_base.scheme:
        raise ValueError("Base URL must include a scheme, e.g. https://example.com")

    base_netloc = parsed_base.netloc
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(base_url, 0)])

    pages: set[str] = set()
    params: set[str] = set()
    endpoints: set[str] = set()
    forms: list[dict] = []

    session = requests.Session()

    while queue:
        url, depth = queue.popleft()
        if depth > MAX_DEPTH or url in visited:
            continue

        visited.add(url)

        try:
            response = session.get(url, timeout=TIMEOUT_SECONDS)
            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                pages.add(url)
                continue
        except requests.RequestException:
            continue

        pages.add(url)
        soup = BeautifulSoup(response.text, "html.parser")

        page_params = parse_qs(urlparse(url).query)
        params.update(page_params.keys())

        for form in soup.find_all("form"):
            action = form.get("action") or url
            method = (form.get("method") or "GET").upper()
            action_url = _normalize_url(url, action)
            input_names = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
            params.update(input_names)

            forms.append(
                {
                    "page": url,
                    "action": action_url,
                    "method": method,
                    "inputs": input_names,
                }
            )
            endpoints.add(action_url)

        for anchor in soup.find_all("a", href=True):
            normalized = _normalize_url(url, anchor["href"])
            if not _is_internal_link(base_netloc, normalized):
                continue

            parsed = urlparse(normalized)
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else normalized
            endpoints.add(clean_url)
            params.update(parse_qs(parsed.query).keys())

            if clean_url not in visited and depth < MAX_DEPTH:
                queue.append((clean_url, depth + 1))

    for candidate in list(endpoints) + list(pages):
        path = urlparse(candidate).path.lower()
        if "/api" in path or path.endswith(".json"):
            endpoints.add(candidate)

    return {
        "pages": sorted(pages),
        "forms": forms,
        "params": sorted(params),
        "endpoints": sorted(endpoints),
    }
