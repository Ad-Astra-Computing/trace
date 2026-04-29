"""Build a CPE product index from NVD's /cpes/2.0 endpoint.

  python -m agents.scout.cpe_dictionary_cli --out cpe-index.json

Reads NVD_API_KEY from the environment (anonymous-first; never required).

Walks every page of the dictionary (~1.7M CPEs, ~170 paginated requests
at 10000/page). Anonymous run takes ~16 minutes (5 req / 30 s quota);
NVD_API_KEY brings it to ~1 minute (50 req / 30 s).

Output: JSON dict {lowercased_product: [cpe, cpe, ...]}, sorted +
deduped for reproducible diffs.

Exit codes:
  0   ok
  10  fetch-failed / transient
  20  rate-limited (server retry-after surfaced on stderr)
  64  usage error
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from agents.scout.cpe_dictionary import (
    build_product_index,
    fetch_all_cpe_pages,
    parse_cpe_page,
    write_index,
)
from agents.scout.feed_client import (
    FeedDecodeError,
    FeedRateLimit,
    FeedTransientError,
)


_EXIT_OK = 0
_EXIT_FETCH_FAILED = 10
_EXIT_RATE_LIMITED = 20
_EXIT_USAGE = 64


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trace-scout-cpe-dictionary")
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Path to write the product-keyed CPE index JSON.",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=None,
        help=(
            "Cap the number of pages fetched. Useful for smoke/CI runs "
            "where a partial index is acceptable. Default: walk all pages."
        ),
    )
    args = parser.parse_args(argv)

    api_key = os.environ.get("NVD_API_KEY") or None

    all_cpes: list[str] = []
    pages_seen = 0

    try:
        for page in fetch_all_cpe_pages(api_key=api_key):
            all_cpes.extend(parse_cpe_page(page))
            pages_seen += 1
            if pages_seen % 10 == 0:
                print(
                    f"...{pages_seen} pages, {len(all_cpes)} CPEs collected so far",
                    file=sys.stderr,
                )
            if args.max_pages is not None and pages_seen >= args.max_pages:
                print(
                    f"reached --max-pages={args.max_pages}, stopping early",
                    file=sys.stderr,
                )
                break
    except FeedRateLimit as e:
        print(f"rate-limited; retry after {e.retry_after}s", file=sys.stderr)
        return _EXIT_RATE_LIMITED
    except (FeedTransientError, FeedDecodeError) as e:
        print(f"CPE dictionary fetch failed: {e}", file=sys.stderr)
        return _EXIT_FETCH_FAILED

    index = build_product_index(all_cpes)
    write_index(index, args.out)
    print(
        f"wrote index with {len(index)} unique products "
        f"({sum(len(v) for v in index.values())} CPEs) to {args.out}",
        file=sys.stderr,
    )
    return _EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
