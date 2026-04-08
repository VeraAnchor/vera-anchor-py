# vera-anchor

Local-first Python SDK for deterministic evidence generation, ingest workflows, and dataset anchoring for [Hash Factory](https://hf.veraanchor.com). Part of the [Vera Anchor](https://veraanchor.com) ecosystem.

Raw data never leaves your machine. Only derived evidence packages are submitted to Hash Factory when you choose to do so.

> **License:** Source-available under MIT with Commons Clause. 
See [LICENSE](./LICENSE).

## Installation

```bash
pip install vera-anchor
```

Requires Python 3.8+.

## What it does

`vera-anchor` builds deterministic evidence packages on your machine composed of SHA3-512 hashes, Merkle proofs, bundle manifests, fingerprints, and receipts. It then optionally submits that evidence to Hash Factory for registration, HCS anchoring, and certificate issuance.

Two operating modes:

- **Local only** — build evidence, inspect it, keep raw files private. No network calls.
- **Local then submit** — build evidence locally, then send the evidence package to Hash Factory.

## Quickstart (no API key needed)

Generate a local evidence package for any directory — no account, no network:

```python
import asyncio, tempfile, pathlib
from vera_anchor.datasets.remote import ExecuteDatasetAnchorLocalOnlyInput, execute_dataset_anchor_local_only
from vera_anchor.datasets.types import DatasetIdentity

async def main():
    # Use any local directory — here we create a temp one with sample files
    root = pathlib.Path(tempfile.mkdtemp())
    (root / "hello.txt").write_text("hello world")
    (root / "data.json").write_text('{"x": 1}')

    result = await execute_dataset_anchor_local_only(
        ExecuteDatasetAnchorLocalOnlyInput(
            identity=DatasetIdentity(
                dataset_key="my-org.demo.quickstart",
                program="demo",
                version_label="v1",
            ),
            root_dir=str(root),
            evidence_pointer=f"file://{root}",
            hooks=None,
        )
    )
    print("merkle_root:  ", result.local.evidence.merkle_root)
    print("bundle_digest:", result.local.evidence.bundle_digest)
    print("receipt_id:   ", result.local.receipt["receipt_id"])

asyncio.run(main())
```

Run the same directory twice and the hashes are identical — that's the determinism guarantee.

## Dataset flow

For directory-backed datasets.

### Local only

```python
import asyncio
from vera_anchor.datasets.remote import ExecuteDatasetAnchorLocalOnlyInput, execute_dataset_anchor_local_only
from vera_anchor.datasets.types import DatasetIdentity

async def main():
    result = await execute_dataset_anchor_local_only(
        ExecuteDatasetAnchorLocalOnlyInput(
            identity=DatasetIdentity(
                dataset_key="<org_id>.<program>.<name>",
                program="my_program",
                version_label="v1",
            ),
            root_dir="/path/to/dataset",
            evidence_pointer="file:///path/to/dataset",
            hooks=None,
        )
    )

    print(result.local.receipt)
    print(result.local.evidence)

asyncio.run(main())
```

### Local then submit to Hash Factory

```python
import asyncio
import os
from vera_anchor import HfLocalAuth, HfLocalClientConfig
from vera_anchor.datasets.remote import ExecuteDatasetAnchorLocalThenSubmitInput, execute_dataset_anchor_local_then_submit
from vera_anchor.datasets.types import DatasetIdentity

async def main():
    config = HfLocalClientConfig(
        base_url="https://hfapi.veraanchor.com",
        auth=HfLocalAuth(apiKey=os.environ["HF_API_KEY"]),
    )

    result = await execute_dataset_anchor_local_then_submit(
        config,
        ExecuteDatasetAnchorLocalThenSubmitInput(
            identity=DatasetIdentity(
                dataset_key="<org_id>.<program>.<name>",
                program="my_program",
                version_label="v1",
            ),
            root_dir="/path/to/dataset",
            evidence_pointer="file:///path/to/dataset",
            display_name="My Dataset",
            publish_visibility="unlisted",
            set_active=True,
            hooks=None,
        ),
    )

    print(result.local.receipt)
    print(result.remote)

asyncio.run(main())
```

### Verify

```python
import asyncio
import os
from vera_anchor import HfLocalAuth, HfLocalClientConfig
from vera_anchor.datasets.remote import verify_dataset_anchor_remote

async def main():
    config = HfLocalClientConfig(
        base_url="https://hfapi.veraanchor.com",
        auth=HfLocalAuth(apiKey=os.environ["HF_API_KEY"]),
    )

    result = await verify_dataset_anchor_remote(
        config,
        {
            "receipt": receipt,   # from a previous run
            "bundle": bundle,     # from a previous run
            "root_dir": "/path/to/dataset",  # optional local consistency check
        },
    )

    print(result)

asyncio.run(main())
```

## Ingest flow

For generic evidence objects — `file_set`, `file`, `text`, or `json`.

### Local only

```python
import asyncio
from vera_anchor.ingest.remote import ExecuteIngestLocalOnlyInput, execute_ingest_local_only

async def main():
    result = await execute_ingest_local_only(
        ExecuteIngestLocalOnlyInput(
            request={
                "mode": "merkle_only",
                "identity": {
                    "object_key": "my_object",
                    "object_kind": "file_set",
                    "program": "my_program",
                    "version_label": "v1",
                },
                "material": {
                    "kind": "file_set",
                    "root_dir": "/path/to/input",
                    "rules": {"follow_symlinks": False},
                },
                "evidence_pointer": "file:///path/to/input",
            },
            hooks=None,
        )
    )

    print(result.local.receipt)
    print(result.local.evidence)

asyncio.run(main())
```

### Local then submit

```python
import asyncio
import os
from vera_anchor import HfLocalAuth, HfLocalClientConfig
from vera_anchor.ingest.remote import ExecuteIngestLocalThenSubmitInput, execute_ingest_local_then_submit

async def main():
    config = HfLocalClientConfig(
        base_url="https://hfapi.veraanchor.com",
        auth=HfLocalAuth(apiKey=os.environ["HF_API_KEY"]),
    )

    result = await execute_ingest_local_then_submit(
        config,
        ExecuteIngestLocalThenSubmitInput(
            request={
                "mode": "register_and_anchor",
                "identity": {
                    "object_key": "my_object",
                    "object_kind": "file_set",
                    "program": "my_program",
                    "version_label": "v1",
                },
                "material": {
                    "kind": "file_set",
                    "root_dir": "/path/to/input",
                    "rules": {"follow_symlinks": False},
                },
                "evidence_pointer": "file:///path/to/input",
                "domain": "hf:ingest|org",
                "proof_date": "2026-03-23",
            },
            hooks=None,
        ),
    )

    print(result.local.receipt)
    print(result.remote)

asyncio.run(main())
```

## Example scripts

The package includes runnable example scripts:

| Script | Description |
|---|---|
| `scripts/example_dataset_local_only.py` | Local-only dataset evidence generation |
| `scripts/example_dataset_local_submit.py` | Local build + submit to Hash Factory |
| `scripts/example_dataset_verify.py` | Verify a receipt and bundle |
| `scripts/example_ingest_local_only.py` | Local-only ingest evidence generation |
| `scripts/example_ingest_local_submit.py` | Local ingest + submit to Hash Factory |
| `scripts/example_ingest_verify.py` | Verify an ingest receipt and bundle |

Copy `.env.example` to `.env` and fill in your values before running any submit or verify script.

Run a dataset submit example:

```bash
HF_API_KEY=your_key \
HF_BASE_URL=https://hfapi.veraanchor.com \
TEST_ROOT_DIR=/path/to/dataset \
TEST_DATASET_KEY=<org_id>.<program>.<name> \
TEST_EVIDENCE_POINTER=s3://your-bucket/path \
python scripts/example_dataset_local_then_submit.py
```

Run an ingest local-only example:

```bash
TEST_ROOT_DIR=/path/to/input \
TEST_OBJECT_KIND=file_set \
TEST_OBJECT_KEY=my_object \
python scripts/example_ingest_local_only.py
```

## Hash Factory

[hf.veraanchor.com](https://hf.veraanchor.com) — live deployment.

Hash Factory is the web interface where users onboard, manage evidence packages, view HCS anchors, and receive HTS certificate NFTs on Hedera.

## License

Source-available under the MIT License with Commons Clause. Commercial resale of the software itself is restricted. See [LICENSE](./LICENSE).