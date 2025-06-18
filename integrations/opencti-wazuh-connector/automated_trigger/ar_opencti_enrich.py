#!/usr/bin/env python3

import asyncio
import os
import logging
from typing import List, Optional

import aiohttp
from aiohttp import ClientError, ClientResponseError, ClientConnectorError, ClientPayloadError, ServerTimeoutError


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


OPENCTI_API_URL = os.getenv("OPENCTI_API_URL", "http://opencti:8080/graphql")
OPENCTI_API_TOKEN = os.getenv("OPENCTI_API_TOKEN", "")
CONNECTOR_ID = os.getenv("OPENCTI_CONNECTOR_ID", "")

OBSERVABLES_QUERY = """
query GetAllObservables($first: Int!, $after: ID) {
  stixCyberObservables(first: $first, after: $after) {
    edges { node { id } }
    pageInfo { hasNextPage endCursor }
  }
}
"""

ENRICHMENT_MUTATION = """
mutation StixCoreObjectEnrichmentLinesMutation($id: ID!, $connectorId: ID!) {
  stixCoreObjectEdit(id: $id) {
    askEnrichment(connectorId: $connectorId) { id }
  }
}
"""

CONCURRENCY_LIMIT = int(os.getenv("CONCURRENCY_LIMIT", "10"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))

async def fetch_all_observable_ids(session: aiohttp.ClientSession) -> List[str]:
    observables: List[str] = []
    after: Optional[str] = None
    while True:
        variables = {"first": 1000}
        if after:
            variables["after"] = after
        payload = {"query": OBSERVABLES_QUERY, "variables": variables}
        try:
            async with session.post(OPENCTI_API_URL, json=payload, timeout=REQUEST_TIMEOUT) as resp:
                resp.raise_for_status()
                result = await resp.json()
        except (ClientResponseError, ClientConnectorError, ServerTimeoutError, ClientPayloadError) as e:
            logger.error(f"Error fetching observables: {e}. Retrying...")
            await asyncio.sleep(5)
            continue
        except Exception as e:
            logger.exception(f"Unexpected error fetching observables: {e}")
            break


        try:
            data = result["data"]["stixCyberObservables"]
            edges = data["edges"]
            page_info = data["pageInfo"]
        except (KeyError, TypeError) as e:
            logger.error(f"Invalid response structure: {e} - {result}")
            break

        ids = [edge["node"]["id"] for edge in edges if edge.get("node")]
        observables.extend(ids)
        logger.info(f"Fetched {len(ids)} observables (total: {len(observables)})")

        if page_info.get("hasNextPage"):
            after = page_info.get("endCursor")
        else:
            break

    return observables

async def enrich_observable(observable_id: str, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore):
    async with semaphore:
        variables = {"id": observable_id, "connectorId": CONNECTOR_ID}
        payload = {"query": ENRICHMENT_MUTATION, "variables": variables}
        retries = 3
        for attempt in range(1, retries + 1):
            try:
                async with session.post(OPENCTI_API_URL, json=payload, timeout=REQUEST_TIMEOUT) as resp:
                    resp.raise_for_status()
                    result = await resp.json()
                enrichment_id = result["data"]["stixCoreObjectEdit"]["askEnrichment"]["id"]
                logger.info(f"Enrichment triggered for {observable_id}: {enrichment_id}")
                return
            except (ClientResponseError, ClientConnectorError, ServerTimeoutError, ClientPayloadError) as e:
                logger.warning(f"[Attempt {attempt}] Failed to trigger enrichment for {observable_id}: {e}")
                if attempt < retries:
                    await asyncio.sleep(2 ** attempt)
                else:
                    logger.error(f"Giving up on {observable_id} after {retries} attempts")
            except Exception as e:
                logger.exception(f"Unexpected error enriching {observable_id}: {e}")
                return

async def main():
    if not OPENCTI_API_TOKEN or not CONNECTOR_ID:
        logger.critical("Missing OPENCTI_API_TOKEN or OPENCTI_CONNECTOR_ID environment variables")
        return

    headers = {
        "Authorization": f"Bearer {OPENCTI_API_TOKEN}",
        "Content-Type": "application/json"
    }
    timeout = aiohttp.ClientTimeout(total=None)
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
        observables = await fetch_all_observable_ids(session)
        if not observables:
            logger.warning("No observables fetched; exiting")
            return

        tasks = [enrich_observable(obs_id, session, semaphore) for obs_id in observables]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())