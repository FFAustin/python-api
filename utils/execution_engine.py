import time
import logging
from solana.keypair import Keypair
from solana.rpc.api import Client
from solana.rpc.types import TxOpts

log = logging.getLogger(__name__)


def execute(api_endpoint, tx, signers, max_retries=3, skip_confirmation=True, max_timeout=60, target=20,
            finalized=True):
    client = Client(api_endpoint)
    signers = list(map(Keypair, set(map(lambda s: s.seed, signers))))

    last_error = TimeoutError()
    for attempt in range(max_retries):
        try:
            result = client.send_transaction(tx, *signers, opts=TxOpts(skip_preflight=True))
            log.info(f"Result of execution: {result}")
            signatures = [x.signature for x in tx.signatures]
            if not skip_confirmation:
                await_confirmation(client, signatures, max_timeout, target, finalized)
            return result
        except Exception as e:
            log.info(f"Failed attempt {attempt}: {e}")
            last_error = e
            continue
    log.error(f"Failed to execute with final error: {last_error}")
    raise last_error


def await_confirmation(client, signatures, max_timeout=60, target=20, finalized=True):
    elapsed = 0
    while elapsed < max_timeout:
        sleep_time = 1
        time.sleep(sleep_time)
        elapsed += sleep_time
        resp = client.get_signature_statuses(signatures)
        if resp["result"]["value"][0] is not None:
            confirmations = resp["result"]["value"][0]["confirmations"]
            is_finalized = resp["result"]["value"][0]["confirmationStatus"] == "finalized"
        else:
            continue
        if not finalized:
            if confirmations >= target or is_finalized:
                log.info(f"Took {elapsed} seconds to confirm transaction")
                return
        elif is_finalized:
            log.info(f"Took {elapsed} seconds to confirm transaction")
            return
