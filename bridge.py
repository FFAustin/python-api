import argparse
import json
import logging.config
import random
import string
import time
from json import JSONDecodeError
from typing import Optional

import base58
from cryptography.fernet import Fernet

from api.metaplex_api import MetaplexAPI

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(funcName)s %(lineno)s %(message)s",
    handlers=[
        logging.StreamHandler()
    ]

)
log = logging.getLogger(__name__)

# Constants
DEV_NET = "https://api.devnet.solana.com/"
TEST_NET = "https://api.testnet.solana.com/"
MAIN_NET = "https://api.mainnet-beta.solana.com/"
CLUSTER_NAME_RPC_ENDPOINT_MAP = {"main_net": MAIN_NET, "test_net": TEST_NET, "dev_net": DEV_NET}


def mint_metaplex_nft(custodian_public_key: str,
                      custodian_private_key: str,
                      link_to_json_file: str,
                      solana_cluster: Optional[str] = "dev_net",
                      token_name: Optional[str] = None,
                      token_symbol: Optional[str] = None,
                      supply: Optional[int] = 1):
    # Docstring
    """#################### mint_metaplex_nft() ####################
    Function to mint a Metaplex compliant NFT to a specified wallet on Solana

    Parameters:
        - custodian_public_key (str): String of the custodian's public Solana key
        - custodian_private_key ([64]): A byte array of len(64) of the custodian's private Solana key
        - solana_cluster (str): String representing cluster name, options are: 'main_net', 'test_net', and 'dev_net'
        - token_name (str)(Optional): String representing the name of the token on the Token Metadata Program
        - token_symbol (str)(Optional): String representing the symbol of the token on the Token Metadata Program
        - supply (int)(Optional): Default=1, max supply for a certain NFT

    Returns:
        Transaction Hash (str)
    ############################# end ###############################
    """

    # TODO: Determine if the custodian's private key will be passed to this function encrypted or not
    # If encrypted, we need to pull the decryption_key from the environment somehow. For now, I'm just
    # assuming the key is unencrypted as I'm not sure how Elixir Ports work
    server_decryption_key = Fernet.generate_key().decode("ascii")

    # Input validity checks
    if not CLUSTER_NAME_RPC_ENDPOINT_MAP.get(solana_cluster):
        raise ValueError("Invalid Solana Cluster")

    if not custodian_public_key:
        raise ValueError('custodian_public_key cannot be None')

    if not custodian_private_key:
        raise ValueError('custodian_private_key cannot be None')

    if not link_to_json_file:
        raise ValueError('link_to_json_file cannot be None')

    # Init the MetaplexAPI
    cfg = {
        "PRIVATE_KEY": custodian_private_key,
        "PUBLIC_KEY": custodian_public_key,
        "DECRYPTION_KEY": server_decryption_key
    }
    api = MetaplexAPI(cfg)

    rpc_endpoint = CLUSTER_NAME_RPC_ENDPOINT_MAP[solana_cluster]

    # Per Metaplex docs this is mapped to "seller_fee_basis_points" desc: "royalties percentage awarded to creators"
    # We don't want any royalties so this should always be 0
    fees = 0

    # Generate a random name and symbol if one was not provided
    token_name = token_name or ''.join([random.choice(string.ascii_uppercase) for _ in range(32)])

    # Generate a random symbol if one was not provided
    token_symbol = token_symbol or ''.join([random.choice(string.ascii_uppercase) for i in range(10)])

    result = api.deploy(rpc_endpoint, token_name, token_symbol, fees, max_timeout=180)
    log.debug(f"api.deploy.result:: {result}")

    contract_key = json.loads(result).get('contract')
    log.debug(f"contract_key:: {contract_key}")

    ###
    # !!!WARNING, HERE BE DRAGONS!!!
    # You might think it horrifying to see an arbitrary sleep sitting in the middle of a function,
    # and you would be right. Have not determined why yet but despite checking with Solana over RPC
    # that the deploy transaction is both confirmed and finalized, minting randomly fails because it
    # cannot find the previously deployed contract. Current theory is this is a progagation issue
    # with the network, which is why the sleep "fixes" it. Leaving it here for now but will dig
    # deeper to get rid of it.
    ###
    # time.sleep(30)

    result = api.mint(rpc_endpoint, contract_key, custodian_public_key, link_to_json_file, supply=supply)
    log.debug(f"api.mint.result:: {result}")

    # Return the mint transaction hash
    return json.loads(result).get('result')


def transfer(asset_key, sender_key, sender_private_key, dest_key, solana_cluster="dev_net", debug=True):
    """#################### transfer() ####################

    Parameters:
        - contract_key (str): Asset (contract/token) key to send
        - sender_key (str): Sender public key
        - sender_private_key ([64]/str): A string OR a byte array of len(64) is using a filesystem wallet of the sender's private Solana key
        - solana_cluster (str)(Optional): Default='dev_net' String representing cluster name, options are: 'main_net', 'test_net', and 'dev_net'
        - debug (bool)(Optional): Default=True, If True, adds some extra logging

    Returns:
        Transaction Hash String
    """

    # TODO: Determine if the custodian's private key will be passed to this function encrypted or not
    # If encrypted, we need to pull the decryption_key from the environment somehow. For now, I'm just
    # assuming the key is unencrypted as I'm not sure how Elixir Ports work
    server_decryption_key = Fernet.generate_key().decode("ascii")

    # Input validity checks
    if not CLUSTER_NAME_RPC_ENDPOINT_MAP.get(solana_cluster):
        raise ValueError("Invalid Solana Cluster")

    if asset_key is None:
        raise ValueError('asset_key cannot be None')

    if sender_key is None:
        raise ValueError('custodian_public_key cannot be None')

    if sender_private_key is None:
        raise ValueError('sender_private_key cannot be None')

    if dest_key is None:
        raise ValueError('dest_key cannot be None')

    cfg = {
        "PRIVATE_KEY": sender_private_key,
        "PUBLIC_KEY": sender_key,
        "DECRYPTION_KEY": server_decryption_key
    }
    api = MetaplexAPI(cfg)

    rpc_endpoint = CLUSTER_NAME_RPC_ENDPOINT_MAP[solana_cluster]

    result = api.send(rpc_endpoint, asset_key, sender_key, dest_key, sender_private_key)
    log.debug(f"api.send.result:: {result}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Aleo -> Solana Bridge CLI')

    parser.add_argument('--mint_metaplex_nft', nargs="+",
                        help='Mints a Metaplex compliant NFT into a specified wallet on Solana.')
    parser.add_argument('--transfer', nargs="+", help='Transfers a token from one address to another on Solana.')
    parser.add_argument('--docs', action='store_true', help='Returns the docstring of all functions')

    args = parser.parse_args()

    if args.mint_metaplex_nft:
        # Note: I tried to do this with named arguments (e.g. '--custodian_public_key "<key>"') instead of
        # an argument array, but it wasn't working with Elixir's System.cmd()
        public_key = args.mint_metaplex_nft[0]
        private_key = args.mint_metaplex_nft[1]

        if private_key[0] == "[" and private_key[-1] == "]":
            private_key = json.loads(private_key)
            pk_bytes = bytes(private_key)
            private_key = base58.b58encode(pk_bytes).decode("ascii")

        link = args.mint_metaplex_nft[2]

        cluster = args.mint_metaplex_nft[3] if len(args.mint_metaplex_nft) > 3 else "dev_net"

        supply = args.mint_metaplex_nft[4] if len(args.mint_metaplex_nft) > 4 else 1

        token_name = args.mint_metaplex_nft[5] if len(args.mint_metaplex_nft) > 5 else None

        token_symbol = args.mint_metaplex_nft[6] if len(args.mint_metaplex_nft) > 6 else None

        debug = args.mint_metaplex_nft[7] if len(args.mint_metaplex_nft) > 7 else True
        log.setLevel(logging.DEBUG if debug else logging.ERROR)

        # Filesystem wallets are stored as arrays. Need to base58 encode them.
        try:
            private_key_byte_array = json.loads(private_key)
            log.debug("Using base58 encoded private key")
            if not isinstance(private_key_byte_array, list) or not all(
                    isinstance(i, int) for i in private_key_byte_array) or len(private_key_byte_array) != 64:
                raise ValueError('Filesystem wallet byte arrays must be a 64 byte json encoded byte array. \n For '
                                 'example: "[23,148,26,223,164,159,38,100,170,73,240,76,219,148,237,141,200,13,70,'
                                 '212,65,192,67,114,199,101,45,31,31,163,215,86,119,214,243,171,0,59,2,40,4,198,39,'
                                 '235,233,121,185,235,110,217,127,156,171,154,173,20,208,123,91,88,125,187,96,214]"')
            private_key = base58.b58encode(bytes(private_key_byte_array)).decode("ascii")
        except JSONDecodeError:
            log.debug("Using base58 encoded private key")

        mint_metaplex_nft(public_key, private_key, link, cluster, token_name, token_symbol, supply)

    if args.transfer:
        asset_key = args.transfer[0]
        sender_key = args.transfer[1]
        sender_private_key = args.transfer[2]
        # Filesystem wallets are stored as arrays. Need to base58 encode them.
        if sender_private_key[0] == "[":
            sender_private_key = json.loads(args.transfer[2])
            pk_bytes = bytes(sender_private_key)
            sender_private_key = base58.b58encode(pk_bytes).decode("ascii")

        dest_key = args.transfer[3]
        cluster = args.transfer[4] if len(args.transfer) > 4 else "dev_net"
        debug = args.transfer[5] if len(args.transfer) > 5 else True
        log.setLevel(logging.DEBUG if debug else logging.ERROR)

        transfer(asset_key, sender_key, sender_private_key, dest_key, cluster)

    if args.docs:
        print(mint_metaplex_nft.__doc__)
        print(transfer.__doc__)
