import sys
import argparse
import json
import logging.config
import random
import string
from json import JSONDecodeError
from typing import Optional
from distutils.util import strtobool

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


def _init_metaplex_api(custodian_public_key: str,
                       custodian_private_key: str,
                       server_decryption_key: Optional[str] = None) -> MetaplexAPI:
    # TODO: Determine if the custodian's private key will be passed to this function encrypted or not
    # If encrypted, we need to pull the decryption_key from the environment somehow. For now, I'm just
    # assuming the key is unencrypted as I'm not sure how Elixir Ports work
    server_decryption_key = server_decryption_key or Fernet.generate_key().decode("ascii")
    # Init the MetaplexAPI
    cfg = {
        "PRIVATE_KEY": custodian_private_key,
        "PUBLIC_KEY": custodian_public_key,
        "DECRYPTION_KEY": server_decryption_key
    }
    return MetaplexAPI(cfg)


def _cluster_rpc_endpoint(cluster: str) -> Optional[str]:
    if rpc_endpoint := CLUSTER_NAME_RPC_ENDPOINT_MAP.get(cluster):
        return rpc_endpoint
    return None


def _get_or_b58encode_private_key(pk: str) -> str:
    try:
        private_key_byte_array = json.loads(pk)
        log.debug("Using base58 encoded private key")
        if not isinstance(private_key_byte_array, list) or not all(
                isinstance(i, int) for i in private_key_byte_array) or len(private_key_byte_array) != 64:
            raise ValueError('Filesystem wallet byte arrays must be a 64 byte json encoded byte array. \n For '
                             'example: "[23,148,26,223,164,159,38,100,170,73,240,76,219,148,237,141,200,13,70,'
                             '212,65,192,67,114,199,101,45,31,31,163,215,86,119,214,243,171,0,59,2,40,4,198,39,'
                             '235,233,121,185,235,110,217,127,156,171,154,173,20,208,123,91,88,125,187,96,214]"')
        return base58.b58encode(bytes(private_key_byte_array)).decode("ascii")
    except JSONDecodeError:
        log.debug("Using base58 encoded private key")
        return pk


def deploy_and_mint_metaplex_nft(custodian_public_key: str,
                                 custodian_private_key: str,
                                 link_to_json_file: str,
                                 cluster: Optional[str] = "dev_net",
                                 token_name: Optional[str] = None,
                                 token_symbol: Optional[str] = None,
                                 supply: Optional[int] = 1) -> str:
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

    # Init the MetaplexAPI
    api = _init_metaplex_api(custodian_public_key, custodian_private_key)
    rpc_endpoint = _cluster_rpc_endpoint(cluster)

    if not rpc_endpoint:
        return json.dumps({"status": 422, "error": "Invalid Solana Cluster"})

    # Deploy the NFT metadata program
    result = deploy(api, rpc_endpoint, token_name, token_symbol)
    serialized_result = json.loads(result)
    if serialized_result.get("status") >= 300:
        log.debug(f"Error Result: {serialized_result}")
        return result

    contract_key = serialized_result.get('contract')
    log.debug(f"contract_key:: {contract_key}")

    # Mint the Master Edition NFT with the metadata program
    result = mint(api, rpc_endpoint, custodian_public_key, link_to_json_file, contract_key, supply=supply)
    serialized_result = json.loads(result)
    if serialized_result.get("status") >= 300:
        log.debug(f"Error Result: {serialized_result}")
        return result
    log.debug(f"result: {result}")

    mint_tx_hash = serialized_result.get('result')
    # Return the mint transaction hash
    return json.dumps({"status": 200, "result": {"contract_key": contract_key, "mint_tx_hash": mint_tx_hash}})


def deploy_metaplex_nft(cluster: str,
                        custodian_public_key: str,
                        custodian_private_key: str,
                        token_name: Optional[str] = None,
                        token_symbol: Optional[str] = None) -> str:
    api = _init_metaplex_api(custodian_public_key, custodian_private_key)
    rpc_endpoint = _cluster_rpc_endpoint(cluster)
    if not rpc_endpoint:
        return json.dumps({"status": 422, "error": "Invalid Solana Cluster"})
    return deploy(api, rpc_endpoint, token_name, token_symbol)


def deploy(api: MetaplexAPI,
           rpc_endpoint: str,
           token_name: Optional[str] = None,
           token_symbol: Optional[str] = None) -> str:
    # Per Metaplex docs this is mapped to "seller_fee_basis_points" desc: "royalties percentage awarded to creators"
    # We don't want any royalties so this should always be 0
    fees = 0

    # Generate a random name and symbol if one was not provided
    token_name = token_name or ''.join([random.choice(string.ascii_uppercase) for _ in range(32)])

    # Generate a random symbol if one was not provided
    token_symbol = token_symbol or ''.join([random.choice(string.ascii_uppercase) for _ in range(10)])

    result = api.deploy(rpc_endpoint, token_name, token_symbol, fees, max_timeout=180)
    log.debug(f"api.deploy.result:: {result}")
    log.debug(f"contract_key:: {json.loads(result).get('contract')}")

    return result


def mint_metaplex_nft(cluster: str,
                      custodian_public_key: str,
                      custodian_private_key: str,
                      link_to_json_file: str,
                      contract_key: str,
                      supply: Optional[int] = 1) -> str:
    api = _init_metaplex_api(custodian_public_key, custodian_private_key)
    rpc_endpoint = _cluster_rpc_endpoint(cluster)
    if not rpc_endpoint:
        return json.dumps({"status": 422, "error": "Invalid Solana Cluster"})
    return mint(api, rpc_endpoint, custodian_public_key, link_to_json_file, contract_key, supply)


def mint(api: MetaplexAPI,
         rpc_endpoint: str,
         custodian_public_key: str,
         link_to_json_file: str,
         contract_key: str,
         supply: Optional[int] = 1) -> str:
    result = api.mint(rpc_endpoint, contract_key, custodian_public_key, link_to_json_file, supply=supply)
    log.debug(f"api.mint.result:: {result}")

    # Return the mint transaction hash
    return result


def transfer_metaplex_nft(cluster: str,
                          asset_key: str,
                          sender_key: str,
                          sender_private_key: str,
                          dest_key: str) -> str:
    api = _init_metaplex_api(sender_key, sender_private_key)
    rpc_endpoint = _cluster_rpc_endpoint(cluster)
    if not rpc_endpoint:
        return json.dumps({"status": 422, "error": "Invalid Solana Cluster"})
    return transfer(api, rpc_endpoint, asset_key, sender_key, sender_private_key, dest_key)


def transfer(api: MetaplexAPI,
             rpc_endpoint: str,
             asset_key: str,
             sender_key: str,
             sender_private_key: str,
             dest_key: str) -> str:
    """#################### transfer() ####################

    Parameters:
        - api (MetaplexAPI): The MetaplexAPI instance to send the token through
        - rpc_endpoint (str): The JSON-RPC endpoint to call
        - asset_key (str): Asset (contract/token) key to send
        - sender_key (str): Sender public key
        - sender_private_key ([64]/str): A string OR a byte array of len(64) is using a filesystem wallet of the sender's private Solana key
        - solana_cluster (str)(Optional): Default='dev_net' String representing cluster name, options are: 'main_net', 'test_net', and 'dev_net'
        - debug (bool)(Optional): Default=True, If True, adds some extra logging

    Returns:
        Transaction Hash String
    """

    result = api.send(rpc_endpoint, asset_key, sender_key, dest_key, sender_private_key)
    log.debug(f"api.send.result:: {result}")
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Aleo -> Solana Bridge CLI')

    parser.add_argument('--deploy_metaplex_nft', nargs="+",
                        help='Deploys the metadata program for a Metaplex compliant NFT.')
    parser.add_argument('--only_mint_metaplex_nft', nargs="+",
                        help='Mints a Metaplex compliant NFT.')
    parser.add_argument('--mint_metaplex_nft', nargs="+",
                        help='Deploys and Mints a Metaplex compliant NFT into a specified wallet on Solana.')
    parser.add_argument('--transfer', nargs="+", help='Transfers a token from one address to another on Solana.')
    parser.add_argument('--docs', action='store_true', help='Returns the docstring of all functions')

    parsed_args = parser.parse_args()

    if args := parsed_args.mint_metaplex_nft:
        # Note: I tried to do this with named arguments (e.g. '--custodian_public_key "<key>"') instead of
        # an argument array, but it wasn't working with Elixir's System.cmd()

        # Aggregate Arguments
        args_len = len(args)

        if args_len < 3:
            print(json.dumps({"status": 422, "error": "public_key, private_key, and link cannot be None"}))
            sys.exit(0)

        public_key = args[0]
        private_key = args[1]

        link = args[2]
        cluster = args[3] if args_len > 3 else "dev_net"

        supply = int(args[4]) if args_len > 4 else 1

        token_name = args[5] if args_len > 5 else None

        token_symbol = args[6] if len(args) > 6 else None

        debug = strtobool(args[7]) if len(args) > 7 else False
        # Set Log Level
        log.setLevel(logging.DEBUG if debug else logging.ERROR)

        # Validate Input Params
        if not public_key:
            print(json.dumps({"status": 422, "error": "public_key cannot be None"}))
            sys.exit(0)

        if not private_key:
            print(json.dumps({"status": 422, "error": "private_key cannot be None"}))
            sys.exit(0)

        if not link:
            print(json.dumps({"status": 422, "error": "link to the asset JSON cannot be None"}))
            sys.exit(0)

        # Filesystem wallets are stored as arrays. Need to base58 encode them.
        private_key = _get_or_b58encode_private_key(private_key)

        result = deploy_and_mint_metaplex_nft(public_key, private_key, link, cluster, token_name, token_symbol, supply)
        print(result)

    if args := parsed_args.deploy_metaplex_nft:

        # Aggregate Arguments
        args_len = len(args)

        public_key = args[0]
        private_key = args[1]

        if args_len < 2:
            print(json.dumps({"status": 422, "error": "public_key, and private_key cannot be None"}))
            sys.exit(0)

        token_name = args[2] if args_len > 2 else None

        token_symbol = args[3] if len(args) > 3 else None

        cluster = args[4] if args_len > 4 else "dev_net"

        debug = strtobool(args[5]) if len(args) > 5 else False
        # Set Log Level
        log.setLevel(logging.DEBUG if debug else logging.ERROR)

        # Validate Input Params
        if not public_key:
            print(json.dumps({"status": 422, "error": "public_key cannot be None"}))
            sys.exit(0)

        if not private_key:
            print(json.dumps({"status": 422, "error": "private_key cannot be None"}))
            sys.exit(0)

        # Filesystem wallets are stored as arrays. Need to base58 encode them.
        private_key = _get_or_b58encode_private_key(private_key)

        result = deploy_metaplex_nft(cluster, public_key, private_key, token_name, token_symbol)
        print(result)

    if args := parsed_args.only_mint_metaplex_nft:

        # Aggregate Arguments
        args_len = len(args)

        if args_len < 4:
            print(json.dumps({"status": 422,
                              "error": "public_key, private_key, link, and contract_key cannot be None"}))
            sys.exit(0)

        public_key = args[0]
        private_key = args[1]
        link = args[2]
        contract_key = args[3]
        supply = int(args[4]) if args_len > 4 else 1
        cluster = args[5] if args_len > 5 else "dev_net"

        debug = strtobool(args[6]) if len(args) > 6 else False
        # Set Log Level
        log.setLevel(logging.DEBUG if debug else logging.ERROR)

        # Validate Input Params
        if not public_key:
            print(json.dumps({"status": 422, "error": "public_key cannot be None"}))
            sys.exit(0)

        if not private_key:
            print(json.dumps({"status": 422, "error": "private_key cannot be None"}))
            sys.exit(0)

        if not link:
            print(json.dumps({"status": 422, "error": "link to the asset JSON cannot be None"}))
            sys.exit(0)

        # Filesystem wallets are stored as arrays. Need to base58 encode them.
        private_key = _get_or_b58encode_private_key(private_key)

        result = mint_metaplex_nft(cluster, public_key, private_key, link, contract_key, supply)
        print(result)

    if args := parsed_args.transfer:
        args_len = len(args)

        if args_len < 4:
            print(json.dumps({"status": 422,
                              "error": "asset_key, sender_key, sender_private_key, and dest_key cannot be None"}))
            sys.exit(0)

        asset_key = args[0]
        sender_key = args[1]
        sender_private_key = args[2]
        dest_key = args[3]
        cluster = args[4] if args_len > 4 else "dev_net"
        debug = strtobool(args[5]) if args_len > 5 else False
        # Set Log Level
        log.setLevel(logging.DEBUG if debug else logging.ERROR)

        # Validate Input Params
        if not asset_key:
            print(json.dumps({"status": 422, "error": "asset_key cannot be None"}))
            sys.exit(0)

        if not sender_key:
            print(json.dumps({"status": 422, "error": "sender_key cannot be None"}))
            sys.exit(0)

        if not sender_private_key:
            print(json.dumps({"status": 422, "error": "sender_private_key cannot be None"}))
            sys.exit(0)

        if not dest_key:
            print(json.dumps({"status": 422, "error": "dest_key cannot be None"}))
            sys.exit(0)

        # Filesystem wallets are stored as arrays. Need to base58 encode them.
        sender_private_key = _get_or_b58encode_private_key(sender_private_key)

        result = transfer_metaplex_nft(cluster, asset_key, sender_key, sender_private_key, dest_key)
        print(result)

    if parsed_args.docs:
        print(mint_metaplex_nft.__doc__)
        print(transfer.__doc__)
