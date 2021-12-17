from api.metaplex_api import MetaplexAPI
from cryptography.fernet import Fernet
import json
import base58
import time
import random
import string
import argparse


# Constants
DEV_NET = "https://api.devnet.solana.com/"
TEST_NET = "https://api.testnet.solana.com/"
MAIN_NET = "https://api.mainnet-beta.solana.com/"
CLUSTER_NAME_RPC_ENDPOINT_MAP = {"main_net": MAIN_NET, "test_net": TEST_NET, "dev_net": DEV_NET}


def mint_metaplex_nft(custodian_public_key, custodian_private_key, link_to_json_file, solana_cluster="dev_net", token_name=None, token_symbol=None, debug=True):
    # Docstring
    """#################### mint_metaplex_nft() ####################
    Function to mint a Metaplex compliant NFT to a specified wallet on Solana

    Parameters:
        - custodian_public_key (str): String of the custodian's public Solana key
        - custodian_private_key ([64]): A byte array of len(64) of the custodian's private Solana key
        - solana_cluster (str): String representing cluster name, options are: 'main_net', 'test_net', and 'dev_net'
        - token_name (str)(Optional): String representing the name of the token on the Token Metadata Program
        - token_symbol (str)(Optional): String representing the symbol of the token on the Token Metadata Program
        - debug (bool)(Optional): Default=True, If True, adds some extra logging

    Returns:
        Transaction Hash (str)
    ############################# end ###############################
    """

    # TODO: Determine if the custodian's private key will be passed to this function encrypted or not
    # If encrypted, we need to pull the decryption_key from the environment somehow. For now, I'm just
    # assuming the key is unencrypted as I'm not sure how Elixir Ports work
    server_decryption_key = Fernet.generate_key().decode("ascii")


    # Input validity checks
    if solana_cluster not in CLUSTER_NAME_RPC_ENDPOINT_MAP:
        raise ValueError('Invalid Solana Cluster Name')

    if custodian_public_key is None:
        raise ValueError('custodian_public_key cannot be None')

    if custodian_private_key is None:
        raise ValueError('custodian_private_key cannot be None')

    if len(custodian_private_key) != 64:
        raise ValueError('custodian_private_key should be a byte array with len(64)')

    if link_to_json_file is None:
        raise ValueError('link_to_json_file cannot be None')

    # Init the MetaplexAPI
    private_key = bytes(custodian_private_key)
    cfg = {
        "PRIVATE_KEY": base58.b58encode(private_key).decode("ascii"),
        "PUBLIC_KEY": custodian_public_key,
        "DECRYPTION_KEY": server_decryption_key
    }
    api = MetaplexAPI(cfg)

    rpc_endpoint = CLUSTER_NAME_RPC_ENDPOINT_MAP[solana_cluster]

    # Per Metaplex docs this is mapped to "seller_fee_basis_points" desc: "royalties percentage awarded to creators"
    # We don't want any royalties so this should always be 0
    fees = 0

    # Generate a random name and symbol if one was not provided
    letters = string.ascii_uppercase
    if token_name is None:
        token_name = ''.join([random.choice(letters) for i in range(32)])

    if token_symbol is None:
       token_symbol = ''.join([random.choice(letters) for i in range(10)])

    result = api.deploy(rpc_endpoint, token_name, token_symbol, fees, max_timeout=180)
    if debug:
        print(f"***[DEBUG]: api.deploy.result:: {result}")

    contract_key = json.loads(result).get('contract')
    if debug:
        print(f"***[DEBUG]: contract_key:: {contract_key}")

    ###
    # !!!WARNING, HERE BE DRAGONS!!!
    # You might think it horrifying to see an arbitrary sleep sitting in the middle of a function,
    # and you would be right. Have not determined why yet but despite checking with Solana over RPC
    # that the deploy transaction is both confirmed and finalized, minting randomly fails because it
    # cannot find the previously deployed contract. Current theory is this is a progagation issue
    # with the network, which is why the sleep "fixes" it. Leaving it here for now but will dig
    # deeper to get rid of it.
    ###
    time.sleep(30)

    result = api.mint(rpc_endpoint, contract_key, custodian_public_key, link_to_json_file)
    if debug:
        print(f"***[DEBUG]: api.mint.result:: {result}")

    # Return the mint transaction hash
    return json.loads(result).get('result')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Aleo -> Solana Bridge CLI')

    parser.add_argument('--mint_metaplex_nft', nargs="+", help='Calls function to mint a Metaplex compliant NFT into a specified wallet on Solana.')

    parser.add_argument('-send', action='store_true', help='TODO: Not yet implemented, but will be a function to transfer an NFT from one account to another.')
    parser.add_argument('--docs', action='store_true', help='Returns the docstring of all functions')

    args = parser.parse_args()

    if args.mint_metaplex_nft:
        # Note: I tried to do this with named arguments (e.g. '--custodian_public_key "<key>"') instead of
        # an argument array, but it wasn't working with Elixir's System.cmd()
        public_key = args.mint_metaplex_nft[0]
        private_key = json.loads(args.mint_metaplex_nft[1])
        link = args.mint_metaplex_nft[2]

        cluster = "dev_net"
        if len(args.mint_metaplex_nft) > 3:
            cluster = args.cluster

        token_name = None
        if len(args.mint_metaplex_nft) > 4:
            token_name = args.token_name

        token_symbol = None
        if len(args.mint_metaplex_nft) > 5:
            token_symbol = args.token_symbol

        debug = True
        if len(args.mint_metaplex_nft) > 6:
            debug = args.debug

        mint_metaplex_nft(public_key, private_key, link, cluster, token_name, token_symbol, debug)


    if args.send:
        print('STUB: This function has not been built yet')

    if args.docs:
        print(mint_metaplex_nft.__doc__)