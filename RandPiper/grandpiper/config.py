import argparse
import getpass
import logging
import math
import os
import sys
import subprocess
import time
import random
from datetime import datetime, timezone
from typing import Optional, List

import grandpiper.cliconfig
from grandpiper.ed25519 import Point, Scalar, KeyPair
import grandpiper.pvss as pvss

N = 7  # Total number of nodes
T = math.ceil(N / 3)  # Maximum # of allowed byzantine nodes
F = T - 1  # Actual # of byzantine nodes

MODE = "testing"
# MODE = "production"

NETWORK_CONFIG = 'localhost'
if getpass.getuser() == 'ec2-user':
    NETWORK_CONFIG = 'amazon'

# DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_LOG_LEVEL = logging.DEBUG

NODE_ID: Optional[int] = None
INITIAL_BEACON = bytes.fromhex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")

PROTOCOL_START_CONNECT_DELAY = 10.0
PROTOCOL_STARTUP_DELAY = 5.0
PROTOCOL_START_TIME = time.time() + PROTOCOL_START_CONNECT_DELAY + PROTOCOL_STARTUP_DELAY

_PHASE_DURATION = 5.0

PROPOSE_PHASE_DURATION = _PHASE_DURATION
VOTE_PHASE_DURATION = _PHASE_DURATION
VOTE_CERT_PHASE_DURATION = _PHASE_DURATION
COMMIT_PHASE_DURATION = _PHASE_DURATION
ROUND_DURATION = PROPOSE_PHASE_DURATION + VOTE_PHASE_DURATION + VOTE_CERT_PHASE_DURATION + COMMIT_PHASE_DURATION

MAX_TIMEOUT = 3.0  # 0.0 to disable

FAST_MODE_ENABLED = False

CONFIG_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config"))
CONFIG_NETWORK_DIR = os.path.join(CONFIG_BASE_DIR, f"network")
CONFIG_NETWORK_PATH = os.path.join(CONFIG_NETWORK_DIR, NETWORK_CONFIG + ".txt")

NODE_INFOS: List = []

NUM_ROUNDS = 500


def init_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('node_id', type=int, nargs='?', help="the node's id (0-based)")
    parser.add_argument("-n", default=N, type=int, help="the total number of nodes")
    parser.add_argument("--start-at", type=str, help="protocol start time, UTC, HH:MM:SS format")
    parser.add_argument("--connection-lead-time", type=float,
                        help="number of seconds to protocol start, when the nodes start to connect to the other nodes")
    parser.add_argument("--propose-duration", type=float, help="duration of the propose phase in seconds")
    parser.add_argument("--acknowledge-duration", type=float, help="duration of the acknowlege phase in seconds")
    parser.add_argument("--vote-duration", type=float, help="duration of the vote phase in seconds")
    parser.add_argument("--max-timeout", type=float,
                        help="time until the receive call is always stopped (and restarted)")

    parser.add_argument("--num-rounds", type=int, help='number of rounds the protocol should run')
    parser.add_argument("--network-config", type=str,
                        help="name of the network configuration (from setup/network) to use")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--sync-mode", action="store_true")
    group.add_argument("--fast-mode", action="store_true")
    return parser


def parse_cli_arguments():
    global N, F, T
    global NODE_ID
    global PROTOCOL_START_CONNECT_DELAY
    global PROTOCOL_START_TIME
    global PROPOSE_PHASE_DURATION  # propose
    global VOTE_PHASE_DURATION  # vote
    global VOTE_CERT_PHASE_DURATION  # vote-cert
    global COMMIT_PHASE_DURATION  # commit
    global ROUND_DURATION
    global MAX_TIMEOUT
    global FAST_MODE_ENABLED
    global NETWORK_CONFIG
    global NUM_ROUNDS

    arg_parser = init_arg_parser()
    args = arg_parser.parse_args()

    if args.node_id is not None:
        NODE_ID = args.node_id

    assert NODE_ID is not None
    N = args.n or N
    T = math.ceil(N / 3)
    F = T - 1

    PROTOCOL_START_CONNECT_DELAY = args.connection_lead_time or PROTOCOL_START_CONNECT_DELAY
    if args.start_at:
        t = datetime.strptime(args.start_at, '%Y-%m-%d %H:%M:%S')
        t = t.replace(tzinfo=timezone.utc).astimezone(tz=None)
        PROTOCOL_START_TIME = t.timestamp()

    PROPOSE_PHASE_DURATION = args.propose_duration or PROPOSE_PHASE_DURATION
    VOTE_PHASE_DURATION = args.vote_duration or VOTE_PHASE_DURATION
    ROUND_DURATION = PROPOSE_PHASE_DURATION + VOTE_PHASE_DURATION + VOTE_CERT_PHASE_DURATION + COMMIT_PHASE_DURATION

    if args.max_timeout is not None:
        MAX_TIMEOUT = args.max_timeout

    NETWORK_CONFIG = args.network_config or NETWORK_CONFIG
    FAST_MODE_ENABLED = args.fast_mode

    if args.num_rounds is not None:
        NUM_ROUNDS = args.num_rounds


def print_info():
    logging.getLogger("config").info("parsing cli arguments: sys.argv=%s", str(sys.argv))

    print()
    print("=" * 60)
    print()
    print(f"  GRANDPIPER NODE")
    print()
    print(f"  node id:    {NODE_ID: >5}")
    print(f"  process id: {os.getpid(): >5}")
    print()
    print(f"  total number of nodes            (N): {N}")
    print(f"  recovery threshold               (T): {T: >{len(str(N))}}")
    print(f"  max. number of adversarial nodes (F): {F: >{len(str(N))}}")
    print()
    print("  current time:       ", datetime.now())
    print("  protocol starts at: ", datetime.fromtimestamp(PROTOCOL_START_TIME))
    print()
    print("  phase durations:")
    print(f"   - propose:     {PROPOSE_PHASE_DURATION:5.1f} seconds")
    print(f"   - vote:        {VOTE_PHASE_DURATION:5.1f} seconds")
    print()
    print(f"  max timeout: {MAX_TIMEOUT:.1f} seconds")
    print(f"  fast mode: {'enabled' if FAST_MODE_ENABLED else 'disabled'}")
    print()
    print("=" * 60)
    print(flush=True)


def load_network_config():
    addresses = []
    ports = []
    with open(CONFIG_NETWORK_PATH, 'r') as f:
        for line in f.read().splitlines():
            addr, port = line.split(":")
            addresses.append(addr)
            ports.append(int(port))
    return addresses, ports


def load_config(n=None):
    if n is None:
        n = N

    from grandpiper import merkle
    from grandpiper.data import ShareCorrectnessProof, NodeInfo

    CONFIG_DIR = os.path.join(CONFIG_BASE_DIR, f"{n:03}")
    if not os.path.exists(CONFIG_DIR):
        assert NETWORK_CONFIG != "amazon", "do never generate config on the fly for amazon tests"
        logging.warning("config does not exist, generating one on the fly")
        return generate_sample_config()

    addresses, ports = load_network_config()
    node_infos = []


    # Reading from the files to get the and initial shares and proof
    for node_id in range(n):
        if MODE == "testing" or NODE_ID == node_id:
            with open(os.path.join(CONFIG_DIR, f"{node_id:03}.secret_key"), "rb") as f:
                keypair = KeyPair(f.read())
            public_key = keypair.public_key
            secrets = []
            for t in range(T):
                with open(os.path.join(CONFIG_DIR, f"{node_id:03}.secrets"), "rb") as f:
                    secret = Scalar.from_bytes(f.read())
                    secrets.append(secret)
        else:
            keypair = None
            initial_secret = None
            with open(os.path.join(CONFIG_DIR, f"{node_id:03}.public_key"), "rb") as f:
                public_key = Point.from_bytes(f.read())

        with open(os.path.join(CONFIG_DIR, f"{node_id:03}.pvss_shares"), "rb") as f:
            # f.read(32) means read at most 32 bytes from the file
            # Repeat for t + 1 times: the t (fake) previous rounds and e = 1
            for t in range(T):
                shares = [Point.from_bytes(f.read(32)) for i in range(n - 1)]
        with open(os.path.join(CONFIG_DIR, f"{node_id:03}.pvss_proof"), "rb") as f:
            # Repeat for t + 1 times: the t (fake) previous rounds and e = 1
            for t in range(T):
                proof = ShareCorrectnessProof(
                    commitments=[Point.from_bytes(f.read(32)) for i in range(n - 1)],
                    challenge=Scalar.from_bytes(f.read(32)),
                    responses=[Scalar.from_bytes(f.read(32)) for i in range(n - 1)],
                )

        merkle_root = merkle.compute_root([merkle.Hash(bytes(es)) for es in shares])
        node_infos.append(
            NodeInfo(node_id, addresses[node_id], ports[node_id], keypair,
                     public_key, secrets, shares, proof)
        )



    return node_infos


# Generating configuration
def generate_sample_config(n=None, write_to_disk=False):
    if n is None:
        n = N

    from grandpiper import merkle, pvss
    from grandpiper.data import NodeInfo

    addresses, ports = load_network_config()
    node_infos = []
    t = math.ceil(n / 3)
    keypairs = [KeyPair.random() for node_id in range(n)]

    for node_id, keypair in enumerate(keypairs):

        node_infos.append(
            NodeInfo(node_id, addresses[node_id], ports[node_id], keypair, keypair.public_key, [[[]]], [[]])
        )

    # randomly select the leaders of last t rounds (hypothetical, before the start of the protocol)
    prev_leaders_list = list(random.sample(n, T))

    # randomly select beacon values of last t rounds and the current (e = 1)
    for pre_round in range(T + 1):
        l = prev_leaders_list[pre_round]
        receiver_pks = [kp.public_key for j, kp in enumerate(keypairs) if j != l]
        secret, shares, proof = pvss.share_random_secret(receiver_pks, t)

        for node_id, keypair in enumerate(keypairs):
            if i == l:
                continue
            node_infos[node_id].secrets[l].append(secret)
            node_infos[node_id].encrypted_shares_queue[l].append(shares)
            node_infos[node_id].witnesses_queue[l].append(proof)

    if write_to_disk:
        save_config(node_infos)
    return node_infos


def save_config(node_infos):
    CONFIG_DIR = os.path.join(CONFIG_BASE_DIR, f"{len(node_infos):03}")
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)
    for node_id, node_info in enumerate(node_infos):
        with open(os.path.join(CONFIG_DIR, f"{node_id:03}.secret_key"), "wb") as f:
            f.write(node_info.keypair.seed)
        with open(os.path.join(CONFIG_DIR, f"{node_id:03}.public_key"), "wb") as f:
            f.write(node_info.public_key.value)

        # Queues
        with open(os.path.join(CONFIG_DIR, f"{node_id:03}.secrets"), "wb") as f:
            for t in range(T):
                f.write(node_info.initial_secret.value)
        with open(os.path.join(CONFIG_DIR, f"{node_id:03}.pvss_shares"), "wb") as f:
            for i in range(N):
                for share in node_info.encrypted_shares_queue[i]:
                    f.write(share.value)
        with open(os.path.join(CONFIG_DIR, f"{node_id:03}.pvss_proofs"), "wb") as f:
            # loop through the queues kept for each node
            for i in range(N):
                for c in node_info.witnesses_queue.commitments:
                    f.write(c.value)
                f.write(node_info.witnesses_queue.challenge.value)
                for r in node_info.witnesses_queue.responses:
                    f.write(r.value)


logging.basicConfig(level=DEFAULT_LOG_LEVEL)
logging.debug(f"use cli config: {grandpiper.cliconfig.USE_CLI_CONFIG}")

if NETWORK_CONFIG == 'amazon':
    logging.debug("loading parameter for N and NODE_ID from amazon network config")

    dnsname = subprocess.Popen(["curl", "-s", "http://169.254.169.254/latest/meta-data/public-hostname"],
                               stdout=subprocess.PIPE).communicate()[0].decode()

    addresses, _ = load_network_config()
    for i, a in enumerate(addresses):
        if a == dnsname:
            NODE_ID = i
            break
    N = len(addresses)

    logging.debug(f"loaded parameters: N={N}, NODE_ID={NODE_ID}")

if grandpiper.cliconfig.USE_CLI_CONFIG:
    parse_cli_arguments()
    print_info()

OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'output'))
if NETWORK_CONFIG != 'amazon':
    OUTPUT_DIR = os.path.join(OUTPUT_DIR, str(NODE_ID))
PID_FILE_PATH = os.path.join(OUTPUT_DIR, 'pid')
RESULT_FILE_PATH = os.path.join(OUTPUT_DIR, 'result')
LOG_FILE_PATH = os.path.join(OUTPUT_DIR, 'node.log')
