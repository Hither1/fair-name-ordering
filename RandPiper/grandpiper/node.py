import dataclasses
import enum
import functools
import heapq
import hashlib
import logging
import math
import signal
import time as _time
import typing
# import warnings
import zmq

from collections import Counter
from typing import Dict, List, Optional

# Using RS code implementation of https://github.com/brownan/Reed-Solomon
import grandpiper.Reed_Solomon.rs

from grandpiper.ed25519 import Scalar, Point, KeyPair

NODE_INFOS = load_config()

@dataclasses.dataclass(order=True)
class MessageQueueItem:
    round: int
    phase: Phase
    timestamp: float
    content: bytes

class NodeStatus(enum.IntEnum):
    NORMAL = enum.auto()
    FAILED = enum.auto()
    ADVERSARIAL = enum.auto()


####################################################################################################################
####################################################################################################################
# BEGIN RANDOMNESS BEACON
####################################################################################################################


####################################################################################################################
# END RANDOMNESS BEACON
####################################################################################################################
####################################################################################################################

####################################################################################################################
####################################################################################################################
# BEGIN LEADER SELECTION
####################################################################################################################

