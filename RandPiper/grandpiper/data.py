import enum
import hashlib
import struct

from dataclasses import dataclass
from typing import Callable, Optional, Union, List, ByteString

from grandpiper.config import N, T
import grandpiper.ed25519 as ed25519
from grandpiper.ed25519 import Scalar, Point, KeyPair, SecretKey, verify_attached
from grandpiper.merkle import branch_length, Hash

from hashlib import sha256
from typing import List, NewType
Hash = NewType("Hash", bytes)

INT_SIZE = 4
SCALAR_SIZE = 32
POINT_SIZE = 32
HASH_SIZE = 32
SIGNATURE_SIZE = 64

MIN_MESSAGE_SIZE = 4 + 4 + 4 + 64
MAX_MESSAGE_SIZE = 1024 ** 2



@dataclass
class Serializeable:
    def __post_init__(self):
        self._serialized: memoryview = None
        self._size: int = 0

    @property
    def size(self):
        if not self._size:
            if self._serialized:
                self._size = len(self._serialized)
            else:
                self._size = getattr(type(self), "SIZE", 0)
                if not self._size:
                    self._size = self.compute_size()
        return self._size

    @property
    def serialized(self):
        assert self._serialized
        return self._serialized

    def serialize(self):
        if not self._serialized:
            s = Serializer(self.size)
            s.write_object(self)
        return self._serialized

    @classmethod
    def deserialize(cls, buffer):
        s = Serializer(buffer)
        return s.read_object(cls)

    def _serialize(self, s: "Serializer"):
        raise NotImplementedError

    def _deserialize(self, s: "Serializer"):
        raise NotImplementedError

class Signature(Serializeable):
    def __init__(self, buffer: Optional[bytearray]):
        super().__init__()

        self._get_data: Optional[Callable[[], ByteString]] = None
        self._signing_key: Optional[SecretKey] = None
        self._signed_data: Optional[ByteString] = None

        if buffer:
            self._serialized = memoryview(buffer)

    @staticmethod
    def create_later(get_data: Callable[[], ByteString], signing_key: SecretKey):
        sig = Signature(None)
        sig._get_data = get_data
        sig._signing_key = signing_key
        sig._signed_data = None
        return sig

    @property
    def signed_data(self):
        return self._signed_data

    def _serialize(self, s: "Serializer"):
        if self._serialized:
            s.write_bytes(self._serialized)
        else:
            assert self._get_data
            assert self._signing_key
            self._signed_data = self._get_data()
            self._serialized = memoryview(ed25519.sign_detached(self._signed_data, self._signing_key))
            s.write_bytes(self._serialized)

    def __repr__(self):
        return f"Signature({repr(bytes(self._serialized))})"

class Serializer:

    offset: int
    buffer: bytearray
    view: memoryview

    def __init__(self, buffer_or_buffersize):
        if isinstance(buffer_or_buffersize, int):
            self.buffer = bytearray(buffer_or_buffersize)
        else:
            self.buffer = buffer_or_buffersize
        self.view = memoryview(self.buffer)
        self.offset = 0

    def write_bytes(self, value):
        self.buffer[self.offset: self.offset + len(value)] = value
        self.offset += len(value)

    def read_bytes(self, num_bytes):
        value = self.view[self.offset: self.offset + num_bytes]
        self.offset += num_bytes
        return value

    def write_u32(self, value: int):
        struct.pack_into("I", self.buffer, self.offset, value)
        self.offset += 4

    def write_u32s(self, values: List[int]):
        struct.pack_into(f"{len(values)}I", self.buffer, self.offset, *values)
        self.offset += 4 * len(values)

    def read_u32(self) -> int:
        value = struct.unpack_from("I", self.buffer, self.offset)[0]
        self.offset += 4
        return value

    def read_u32s(self, num_values: int) -> List[int]:
        values = list(struct.unpack_from(f"{num_values}I", self.buffer, self.offset))
        self.offset += 4 * num_values
        return values

    def write_signature(self, value: Signature):
        self.write_object(value)

    def write_signatures(self, values: List[Signature]):
        for value in values:
            self.write_object(value)

    def read_signature(self) -> Signature:
        return Signature(self.read_bytes(SIGNATURE_SIZE))

    def read_signatures(self, num_values: int) -> List[Signature]:
        return [Signature(self.read_bytes(SIGNATURE_SIZE)) for i in range(num_values)]

    def write_hash(self, value: Hash):
        self.write_bytes(value)

    def write_hashes(self, values: List[Hash]):
        for value in values:
            self.write_bytes(value)

    def read_hash(self) -> Hash:
        return Hash(bytes(self.read_bytes(HASH_SIZE)))

    def read_hashes(self, num_values: int) -> List[Hash]:
        return [Hash(bytes(self.read_bytes(HASH_SIZE))) for i in range(num_values)]

    def write_scalar(self, value: Scalar):
        self.write_bytes(value.value)

    def write_scalars(self, values: List[Scalar]):
        for value in values:
            self.write_bytes(value.value)

    def read_scalar(self) -> Scalar:
        return Scalar.from_bytes(self.read_bytes(SCALAR_SIZE))

    def read_scalars(self, num_values: int) -> List[Scalar]:
        return [Scalar.from_bytes(self.read_bytes(SCALAR_SIZE)) for i in range(num_values)]

    def write_point(self, value: Point):
        self.write_bytes(value.value)

    def write_points(self, values: List[Point]):
        for value in values:
            self.write_bytes(value.value)

    def read_point(self) -> Point:
        return Point.from_bytes(self.read_bytes(POINT_SIZE))

    def read_points(self, num_values: int) -> List[Point]:
        return [Point.from_bytes(self.read_bytes(POINT_SIZE)) for i in range(num_values)]

    def write_object(self, obj: Serializeable):
        start = self.offset
        obj._serialize(self)
        if self.offset - start != obj.size:
            raise ValueError(f"Failed to write object of type {type(obj)}, invalid size!")
        obj._serialized = self.view[start: self.offset]

    def read_object(self, obj_type):
        obj = object.__new__(obj_type)
        obj.__post_init__()
        start = self.offset
        obj._deserialize(self)
        if self.offset - start != obj.size:
            raise ValueError(f"Failed to read object of type {type(obj)}, invalid size!")
        obj._serialized = self.view[start: self.offset]
        return obj

@dataclass
class ShareCorrectnessProof(Serializeable):

    commitments: List[Point]
    challenge: Scalar
    responses: List[Scalar]

    SIZE = (N - 1) * (POINT_SIZE + SCALAR_SIZE) + SCALAR_SIZE

    def _serialize(self, s: Serializer):
        s.write_points(self.commitments)
        s.write_scalar(self.challenge)
        s.write_scalars(self.responses)

    def _deserialize(self, s: Serializer):
        self.commitments = s.read_points(N - 1)
        self.challenge = s.read_scalar()
        self.responses = s.read_scalars(N - 1)

@dataclass
class ShareDecryptionProof(Serializeable):

    challenge: Scalar
    response: Scalar

    SIZE = 2 * SCALAR_SIZE

    def _serialize(self, s: Serializer):
        s.write_scalar(self.challenge)
        s.write_scalar(self.response)

    def _deserialize(self, s: Serializer):
        self.challenge = s.read_scalar()
        self.response = s.read_scalar()


@dataclass
class RecoveredShare(Serializeable):

    share: Point
    proof: ShareDecryptionProof
    merkle_branch: List[Hash]

    # TODO: check if size of branch is correct, see also _deserialize!
    SIZE = POINT_SIZE + ShareDecryptionProof.SIZE + branch_length(N - 1) * HASH_SIZE

    def _serialize(self, s: Serializer):
        s.write_point(self.share)
        s.write_object(self.proof)
        #s.write_hashes(self.merkle_branch)

    def _deserialize(self, s: Serializer):
        self.share = s.read_point()
        self.proof = s.read_object(ShareDecryptionProof)
        #self.merkle_branch = s.read_hashes(branch_length(N - 1))

class Phase(enum.IntEnum):
    Propose = 1
    Vote = 2


class MessageType(enum.IntEnum):

    Propose = enum.auto()

    def to_phase(self):
        return Phase(min(int(self), 3))

class Block(Serializeable):
    encryption_vector: List[Point]
    witness_vector: List[Point]
    hash_previous_block: Hash

    def __init__(self, encryption_vector, witness_vector):
        self.encryption_vector = encryption_vector
        self.witness_vector = witness_vector

    def set_previous_block_hash(self, block): # to be called by the node
        self.hash_previous_block = hash(block)


@dataclass
class ProposeMessage(Serializeable):
    @property
    def type(self):
        return MessageType.Propose

    sender: int
    block: Block
    certificate_signature: Signature

    def compute_size(self):
        return 2 * INT_SIZE + self.block.size + 2 * SIGNATURE_SIZE

    def _serialize(self, s: Serializer):
        s.write_u32(self.type)
        s.write_u32(self.sender)
        s.write_object(self.dataset)
        s.write_signature(self.dataset_header_signature)
        s.write_signature(self.confirmation_certificate_signature)

    def _deserialize(self, s: Serializer):
        assert s.read_u32() == self.type
        self.sender = s.read_u32()
        self.block = s.read_object(Block)
        self.dataset_header_signature = s.read_signature()
        self.confirmation_certificate_signature = s.read_signature()

    @property
    def round_idx(self):
        return self.dataset.round_idx

# TODO: finish implementation of VoteMessage
@dataclass
class VoteMessage(Serializeable):
    @property
    def type(self):
        return MessageType.Vote

    sender: int
    block: Block
    signature: Signature
    certificate_signature: Signature

    def compute_size(self):
        return 2 * INT_SIZE + self.block.size + 2 * SIGNATURE_SIZE

    def _serialize(self, s: Serializer):
        s.write_u32(self.type)
        s.write_u32(self.sender)
        s.write_object(self.dataset)
        s.write_signature(self.signature)
        s.write_signature(self.certificate_signature)

    def _deserialize(self, s: Serializer):
        assert s.read_u32() == self.type
        self.sender = s.read_u32()
        self.block = s.read_object(Block)
        self.dataset_header_signature = s.read_signature()
        self.confirmation_certificate_signature = s.read_signature()

    @property
    def round_idx(self):
        return self.block.round_idx

# TODO: finish implementation of VotecertMessage
@dataclass
class VotecertMessage(Serializeable):
    @property
    def type(self):
        return MessageType.Votecert

    sender: int
    block: Block
    signature: Signature
    certificate_signature: Signature

    def compute_size(self):
        return 2 * INT_SIZE + self.block.size + 2 * SIGNATURE_SIZE

    def _serialize(self, s: Serializer):
        s.write_u32(self.type)
        s.write_u32(self.sender)
        s.write_object(self.dataset)
        s.write_signature(self.signature)
        s.write_signature(self.certificate_signature)

    def _deserialize(self, s: Serializer):
        assert s.read_u32() == self.type
        self.sender = s.read_u32()
        self.block = s.read_object(Block)
        self.dataset_header_signature = s.read_signature()
        self.confirmation_certificate_signature = s.read_signature()

    @property
    def round_idx(self):
        return self.dataset.round_idx

Message = Union[ProposeMessage, VoteMessage, VotecertMessage]

@dataclass
class SignedMessage(Serializeable):
    @property
    def type(self):
        return self.message.type

    message: Message
    signature: Signature

    def compute_size(self):
        return self.message.size + SIGNATURE_SIZE

    def _serialize(self, s: Serializer):
        s.write_object(self.message)
        s.write_signature(self.signature)

    def _deserialize(self, s: Serializer):
        msg_type = get_message_type(s.buffer)
        if msg_type == MessageType.Propose:
            self.message = s.read_object(ProposeMessage)
        elif msg_type == MessageType.Acknowledge:
            self.message = s.read_object(Message)
        elif msg_type == MessageType.Confirm:
            self.message = s.read_object(Message)
        elif msg_type == MessageType.Recover:
            self.message = s.read_object(Message)
        else:
            raise ValueError("invalid message type")
        self.signature = s.read_signature()

    def verify_signature(self, public_key):
        return verify_attached(self.serialized, public_key)

@dataclass
class NodeInfo:
    id: int
    address: str
    port: int
    keypair: Optional[KeyPair]
    public_key: Point
    initial_secret: Scalar
    initial_shares: List[Point]
    initial_proof: ShareCorrectnessProof
    initial_merkle_root: List[Hash]

# A certificate should consist of a list of votes from t+1 distinct honest nodes
class Certificate(Serializeable):
    block: Block
    signer: List[int]
    signatures: List[Signature]
    #def __init__(self):


def get_message_type(data):
    return MessageType(struct.unpack_from("I", data, offset=0)[0])


def get_message_sender(data):
    s = struct.unpack_from("I", data, offset=4)[0]
    if 0 <= s < N:
        return s
    raise ValueError(f"Invalid message sender id {s} (N={N})!")


def get_message_round(data):
    return struct.unpack_from("I", data, offset=8)[0]