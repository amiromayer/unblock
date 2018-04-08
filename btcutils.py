from binascii import hexlify
from binascii import unhexlify
from hashlib import sha256
from hashlib import sha512
import hmac

import base58
from os import urandom
from cachetools.func import lru_cache
from ecdsa import SECP256k1
from ecdsa.ecdsa import Public_key as _ECDSA_Public_key
from ecdsa.ellipticcurve import INFINITY
import six
import time

from network import BitcoinMainNet
from network import BitcoinTestNet
from keys import incompatible_network_exception_factory
from keys import PrivateKey
from keys import PublicKey
from keys import PublicPair
from utils import chr_py2
from utils import ensure_bytes
from utils import ensure_str
from utils import hash160
from utils import is_hex_string
from utils import long_or_int
from utils import long_to_hex


class Wallet(object):
    def __init__(self,
                 chain_code,
                 depth=0,
                 parent_fingerprint=0,
                 child_number=0,
                 private_exponent=None,
                 private_key=None,
                 public_pair=None,
                 public_key=None,
                 network=None):

        if (not (private_exponent or private_key) and
                not (public_pair or public_key)):
            raise InsufficientKeyDataError(
                "You must supply one of private_exponent or public_pair")

        self.private_key = None
        self.public_key = None
        if private_key:
            if not isinstance(private_key, PrivateKey):
                raise InvalidPrivateKeyError(
                    "private_key must be of type "
                    "bitmerchant.wallet.keys.PrivateKey")
            self.private_key = private_key
        elif private_exponent:
            self.private_key = PrivateKey(
                private_exponent, network=network)

        if public_key:
            if not isinstance(public_key, PublicKey):
                raise InvalidPublicKeyError(
                    "public_key must be of type "
                    "bitmerchant.wallet.keys.PublicKey")
            self.public_key = public_key
        elif public_pair:
            self.public_key = PublicKey.from_public_pair(
                public_pair, network=network)
        else:
            self.public_key = self.private_key.get_public_key()

        if (self.private_key and self.private_key.get_public_key() !=
                self.public_key):
            raise KeyMismatchError(
                "Provided private and public values do not match")

        def h(val, hex_len):
            if isinstance(val, six.integer_types):
                return long_to_hex(val, hex_len)
            elif (isinstance(val, six.string_types) or
                    isinstance(val, six.binary_type)) and is_hex_string(val):
                val = ensure_bytes(val)
                if len(val) != hex_len:
                    raise ValueError("Invalid parameter length")
                return val
            else:
                raise ValueError("Invalid parameter type")

        def l(val):
            if isinstance(val, six.integer_types):
                return long_or_int(val)
            elif (isinstance(val, six.string_types) or
                    isinstance(val, six.binary_type)):
                val = ensure_bytes(val)
                if not is_hex_string(val):
                    val = hexlify(val)
                return long_or_int(val, 16)
            else:
                raise ValueError("parameter must be an int or long")

        self.network = network
        self.depth = l(depth)
        if (isinstance(parent_fingerprint, six.string_types) or
                isinstance(parent_fingerprint, six.binary_type)):
            val = ensure_bytes(parent_fingerprint)
            if val.startswith(b"0x"):
                parent_fingerprint = val[2:]
        self.parent_fingerprint = b"0x" + h(parent_fingerprint, 8)
        self.child_number = l(child_number)
        self.chain_code = h(chain_code, 64)

    def get_private_key_hex(self):
        return ensure_bytes(self.private_key.get_key())

    def get_public_key_hex(self, compressed=True):
        return ensure_bytes(self.public_key.get_key(compressed))

    @property
    def identifier(self):
        key = self.get_public_key_hex()
        return ensure_bytes(hexlify(hash160(unhexlify(ensure_bytes(key)))))

    @property
    def fingerprint(self):
        return b'0x' + self.identifier[:8]

    def create_new_address_for_user(self, user_id):
        max_id = 0x80000000
        if user_id < 0 or user_id > max_id:
            raise ValueError(
                "Invalid UserID. Must be between 0 and %s" % max_id)
        return self.get_child(user_id, is_prime=False, as_private=False)

    def get_child_for_path(self, path):
        path = ensure_str(path)

        if not path:
            raise InvalidPathError("%s is not a valid path" % path)

        # Figure out public/private derivation
        as_private = True
        if path.startswith("M"):
            as_private = False
        if path.endswith(".pub"):
            as_private = False
            path = path[:-4]

        parts = path.split("/")
        if len(parts) == 0:
            raise InvalidPathError()

        child = self
        for part in parts:
            if part.lower() == "m":
                continue
            is_prime = None  # Let primeness be figured out by the child number
            if part[-1] in "'p":
                is_prime = True
                part = part.replace("'", "").replace("p", "")
            try:
                child_number = long_or_int(part)
            except ValueError:
                raise InvalidPathError("%s is not a valid path" % path)
            child = child.get_child(child_number, is_prime)
        if not as_private:
            return child.public_copy()
        return child

    @lru_cache(maxsize=1024)
    def get_child(self, child_number, is_prime=None, as_private=True):
       
        boundary = 0x80000000

        # Note: If this boundary check gets removed, then children above
        # the boundary should use private (prime) derivation.
        if abs(child_number) >= boundary:
            raise ValueError("Invalid child number %s" % child_number)

        if is_prime is None:
            # Prime children are either < 0 or > 0x80000000
            if child_number < 0:
                child_number = abs(child_number)
                is_prime = True
            else:
                is_prime = False
        else:
            if child_number < 0 or child_number >= boundary:
                raise ValueError(
                    "Invalid child number. Must be between 0 and %s" %
                    boundary)

        if not self.private_key and is_prime:
            raise ValueError(
                "Cannot compute a prime child without a private key")

        if is_prime:
            child_number = child_number + boundary
        child_number_hex = long_to_hex(child_number, 8)

        if is_prime:
            data = b'00' + self.private_key.get_key()
        else:
            data = self.get_public_key_hex()
        data += child_number_hex

        I = hmac.new(
            unhexlify(ensure_bytes(self.chain_code)),
            msg=unhexlify(ensure_bytes(data)),
            digestmod=sha512).digest()
        # Split I into its 32 Byte components.
        I_L, I_R = I[:32], I[32:]

        if long_or_int(hexlify(I_L), 16) >= SECP256k1.order:
            raise InvalidPrivateKeyError("The derived key is too large.")

        c_i = hexlify(I_R)
        private_exponent = None
        public_pair = None
        if self.private_key:
            private_exponent = (
                (long_or_int(hexlify(I_L), 16) +
                 long_or_int(self.private_key.get_key(), 16))
                % SECP256k1.order)
        else:
            g = SECP256k1.generator
            I_L_long = long_or_int(hexlify(I_L), 16)
            point = (_ECDSA_Public_key(g, g * I_L_long).point +
                     self.public_key.to_point())
            # I_R is the child's chain code
            public_pair = PublicPair(point.x(), point.y())

        child = self.__class__(
            chain_code=c_i,
            depth=self.depth + 1, # go deeper
            parent_fingerprint=self.fingerprint,
            child_number=child_number_hex,
            private_exponent=private_exponent,
            public_pair=public_pair,
            network=self.network)
        if child.public_key.to_point() == INFINITY:
            raise InfinityPointException("The point at infinity is invalid.")
        if not as_private:
            return child.public_copy()
        return child

    def public_copy(self):
        return self.__class__(
            chain_code=self.chain_code,
            depth=self.depth,
            parent_fingerprint=self.parent_fingerprint,
            child_number=self.child_number,
            public_pair=self.public_key.to_public_pair(),
            network=self.network)

    def crack_private_key(self, child_private_key):
        if self.private_key:
            raise AssertionError("You already know the private key")
        if child_private_key.parent_fingerprint != self.fingerprint:
            raise ValueError("This is not a valid child")
        if child_private_key.child_number >= 0x80000000:
            raise ValueError(
                "Cannot crack private keys from private derivation")

        # Duplicate the public child derivation
        child_number_hex = long_to_hex(child_private_key.child_number, 8)
        data = self.get_public_key_hex() + child_number_hex
        I = hmac.new(
            unhexlify(ensure_bytes(self.chain_code)),
            msg=unhexlify(ensure_bytes(data)),
            digestmod=sha512).digest()
        I_L, I_R = I[:32], I[32:]
        privkey = PrivateKey(long_or_int(hexlify(I_L), 16),
                             network=self.network)
        parent_private_key = child_private_key.private_key - privkey
        return self.__class__(
            chain_code=self.chain_code,
            depth=self.depth,
            parent_fingerprint=self.parent_fingerprint,
            child_number=self.child_number,
            private_key=parent_private_key,
            network=self.network)

    def export_to_wif(self):
        # https://en.bitcoin.it/wiki/Wallet_import_format 
        extended_key_hex = self.private_key.get_extended_key()
        extended_key_bytes = unhexlify(ensure_bytes(extended_key_hex)) + b'\01'
        return base58.b58encode_check(extended_key_bytes)

    def serialize(self, private=True):
        if private and not self.private_key:
            raise ValueError("Cannot serialize a public key as private")

        if private:
            network_version = long_to_hex(
                self.network.EXT_SECRET_KEY, 8)
        else:
            network_version = long_to_hex(
                self.network.EXT_PUBLIC_KEY, 8)
        depth = long_to_hex(self.depth, 2)
        parent_fingerprint = self.parent_fingerprint[2:] 
        child_number = long_to_hex(self.child_number, 8)
        chain_code = self.chain_code
        ret = (network_version + depth + parent_fingerprint + child_number +
               chain_code)
        if private:
            ret += b'00' + self.private_key.get_key()
        else:
            ret += self.get_public_key_hex(compressed=True)
        return ensure_bytes(ret.lower())

    def serialize_b58(self, private=True):
        return ensure_str(
            base58.b58encode_check(
                unhexlify(ensure_bytes(self.serialize(private)))))

    def to_address(self):
        # https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses
        key = unhexlify(ensure_bytes(self.get_public_key_hex()))
        # Get the hash160 of the key
        hash160_bytes = hash160(key)
        network_hash160_bytes = \
            chr_py2(self.network.PUBKEY_ADDRESS) + hash160_bytes
        return ensure_str(base58.b58encode_check(network_hash160_bytes))

    @classmethod
    def deserialize(cls, key, network=None):
        
        if len(key) in [78, (78 + 32)]:
            pass
        else:
            key = ensure_bytes(key)
            if len(key) in [78 * 2, (78 + 32) * 2]:
                # a hexlified non-base58 key
                key = unhexlify(key)
            elif len(key) == 111:
                # base58 encoded string
                key = base58.b58decode_check(key)
      
        version, depth, parent_fingerprint, child, chain_code, key_data = (
            key[:4], key[4], key[5:9], key[9:13], key[13:45], key[45:])

        version_long = long_or_int(hexlify(version), 16)
        exponent = None
        pubkey = None
        point_type = key_data[0]
        if not isinstance(point_type, six.integer_types):
            point_type = ord(point_type)
        if point_type == 0:
            # Private key
            if version_long != network.EXT_SECRET_KEY:
                raise incompatible_network_exception_factory(
                    network.NAME, network.EXT_SECRET_KEY,
                    version)
            exponent = key_data[1:]
        elif point_type in [2, 3, 4]:# Compressed public coordinates
            if version_long != network.EXT_PUBLIC_KEY:
                raise incompatible_network_exception_factory(
                    network.NAME, network.EXT_PUBLIC_KEY,
                    version)
            pubkey = PublicKey.from_hex_key(key_data, network=network)
            pubkey.compressed = False
        else:
            raise ValueError("Invalid key_data prefix, got %s" % point_type)

        def l(byte_seq):
            if byte_seq is None:
                return byte_seq
            elif isinstance(byte_seq, six.integer_types):
                return byte_seq
            return long_or_int(hexlify(byte_seq), 16)

        return cls(depth=l(depth),
                   parent_fingerprint=l(parent_fingerprint),
                   child_number=l(child),
                   chain_code=l(chain_code),
                   private_exponent=l(exponent),
                   public_key=pubkey,
                   network=network)

    @classmethod
    def from_master_secret(cls, seed, network):

        # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format  
        seed = ensure_bytes(seed)
        # Given a seed S of at least 128 bits, but 256 is advised
        # Calculate I = HMAC-SHA512(key="Bitcoin seed", msg=S)
        I = hmac.new(b"Bitcoin seed", msg=seed, digestmod=sha512).digest()
        # Split I into two 32-byte sequences, IL and IR.
        I_L, I_R = I[:32], I[32:]
        # Use IL as master secret key, and IR as master chain code.
        return cls(private_exponent=long_or_int(hexlify(I_L), 16),
                   chain_code=long_or_int(hexlify(I_R), 16),
                   network=network)

    @classmethod
    def from_master_secret_slow(cls, password, network=None):
       
        key = ensure_bytes(password)
        data = unhexlify(b"0" * 64)  # 256-bit 0
        for i in range(50000):
            data = hmac.new(key, msg=data, digestmod=sha256).digest()
        return cls.from_master_secret(data, network)

    def __eq__(self, other):
        attrs = [
            'chain_code',
            'depth',
            'parent_fingerprint',
            'child_number',
            'private_key',
            'public_key',
            'network',
        ]
        return other and all(
            getattr(self, attr) == getattr(other, attr) for attr in attrs)

    def __ne__(self, other):
        return not self == other

    __hash__ = object.__hash__

    @classmethod
    def new_random_wallet(cls, user_entropy=None, network=None):
      
        seed = str(urandom(64))  # 512/8
        # by pybitcointools:
        seed += str(int(time.time()*10**6))
        if user_entropy:
            user_entropy = str(user_entropy) 
            seed += user_entropy
        return cls.from_master_secret(seed, network=network)


class InvalidPathError(Exception):
    pass


class InsufficientKeyDataError(ValueError):
    pass


class InvalidPrivateKeyError(ValueError):
    pass


class InvalidPublicKeyError(ValueError):
    pass


class KeyMismatchError(ValueError):
    pass


class InfinityPointException(Exception):
    pass
