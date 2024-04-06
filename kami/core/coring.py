import json
from collections import namedtuple
from dataclasses import dataclass, astuple
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64

import cbor
import msgpack
import pysodium

from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec, utils

from kami.help.helping import codeB64ToB2, intToB64, Reb64, b64ToInt, sceil, nabSextets, codeB2ToB64
from kami.kering import Version, deversify, Serials, Rever, versify, DeserializeError, \
    EmptyMaterialError, InvalidCodeError, InvalidVarRawSizeError, SoftMaterialError, \
    InvalidSoftError, RawMaterialError, InvalidCodeSizeError, ShortageError, \
    UnexpectedCountCodeError, UnexpectedOpCodeError, UnexpectedCodeError, ConversionError

from kami.core import indexing

DSS_SIG_MODE = "fips-186-3"
ECDSA_256r1_SEEDBYTES = 32
ECDSA_256k1_SEEDBYTES = 32


# SAID field labels
Saidage = namedtuple("Saidage", "dollar at id_ i d")

Saids = Saidage(dollar="$id", at="@id", id_="id", i="i", d="d")

def sizeify(ked, kind=None, version=Version):
    """
    Compute serialized size of ked and update version field
    Returns tuple of associated values extracted and or changed by sizeify

    Returns tuple of (raw, proto, kind, ked, version) where:
        raw (str): serialized event as bytes of kind
        proto (str): protocol type as value of Protocolage
        kind (str): serialzation kind as value of Serialage
        ked (dict): key event dict
        version (Versionage): instance

    Parameters:
        ked (dict): key event dict
        kind (str): value of Serials is serialization type
            if not provided use that given in ked["v"]
        version (Versionage): instance supported protocol version for message


    Assumes only supports Version
    """
    if "v" not in ked:
        raise ValueError("Missing or empty version string in key event "
                         "dict = {}".format(ked))

    proto, vrsn, knd, size, _ = deversify(ked["v"])  # extract kind and version
    if vrsn != version:
        raise ValueError("Unsupported version = {}.{}".format(vrsn.major,
                                                              vrsn.minor))

    if not kind:
        kind = knd

    if kind not in Serials:
        raise ValueError("Invalid serialization kind = {}".format(kind))

    raw = dumps(ked, kind)
    size = len(raw)

    match = Rever.search(raw)  # Rever's regex takes bytes
    if not match or match.start() > 12:
        raise ValueError("Invalid version string in raw = {}".format(raw))

    fore, back = match.span()  # full version string
    # update vs with latest kind version size
    vs = versify(protocol=proto, version=vrsn, kind=kind, size=size)
    # replace old version string in raw with new one
    raw = b'%b%b%b' % (raw[:fore], vs.encode("utf-8"), raw[back:])
    if size != len(raw):  # substitution messed up
        raise ValueError("Malformed version string size = {}".format(vs))
    ked["v"] = vs  # update ked

    return raw, proto, kind, ked, vrsn




def dumps(ked, kind=Serials.json):
    """
    utility function to handle serialization by kind

    Returns:
       raw (bytes): serialized version of ked dict

    Parameters:
       ked (Optional(dict, list)): key event dict or message dict to serialize
       kind (str): serialization kind (JSON, MGPK, CBOR)
    """
    if kind == Serials.json:
        raw = json.dumps(ked, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    elif kind == Serials.mgpk:
        raw = msgpack.dumps(ked)

    elif kind == Serials.cbor:
        raw = cbor.dumps(ked)
    else:
        raise ValueError("Invalid serialization kind = {}".format(kind))

    return raw


def loads(raw, size=None, kind=Serials.json):
    """
    utility function to handle deserialization by kind

    Returns:
       ked (dict): deserialized

    Parameters:
       raw (Union[bytes,bytearray]): raw serialization to deserialze as dict
       size (int): number of bytes to consume for the deserialization. If None
                   then consume all bytes
       kind (str): serialization kind (JSON, MGPK, CBOR)
    """
    if kind == Serials.json:
        try:
            ked = json.loads(raw[:size].decode("utf-8"))
        except Exception as ex:
            raise DeserializeError("Error deserializing JSON: {}"
                                       "".format(raw[:size].decode("utf-8")))

    elif kind == Serials.mgpk:
        try:
            ked = msgpack.loads(raw[:size])
        except Exception as ex:
            raise DeserializeError("Error deserializing MGPK: {}"
                                       "".format(raw[:size]))

    elif kind == Serials.cbor:
        try:
            ked = cbor.loads(raw[:size])
        except Exception as ex:
            raise DeserializeError("Error deserializing CBOR: {}"
                                       "".format(raw[:size]))

    else:
        raise DeserializeError("Invalid deserialization kind: {}"
                                   "".format(kind))

    return ked


def generateSigners(raw=None, count=8, transferable=True):
    """Returns list of Signers for Ed25519

    Deprecated, use Salter.signers instead.

    Use this when simply need valid AIDs but not when need valid controller
    contexts. In the latter case use openHby or openHab which create databases.

    Parameters:
        raw (bytes):  16 byte long salt cryptomatter from which seeds
            for Signers in list are derived
            random salt created if not provided
        count is number of signers in list
        transferable is boolean true means signer.verfer code is transferable
                                non-transferable otherwise
    """
    if not raw:
        raw = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)

    signers = []
    for i in range(count):
        path = f"{i:x}"
        # algorithm default is argon2id
        seed = pysodium.crypto_pwhash(outlen=32,
                                      passwd=path,
                                      salt=raw,
                                      opslimit=2,  # pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                      memlimit=67108864,  # pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
                                      alg=pysodium.crypto_pwhash_ALG_ARGON2ID13)

        signers.append(Signer(raw=seed, transferable=transferable))

    return signers


# ToDo: nonces only need 128 bits of entropy. a Salt is enough
# Just use Salter().qb64.
# Deprecated

def randomNonce():
    """ Generate a random ed25519 seed and encode as qb64

    Returns:
        str: qb64 encoded ed25519 random seed
    """
    preseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seedqb64 = Matter(raw=preseed, code=MtrDex.Ed25519_Seed).qb64
    return seedqb64





# secret derivation security tier
Tierage = namedtuple("Tierage", 'low med high')

Tiers = Tierage(low='low', med='med', high='high')


@dataclass(frozen=True)
class MatterCodex:
    """
    MatterCodex is codex code (stable) part of all matter derivation codes.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """

    Ed25519_Seed:         str = 'A'  # Ed25519 256 bit random seed for private key
    Ed25519N:             str = 'B'  # Ed25519 verification key non-transferable, basic derivation.
    X25519:               str = 'C'  # X25519 public encryption key, may be converted from Ed25519 or Ed25519N.
    Ed25519:              str = 'D'  # Ed25519 verification key basic derivation
    Blake3_256:           str = 'E'  # Blake3 256 bit digest self-addressing derivation.
    Blake2b_256:          str = 'F'  # Blake2b 256 bit digest self-addressing derivation.
    Blake2s_256:          str = 'G'  # Blake2s 256 bit digest self-addressing derivation.
    SHA3_256:             str = 'H'  # SHA3 256 bit digest self-addressing derivation.
    SHA2_256:             str = 'I'  # SHA2 256 bit digest self-addressing derivation.
    ECDSA_256k1_Seed:     str = 'J'  # ECDSA secp256k1 256 bit random Seed for private key
    Ed448_Seed:           str = 'K'  # Ed448 448 bit random Seed for private key
    X448:                 str = 'L'  # X448 public encryption key, converted from Ed448
    Short:                str = 'M'  # Short 2 byte b2 number
    Big:                  str = 'N'  # Big 8 byte b2 number
    X25519_Private:       str = 'O'  # X25519 private decryption key/seed, may be converted from Ed25519
    X25519_Cipher_Seed:   str = 'P'  # X25519 sealed box 124 char qb64 Cipher of 44 char qb64 Seed
    ECDSA_256r1_Seed:     str = "Q"  # ECDSA secp256r1 256 bit random Seed for private key
    Tall:                 str = 'R'  # Tall 5 byte b2 number
    Large:                str = 'S'  # Large 11 byte b2 number
    Great:                str = 'T'  # Great 14 byte b2 number
    Vast:                 str = 'U'  # Vast 17 byte b2 number
    Label1:               str = 'V'  # Label1 1 bytes for label lead size 1
    Label2:               str = 'W'  # Label2 2 bytes for label lead size 0
    Tag3:                 str = 'X'  # Tag3  3 B64 encoded chars for special values
    Tag7:                 str = 'Y'  # Tag7  7 B64 encoded chars for special values
    Blind:                str = 'Z'  # Blinding factor 256 bits, Cryptographic strength deterministically generated from random salt
    Salt_128:             str = '0A'  # random salt/seed/nonce/private key or number of length 128 bits (Huge)
    Ed25519_Sig:          str = '0B'  # Ed25519 signature.
    ECDSA_256k1_Sig:      str = '0C'  # ECDSA secp256k1 signature.
    Blake3_512:           str = '0D'  # Blake3 512 bit digest self-addressing derivation.
    Blake2b_512:          str = '0E'  # Blake2b 512 bit digest self-addressing derivation.
    SHA3_512:             str = '0F'  # SHA3 512 bit digest self-addressing derivation.
    SHA2_512:             str = '0G'  # SHA2 512 bit digest self-addressing derivation.
    Long:                 str = '0H'  # Long 4 byte b2 number
    ECDSA_256r1_Sig:      str = '0I'  # ECDSA secp256r1 signature.
    Tag1:                 str = '0J'  # Tag1 1 B64 encoded char + 1 prepad for special values
    Tag2:                 str = '0K'  # Tag2 2 B64 encoded chars for for special values
    Tag5:                 str = '0L'  # Tag5 5 B64 encoded chars + 1 prepad for special values
    Tag6:                 str = '0M'  # Tag6 6 B64 encoded chars for special values
    Tag9:                 str = '0N'  # Tag9 9 B64 encoded chars + 1 prepad for special values
    Tag10:                str = '0O'  # Tag10 10 B64 encoded chars for special values
    ECDSA_256k1N:         str = '1AAA'  # ECDSA secp256k1 verification key non-transferable, basic derivation.
    ECDSA_256k1:          str = '1AAB'  # ECDSA public verification or encryption key, basic derivation
    Ed448N:               str = '1AAC'  # Ed448 non-transferable prefix public signing verification key. Basic derivation.
    Ed448:                str = '1AAD'  # Ed448 public signing verification key. Basic derivation.
    Ed448_Sig:            str = '1AAE'  # Ed448 signature. Self-signing derivation.
    Tag4:                 str = '1AAF'  # Tag4 4 B64 encoded chars for special values
    DateTime:             str = '1AAG'  # Base64 custom encoded 32 char ISO-8601 DateTime
    X25519_Cipher_Salt:   str = '1AAH'  # X25519 sealed box 100 char qb64 Cipher of 24 char qb64 Salt
    ECDSA_256r1N:         str = '1AAI'  # ECDSA secp256r1 verification key non-transferable, basic derivation.
    ECDSA_256r1:          str = '1AAJ'  # ECDSA secp256r1 verification or encryption key, basic derivation
    Null:                 str = '1AAK'  # Null None or empty value
    No:                   str = '1AAL'  # No Falsey Boolean value
    Yes:                  str = '1AAM'  # Yes Truthy Boolean value
    Tag8:                 str = '1AAN'  # Tag8 8 B64 encoded chars for special values
    TBD0S:                str = '1__-'  # Testing purposes only, fixed special values with non-empty raw lead size 0
    TBD0:                 str = '1___'  # Testing purposes only, fixed with lead size 0
    TBD1S:                str = '2__-'  # Testing purposes only, fixed special values with non-empty raw lead size 1
    TBD1:                 str = '2___'  # Testing purposes only, fixed with lead size 1
    TBD2S:                str = '3__-'  # Testing purposes only, fixed special values with non-empty raw lead size 2
    TBD2:                 str = '3___'  # Testing purposes only, fixed with lead size 2
    StrB64_L0:            str = '4A'  # String Base64 only lead size 0
    StrB64_L1:            str = '5A'  # String Base64 only lead size 1
    StrB64_L2:            str = '6A'  # String Base64 only lead size 2
    StrB64_Big_L0:        str = '7AAA'  # String Base64 only big lead size 0
    StrB64_Big_L1:        str = '8AAA'  # String Base64 only big lead size 1
    StrB64_Big_L2:        str = '9AAA'  # String Base64 only big lead size 2
    Bytes_L0:             str = '4B'  # Byte String lead size 0
    Bytes_L1:             str = '5B'  # Byte String lead size 1
    Bytes_L2:             str = '6B'  # Byte String lead size 2
    Bytes_Big_L0:         str = '7AAB'  # Byte String big lead size 0
    Bytes_Big_L1:         str = '8AAB'  # Byte String big lead size 1
    Bytes_Big_L2:         str = '9AAB'  # Byte String big lead size 2
    X25519_Cipher_L0:     str = '4C'  # X25519 sealed box cipher bytes of sniffable plaintext lead size 0
    X25519_Cipher_L1:     str = '5C'  # X25519 sealed box cipher bytes of sniffable plaintext lead size 1
    X25519_Cipher_L2:     str = '6C'  # X25519 sealed box cipher bytes of sniffable plaintext lead size 2
    X25519_Cipher_Big_L0: str = '7AAC'  # X25519 sealed box cipher bytes of sniffable plaintext big lead size 0
    X25519_Cipher_Big_L1: str = '8AAC'  # X25519 sealed box cipher bytes of sniffable plaintext big lead size 1
    X25519_Cipher_Big_L2: str = '9AAC'  # X25519 sealed box cipher bytes of sniffable plaintext big lead size 2
    X25519_Cipher_QB64_L0:     str = '4D'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 0
    X25519_Cipher_QB64_L1:     str = '5D'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 1
    X25519_Cipher_QB64_L2:     str = '6D'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 2
    X25519_Cipher_QB64_Big_L0: str = '7AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 0
    X25519_Cipher_QB64_Big_L1: str = '8AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 1
    X25519_Cipher_QB64_Big_L2: str = '9AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 2
    X25519_Cipher_QB2_L0:     str = '4D'  # X25519 sealed box cipher bytes of QB2 plaintext lead size 0
    X25519_Cipher_QB2_L1:     str = '5D'  # X25519 sealed box cipher bytes of QB2 plaintext lead size 1
    X25519_Cipher_QB2_L2:     str = '6D'  # X25519 sealed box cipher bytes of QB2 plaintext lead size 2
    X25519_Cipher_QB2_Big_L0: str = '7AAD'  # X25519 sealed box cipher bytes of QB2 plaintext big lead size 0
    X25519_Cipher_QB2_Big_L1: str = '8AAD'  # X25519 sealed box cipher bytes of QB2 plaintext big lead size 1
    X25519_Cipher_QB2_Big_L2: str = '9AAD'  # X25519 sealed box cipher bytes of QB2 plaintext big lead size 2


    def __iter__(self):
        return iter(astuple(self))  # enables inclusion test with "in"


MtrDex = MatterCodex()  # Make instance




@dataclass(frozen=True)
class SmallVarRawSizeCodex:
    """
    SmallVarRawSizeCodex is codex all selector characters for the three small
    variable raw size tables that act as one table but with different leader
    byte sizes.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Lead0: str = '4'  # First Selector Character for all ls == 0 codes
    Lead1: str = '5'  # First Selector Character for all ls == 1 codes
    Lead2: str = '6'  # First Selector Character for all ls == 2 codes

    def __iter__(self):
        return iter(astuple(self))


SmallVrzDex = SmallVarRawSizeCodex()  # Make instance


@dataclass(frozen=True)
class LargeVarRawSizeCodex:
    """
    LargeVarRawSizeCodex is codex all selector characters for the three large
    variable raw size tables that act as one table but with different leader
    byte sizes.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Lead0_Big: str = '7'  # First Selector Character for all ls == 0 codes
    Lead1_Big: str = '8'  # First Selector Character for all ls == 1 codes
    Lead2_Big: str = '9'  # First Selector Character for all ls == 2 codes

    def __iter__(self):
        return iter(astuple(self))


LargeVrzDex = LargeVarRawSizeCodex()  # Make instance



@dataclass(frozen=True)
class BextCodex:
    """
    BextCodex is codex of all variable sized Base64 Text (Bext) derivation codes.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    StrB64_L0:     str = '4A'  # String Base64 Only Leader Size 0
    StrB64_L1:     str = '5A'  # String Base64 Only Leader Size 1
    StrB64_L2:     str = '6A'  # String Base64 Only Leader Size 2
    StrB64_Big_L0: str = '7AAA'  # String Base64 Only Big Leader Size 0
    StrB64_Big_L1: str = '8AAA'  # String Base64 Only Big Leader Size 1
    StrB64_Big_L2: str = '9AAA'  # String Base64 Only Big Leader Size 2

    def __iter__(self):
        return iter(astuple(self))


BexDex = BextCodex()  # Make instance



@dataclass(frozen=True)
class TextCodex:
    """
    TextCodex is codex of all variable sized byte string (Text) derivation codes.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Bytes_L0:     str = '4B'  # Byte String lead size 0
    Bytes_L1:     str = '5B'  # Byte String lead size 1
    Bytes_L2:     str = '6B'  # Byte String lead size 2
    Bytes_Big_L0: str = '7AAB'  # Byte String big lead size 0
    Bytes_Big_L1: str = '8AAB'  # Byte String big lead size 1
    Bytes_Big_L2: str = '9AAB'  # Byte String big lead size 2

    def __iter__(self):
        return iter(astuple(self))


TexDex = TextCodex()  # Make instance


@dataclass(frozen=True)
class CipherX25519VarCodex:
    """
    CipherX25519VarCodex is codex all variable sized cipher bytes derivation codes
    for sealed box encryped ciphertext. Plaintext is B2.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    X25519_Cipher_L0:     str = '4D'  # X25519 sealed box cipher bytes of sniffable plaintext lead size 0
    X25519_Cipher_L1:     str = '5D'  # X25519 sealed box cipher bytes of sniffable plaintext lead size 1
    X25519_Cipher_L2:     str = '6D'  # X25519 sealed box cipher bytes of sniffable plaintext lead size 2
    X25519_Cipher_Big_L0: str = '7AAD'  # X25519 sealed box cipher bytes of sniffable plaintext big lead size 0
    X25519_Cipher_Big_L1: str = '8AAD'  # X25519 sealed box cipher bytes of sniffable plaintext big lead size 1
    X25519_Cipher_Big_L2: str = '9AAD'  # X25519 sealed box cipher bytes of sniffable plaintext big lead size 2

    def __iter__(self):
        return iter(astuple(self))


CiXVarDex = CipherX25519VarCodex()  # Make instance


@dataclass(frozen=True)
class CipherX25519FixQB64Codex:
    """
    CipherX25519FixQB64Codex is codex all fixed sized cipher bytes derivation codes
    for sealed box encryped ciphertext. Plaintext is B64.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    X25519_Cipher_Seed:   str = 'P'  # X25519 sealed box 124 char qb64 Cipher of 44 char qb64 Seed
    X25519_Cipher_Salt:   str = '1AAH'  # X25519 sealed box 100 char qb64 Cipher of 24 char qb64 Salt

    def __iter__(self):
        return iter(astuple(self))


CiXFixQB64Dex = CipherX25519FixQB64Codex()  # Make instance


@dataclass(frozen=True)
class CipherX25519VarQB64Codex:
    """
    CipherX25519VarQB64Codex is codex all variable sized cipher bytes derivation codes
    for sealed box encryped ciphertext. Plaintext is QB64.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    X25519_Cipher_QB64_L0:     str = '4D'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 0
    X25519_Cipher_QB64_L1:     str = '5E'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 1
    X25519_Cipher_QB64_L2:     str = '6E'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 2
    X25519_Cipher_QB64_Big_L0: str = '7AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 0
    X25519_Cipher_QB64_Big_L1: str = '8AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 1
    X25519_Cipher_QB64_Big_L2: str = '9AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 2

    def __iter__(self):
        return iter(astuple(self))


CiXVarQB64Dex = CipherX25519VarQB64Codex()  # Make instance


@dataclass(frozen=True)
class CipherX25519AllQB64Codex:
    """
    CipherX25519AllQB64Codex is codex all both fixed and variable sized cipher bytes
    derivation codes for sealed box encryped ciphertext. Plaintext is B64.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    X25519_Cipher_Seed:   str = 'P'  # X25519 sealed box 124 char qb64 Cipher of 44 char qb64 Seed
    X25519_Cipher_Salt:   str = '1AAH'  # X25519 sealed box 100 char qb64 Cipher of 24 char qb64 Salt
    X25519_Cipher_QB64_L0:     str = '4D'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 0
    X25519_Cipher_QB64_L1:     str = '5E'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 1
    X25519_Cipher_QB64_L2:     str = '6E'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 2
    X25519_Cipher_QB64_Big_L0: str = '7AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 0
    X25519_Cipher_QB64_Big_L1: str = '8AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 1
    X25519_Cipher_QB64_Big_L2: str = '9AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 2

    def __iter__(self):
        return iter(astuple(self))


CiXAllQB64Dex = CipherX25519AllQB64Codex()  # Make instance


@dataclass(frozen=True)
class CipherX25519QB2VarCodex:
    """
    CipherX25519QB2VarCodex is codex all variable sized cipher bytes derivation codes
    for sealed box encryped ciphertext. Plaintext is B2.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    X25519_Cipher_L0:     str = '4E'  # X25519 sealed box cipher bytes of QB2 plaintext lead size 0
    X25519_Cipher_L1:     str = '5E'  # X25519 sealed box cipher bytes of QB2 plaintext lead size 1
    X25519_Cipher_L2:     str = '6E'  # X25519 sealed box cipher bytes of QB2 plaintext lead size 2
    X25519_Cipher_Big_L0: str = '7AAE'  # X25519 sealed box cipher bytes of QB2 plaintext big lead size 0
    X25519_Cipher_Big_L1: str = '8AAE'  # X25519 sealed box cipher bytes of QB2 plaintext big lead size 1
    X25519_Cipher_Big_L2: str = '9AAE'  # X25519 sealed box cipher bytes of QB2 plaintext big lead size 2

    def __iter__(self):
        return iter(astuple(self))


CiXVarQB2Dex = CipherX25519QB2VarCodex()  # Make instance




@dataclass(frozen=True)
class NonTransCodex:
    """
    NonTransCodex is codex all non-transferable derivation codes
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519N: str = 'B'  # Ed25519 verification key non-transferable, basic derivation.
    ECDSA_256k1N: str = '1AAA'  # ECDSA secp256k1 verification key non-transferable, basic derivation.
    Ed448N: str = '1AAC'  # Ed448 non-transferable prefix public signing verification key. Basic derivation.
    ECDSA_256r1N: str = "1AAI"  # ECDSA secp256r1 verification key non-transferable, basic derivation.

    def __iter__(self):
        return iter(astuple(self))


NonTransDex = NonTransCodex()  # Make instance

# When add new to DigCodes update Saider.Digests and Serder.Digests class attr
@dataclass(frozen=True)
class DigCodex:
    """
    DigCodex is codex all digest derivation codes. This is needed to ensure
    delegated inception using a self-addressing derivation i.e. digest derivation
    code.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Blake3_256: str = 'E'  # Blake3 256 bit digest self-addressing derivation.
    Blake2b_256: str = 'F'  # Blake2b 256 bit digest self-addressing derivation.
    Blake2s_256: str = 'G'  # Blake2s 256 bit digest self-addressing derivation.
    SHA3_256: str = 'H'  # SHA3 256 bit digest self-addressing derivation.
    SHA2_256: str = 'I'  # SHA2 256 bit digest self-addressing derivation.
    Blake3_512: str = '0D'  # Blake3 512 bit digest self-addressing derivation.
    Blake2b_512: str = '0E'  # Blake2b 512 bit digest self-addressing derivation.
    SHA3_512: str = '0F'  # SHA3 512 bit digest self-addressing derivation.
    SHA2_512: str = '0G'  # SHA2 512 bit digest self-addressing derivation.

    def __iter__(self):
        return iter(astuple(self))


DigDex = DigCodex()  # Make instance


@dataclass(frozen=True)
class NumCodex:
    """
    NumCodex is codex of Base64 derivation codes for compactly representing
    numbers across a wide rage of sizes.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Short:   str = 'M'  # Short 2 byte b2 number
    Long:    str = '0H'  # Long 4 byte b2 number
    Tall:    str = 'R'  # Tall 5 byte b2 number
    Big:     str = 'N'  # Big 8 byte b2 number
    Large:   str = 'S'  # Large 11 byte b2 number
    Great:   str = 'T'  # Great 14 byte b2 number
    Huge:    str = '0A'  # Huge 16 byte b2 number (same as Salt_128)
    Vast:    str = 'U'  # Vast 17 byte b2 number

    def __iter__(self):
        return iter(astuple(self))


NumDex = NumCodex()  # Make instance


@dataclass(frozen=True)
class TagCodex:
    """
    TagCodex is codex of Base64 derivation codes for compactly representing
    various small Base64 tag values as special code soft part values.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Tag1:  str = '0J'  # 1 B64 char tag with 1 pre pad
    Tag2:  str = '0K'  # 1 B64 char tag
    Tag3:  str = 'X'  # 1 B64 char tag
    Tag4:  str = '1AAF'  # 1 B64 char tag
    Tag5:  str = '0L'  # 1 B64 char tag with 1 pre pad
    Tag6:  str = '0M'  # 1 B64 char tag
    Tag7:  str = 'Y'  # 1 B64 char tag
    Tag8:  str = '1AAN'  # 1 B64 char tag
    Tag9:  str = '0N'  # 1 B64 char tag with 1 pre pad
    Tag10: str = '0O'  # 1 B64 char tag

    def __iter__(self):
        return iter(astuple(self))


TagDex = TagCodex()  # Make instance


@dataclass(frozen=True)
class PadTagCodex:
    """
    TagCodex is codex of Base64 derivation codes for compactly representing
    various small Base64 tag values as prepadded special code soft part values.
    Prepad is 1 B64 char.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Tag1:  str = '0J'  # 1 B64 char tag with 1 pre pad
    Tag5:  str = '0L'  # 1 B64 char tag with 1 pre pad
    Tag9:  str = '0N'  # 1 B64 char tag with 1 pre pad

    def __iter__(self):
        return iter(astuple(self))


PadTagDex = PadTagCodex()  # Make instance


@dataclass(frozen=True)
class PreCodex:
    """
    PreCodex is codex all identifier prefix derivation codes.
    This is needed to verify valid inception events.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519N:      str = 'B'  # Ed25519 verification key non-transferable, basic derivation.
    Ed25519:       str = 'D'  # Ed25519 verification key basic derivation
    Blake3_256:    str = 'E'  # Blake3 256 bit digest self-addressing derivation.
    Blake2b_256:   str = 'F'  # Blake2b 256 bit digest self-addressing derivation.
    Blake2s_256:   str = 'G'  # Blake2s 256 bit digest self-addressing derivation.
    SHA3_256:      str = 'H'  # SHA3 256 bit digest self-addressing derivation.
    SHA2_256:      str = 'I'  # SHA2 256 bit digest self-addressing derivation.
    Blake3_512:    str = '0D'  # Blake3 512 bit digest self-addressing derivation.
    Blake2b_512:   str = '0E'  # Blake2b 512 bit digest self-addressing derivation.
    SHA3_512:      str = '0F'  # SHA3 512 bit digest self-addressing derivation.
    SHA2_512:      str = '0G'  # SHA2 512 bit digest self-addressing derivation.
    ECDSA_256k1N:  str = '1AAA'  # ECDSA secp256k1 verification key non-transferable, basic derivation.
    ECDSA_256k1:   str = '1AAB'  # ECDSA public verification or encryption key, basic derivation
    ECDSA_256r1N:  str = "1AAI"  # ECDSA secp256r1 verification key non-transferable, basic derivation.
    ECDSA_256r1:   str = "1AAJ"  # ECDSA secp256r1 verification or encryption key, basic derivation

    def __iter__(self):
        return iter(astuple(self))


PreDex = PreCodex()  # Make instance


# namedtuple for size entries in Matter  and Counter derivation code tables
# hs is the hard size int number of chars in hard (stable) part of code
# ss is the soft size int number of chars in soft (unstable) part of code
# fs is the full size int number of chars in code plus appended material if any
# ls is the lead size int number of bytes to pre-pad pre-converted raw binary
Sizage = namedtuple("Sizage", "hs ss fs ls")
class Matter:
    """
    Matter is fully qualified cryptographic material primitive base class for
    non-indexed primitives.

    Sub classes are derivation code and key event element context specific.

    Includes the following attributes and properties:

    Class Attributes:
        Codex (MatterCodex):  MtrDex
        Hards (dict): hard sizes keyed by qb64 selector
        Bards (dict): hard size keyed by qb2 selector
        Sizes (dict): sizes tables for codes

    Calss Methods:


    Attributes:

    Properties:
        code (str): hard part of derivation code to indicate cypher suite
        hard (str): hard part of derivation code. alias for code
        soft (str | bytes): soft part of derivation code fs any.
                    Empty when ss = 0.
        both (str): hard + soft parts of full text code
        size (int | None): Number of quadlets/triplets of chars/bytes including
                            lead bytes of variable sized material (fs = None).
                            Converted value of the soft part (of len ss) of full
                            derivation code.
                          Otherwise None when not variably sized (fs != None)
        fullSize (int): full size of primitive
        raw (bytes): crypto material only. Not derivation code or lead bytes.
        qb64 (str): Base64 fully qualified with derivation code + crypto mat
        qb64b (bytes): Base64 fully qualified with derivation code + crypto mat
        qb2  (bytes): binary with derivation code + crypto material
        transferable (bool): True means transferable derivation code False otherwise
        digestive (bool): True means digest derivation code False otherwise
        prefixive (bool): True means identifier prefix derivation code False otherwise
        special (bool): True when soft is special raw is empty and fixed size
        composable (bool): True when .qb64b and .qb2 are 24 bit aligned and round trip

    Hidden:
        _code (str): value for .code property
        _soft (str): soft value of full code
        _raw (bytes): value for .raw property
        _rawSize():
        _leadSize():
        _special():
        _infil(): creates qb64b from .raw and .code (fully qualified Base64)
        _binfil(): creates qb2 from .raw and .code (fully qualified Base2)
        _exfil(): extracts .code and .raw from qb64b (fully qualified Base64)
        _bexfil(): extracts .code and .raw from qb2 (fully qualified Base2)


    Special soft values are indicated when fn in table is None and ss > 0.

    """
    # Hards table maps from bytes Base64 first code char to int of hard size, hs,
    # (stable) of code. The soft size, ss, (unstable) is always 0 for Matter
    # unless fs is None which allows for variable size multiple of 4, i.e.
    # not (hs + ss) % 4.
    Hards = ({chr(c): 1 for c in range(65, 65 + 26)})  # size of hard part of code
    Hards.update({chr(c): 1 for c in range(97, 97 + 26)})
    Hards.update([('0', 2), ('1', 4), ('2', 4), ('3', 4), ('4', 2), ('5', 2),
                  ('6', 2), ('7', 4), ('8', 4), ('9', 4)])


    # Bards table maps first code char. converted to binary sextext of hard size,
    # hs. Used for ._bexfil.
    Bards = ({codeB64ToB2(c): hs for c, hs in Hards.items()})

    # Sizes table maps from value of hs chars of code to Sizage namedtuple of
    # (hs, ss, fs, ls) where hs is hard size, ss is soft size, and fs is full size
    # and ls is lead size
    # soft size, ss, should always be 0 for Matter unless fs is None which allows
    # for variable size multiple of 4, i.e. not (hs + ss) % 4.
    Sizes = {
        'A': Sizage(hs=1, ss=0, fs=44, ls=0),
        'B': Sizage(hs=1, ss=0, fs=44, ls=0),
        'C': Sizage(hs=1, ss=0, fs=44, ls=0),
        'D': Sizage(hs=1, ss=0, fs=44, ls=0),
        'E': Sizage(hs=1, ss=0, fs=44, ls=0),
        'F': Sizage(hs=1, ss=0, fs=44, ls=0),
        'G': Sizage(hs=1, ss=0, fs=44, ls=0),
        'H': Sizage(hs=1, ss=0, fs=44, ls=0),
        'I': Sizage(hs=1, ss=0, fs=44, ls=0),
        'J': Sizage(hs=1, ss=0, fs=44, ls=0),
        'K': Sizage(hs=1, ss=0, fs=76, ls=0),
        'L': Sizage(hs=1, ss=0, fs=76, ls=0),
        'M': Sizage(hs=1, ss=0, fs=4, ls=0),
        'N': Sizage(hs=1, ss=0, fs=12, ls=0),
        'O': Sizage(hs=1, ss=0, fs=44, ls=0),
        'P': Sizage(hs=1, ss=0, fs=124, ls=0),
        'Q': Sizage(hs=1, ss=0, fs=44, ls=0),
        'R': Sizage(hs=1, ss=0, fs=8, ls=0),
        'S': Sizage(hs=1, ss=0, fs=16, ls=0),
        'T': Sizage(hs=1, ss=0, fs=20, ls=0),
        'U': Sizage(hs=1, ss=0, fs=24, ls=0),
        'V': Sizage(hs=1, ss=0, fs=4, ls=1),
        'W': Sizage(hs=1, ss=0, fs=4, ls=0),
        'X': Sizage(hs=1, ss=3, fs=4, ls=0),
        'Y': Sizage(hs=1, ss=7, fs=8, ls=0),
        'Z': Sizage(hs=1, ss=0, fs=44, ls=0),
        '0A': Sizage(hs=2, ss=0, fs=24, ls=0),
        '0B': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0C': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0D': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0E': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0F': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0G': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0H': Sizage(hs=2, ss=0, fs=8, ls=0),
        '0I': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0J': Sizage(hs=2, ss=2, fs=4, ls=0),
        '0K': Sizage(hs=2, ss=2, fs=4, ls=0),
        '0L': Sizage(hs=2, ss=6, fs=8, ls=0),
        '0M': Sizage(hs=2, ss=6, fs=8, ls=0),
        '0N': Sizage(hs=2, ss=10, fs=12, ls=0),
        '0O': Sizage(hs=2, ss=10, fs=12, ls=0),
        '1AAA': Sizage(hs=4, ss=0, fs=48, ls=0),
        '1AAB': Sizage(hs=4, ss=0, fs=48, ls=0),
        '1AAC': Sizage(hs=4, ss=0, fs=80, ls=0),
        '1AAD': Sizage(hs=4, ss=0, fs=80, ls=0),
        '1AAE': Sizage(hs=4, ss=0, fs=56, ls=0),
        '1AAF': Sizage(hs=4, ss=4, fs=8, ls=0),
        '1AAG': Sizage(hs=4, ss=0, fs=36, ls=0),
        '1AAH': Sizage(hs=4, ss=0, fs=100, ls=0),
        '1AAI': Sizage(hs=4, ss=0, fs=48, ls=0),
        '1AAJ': Sizage(hs=4, ss=0, fs=48, ls=0),
        '1AAK': Sizage(hs=4, ss=0, fs=4, ls=0),
        '1AAL': Sizage(hs=4, ss=0, fs=4, ls=0),
        '1AAM': Sizage(hs=4, ss=0, fs=4, ls=0),
        '1AAN': Sizage(hs=4, ss=8, fs=12, ls=0),
        '1__-': Sizage(hs=4, ss=2, fs=12, ls=0),
        '1___': Sizage(hs=4, ss=0, fs=8, ls=0),
        '2__-': Sizage(hs=4, ss=2, fs=12, ls=1),
        '2___': Sizage(hs=4, ss=0, fs=8, ls=1),
        '3__-': Sizage(hs=4, ss=2, fs=12, ls=2),
        '3___': Sizage(hs=4, ss=0, fs=8, ls=2),
        '4A': Sizage(hs=2, ss=2, fs=None, ls=0),
        '5A': Sizage(hs=2, ss=2, fs=None, ls=1),
        '6A': Sizage(hs=2, ss=2, fs=None, ls=2),
        '7AAA': Sizage(hs=4, ss=4, fs=None, ls=0),
        '8AAA': Sizage(hs=4, ss=4, fs=None, ls=1),
        '9AAA': Sizage(hs=4, ss=4, fs=None, ls=2),
        '4B': Sizage(hs=2, ss=2, fs=None, ls=0),
        '5B': Sizage(hs=2, ss=2, fs=None, ls=1),
        '6B': Sizage(hs=2, ss=2, fs=None, ls=2),
        '7AAB': Sizage(hs=4, ss=4, fs=None, ls=0),
        '8AAB': Sizage(hs=4, ss=4, fs=None, ls=1),
        '9AAB': Sizage(hs=4, ss=4, fs=None, ls=2),
        '4C': Sizage(hs=2, ss=2, fs=None, ls=0),
        '5C': Sizage(hs=2, ss=2, fs=None, ls=1),
        '6C': Sizage(hs=2, ss=2, fs=None, ls=2),
        '7AAC': Sizage(hs=4, ss=4, fs=None, ls=0),
        '8AAC': Sizage(hs=4, ss=4, fs=None, ls=1),
        '9AAC': Sizage(hs=4, ss=4, fs=None, ls=2),
        '4D': Sizage(hs=2, ss=2, fs=None, ls=0),
        '5D': Sizage(hs=2, ss=2, fs=None, ls=1),
        '6D': Sizage(hs=2, ss=2, fs=None, ls=2),
        '7AAD': Sizage(hs=4, ss=4, fs=None, ls=0),
        '8AAD': Sizage(hs=4, ss=4, fs=None, ls=1),
        '9AAD': Sizage(hs=4, ss=4, fs=None, ls=2),
        '4E': Sizage(hs=2, ss=2, fs=None, ls=0),
        '5E': Sizage(hs=2, ss=2, fs=None, ls=1),
        '6E': Sizage(hs=2, ss=2, fs=None, ls=2),
        '7AAE': Sizage(hs=4, ss=4, fs=None, ls=0),
        '8AAE': Sizage(hs=4, ss=4, fs=None, ls=1),
        '9AAE': Sizage(hs=4, ss=4, fs=None, ls=2),
    }



    def __init__(self, raw=None, code=MtrDex.Ed25519N, soft='', rize=None,
                 qb64b=None, qb64=None, qb2=None, strip=False):
        """
        Validate as fully qualified
        Parameters:
            raw (bytes | bytearray | None): unqualified crypto material usable
                    for crypto operations.
            code (str): stable (hard) part of derivation code
            soft (str | bytes): soft part for special codes
            rize (int | None): raw size in bytes when variable sized material not
                        including lead bytes if any
                        Otherwise None
            qb64b (bytes | None): fully qualified crypto material Base64
            qb64 (str | bytes | None):  fully qualified crypto material Base64
            qb2 (bytes | None): fully qualified crypto material Base2
            strip (bool): True means strip (delete) matter from input stream
                bytearray after parsing qb64b or qb2. False means do not strip


        Needs either (raw and code and optionally rsize)
               or qb64b or qb64 or qb2
        Otherwise raises EmptyMaterialError
        When raw and code and optional rsize provided
            then validate that code is correct for length of raw, rsize,
            computed size from Sizes and assign .raw
        Else when qb64b or qb64 or qb2 provided extract and assign
            .raw and .code and .size and .rsize

        """
        if hasattr(soft, "decode"):  # make soft str
            soft = soft.decode("utf-8")

        if raw is not None:  # raw provided but may be empty
            if not code:
                raise EmptyMaterialError(f"Improper initialization need either "
                                         f"(raw not None and code) or "
                                         f"(code and soft) or "
                                         f"qb64b or qb64 or qb2.")

            if not isinstance(raw, (bytes, bytearray)):
                raise TypeError(f"Not a bytes or bytearray {raw=}.")

            if code not in self.Sizes:
                raise InvalidCodeError(f"Unsupported {code=}.")

            hs, ss, fs, ls = self.Sizes[code]  # assumes unit tests force valid sizes

            if fs is None:  # variable sized assumes code[0] in SmallVrzDex or LargeVrzDex
                if rize:  # use rsize to determine length of raw to extract
                    if rize < 0:
                        raise InvalidVarRawSizeError(f"Missing var raw size for "
                                                     f"code={code}.")
                else:  # use length of provided raw as rize
                    rize = len(raw)

                ls = (3 - (rize % 3)) % 3  # calc actual lead (pad) size
                # raw binary size including leader in bytes
                size = (rize + ls) // 3  # calculate value of size in triplets

                if code[0] in SmallVrzDex:  # compute code with sizes
                    if size <= (64 ** 2 - 1):  # ss = 2
                        hs = 2
                        s = astuple(SmallVrzDex)[ls]
                        code = f"{s}{code[1:hs]}"
                        ss = 2
                    elif size <= (64 ** 4 - 1):  # ss = 4 make big version of code
                        hs = 4
                        s = astuple(LargeVrzDex)[ls]
                        code = f"{s}{'A' * (hs - 2)}{code[1]}"
                        soft = intToB64(size, 4)
                        ss = 4
                    else:
                        raise InvalidVarRawSizeError(f"Unsupported raw size for "
                                                     f"{code=}.")
                elif code[0] in LargeVrzDex:  # compute code with sizes
                    if size <= (64 ** 4 - 1):  # ss = 4
                        hs = 4
                        s = astuple(LargeVrzDex)[ls]
                        code = f"{s}{code[1:hs]}"
                        ss = 4
                    else:
                        raise InvalidVarRawSizeError(f"Unsupported raw size for "
                                                     f"{code=}.")
                else:
                    raise InvalidVarRawSizeError(f"Unsupported variable raw size "
                                                 f"{code=}.")
                soft = intToB64(size, ss)

            else:  # fixed size but raw may be empty and/or special soft
                rize = Matter._rawSize(code)  # get raw size from Sizes for code

                if ss > 0: # special soft size, so soft must be provided
                    soft = soft[:ss]
                    if len(soft) != ss:
                        raise SoftMaterialError(f"Not enough chars in {soft=} "
                                                 f"with {ss=} for {code=}.")

                    if not Reb64.match(soft.encode("utf-8")):
                        raise InvalidSoftError(f"Non Base64 chars in {soft=}.")
                else:
                    soft = ''  # must be empty when ss == 0


            raw = raw[:rize]  # copy only exact size from raw stream
            if len(raw) != rize:  # forbids shorter
                raise RawMaterialError(f"Not enougth raw bytes for code={code}"
                                       f"expected {rize=} got {len(raw)}.")

            self._code = code  # str hard part of code
            self._soft = soft  # str soft part of code, empty when ss=0
            self._raw = bytes(raw)  # crypto ops require bytes not bytearray

        elif soft and code:  # fixed size and special when raw None
            hs, ss, fs, ls = self.Sizes[code]  # assumes unit tests force valid sizes
            if not fs:  # variable sized code so can't be soft
                raise InvalidSoftError(f"Unsupported variable sized {code=} "
                                       f" with {fs=} for special {soft=}.")

            if not ss > 0 or (fs == hs + ss and not ls == 0):  # not special soft
                raise InvalidSoftError("Invalid soft size={ss} or lead={ls} "
                                       f" or {code=} {fs=} when special soft.")

            soft = soft[:ss]
            if len(soft) != ss:
                raise SoftMaterialError(f"Not enough chars in {soft=} "
                                         f"with {ss=} for {code=}.")

            if not Reb64.match(soft.encode("utf-8")):
                raise InvalidSoftError(f"Non Base64 chars in {soft=}.")

            self._code = code  # str hard part of code
            self._soft = soft  # str soft part of code, empty when ss=0
            self._raw = b''  # make raw empty when None and when special soft

        elif qb64b is not None:
            self._exfil(qb64b)
            if strip:  # assumes bytearray
                del qb64b[:self.fullSize]

        elif qb64 is not None:
            self._exfil(qb64)

        elif qb2 is not None:
            self._bexfil(qb2)
            if strip:  # assumes bytearray
                del qb2[:self.fullSize * 3 // 4]

        else:
            raise EmptyMaterialError(f"Improper initialization need either "
                                         f"(raw not None and code) or "
                                         f"(code and soft) or "
                                         f"qb64b or qb64 or qb2.")


    @classmethod
    def _rawSize(cls, code):
        """
        Returns raw size in bytes not including leader for a given code
        Parameters:
            code (str): derivation code Base64
        """
        hs, ss, fs, ls = cls.Sizes[code]  # get sizes
        cs = hs + ss  # both hard + soft code size
        if fs is None:
            raise InvalidCodeSizeError(f"Non-fixed raw size code {code}.")
        # assumes .Sizes only has valid entries, cs % 4 != 3, and fs % 4 == 0
        return (((fs - cs) * 3 // 4) - ls)


    @classmethod
    def _leadSize(cls, code):
        """
        Returns lead size in bytes for a given code
        Parameters:
            code (str): derivation code Base64
        """
        _, _, _, ls = cls.Sizes[code]  # get lead size from .Sizes table
        return ls


    @classmethod
    def _special(cls, code):
        """
        Returns:
            special (bool): True when code has special soft i.e. when
                    fs is not None and ss > 0
                False otherwise

        """
        hs, ss, fs, ls = cls.Sizes[code]

        return (fs is not None and ss > 0)


    @property
    def code(self):
        """
        Returns:
            code (str): hard part only of full text code.

        Getter for ._code. Makes ._code read only

        Some codes only have a hard part. Soft part may be for variable sized
        matter or for special codes that are code only (raw is empty)
        """
        return self._code


    @property
    def hard(self):
        """
        Returns:
            hard (str): hard part only of full text code. Alias for .code.

        """
        return self.code


    @property
    def soft(self):
        """
        Returns:
            soft (str): soft part only of full text code.

        Getter for ._soft. Make ._soft read only
        """
        return self._soft


    @property
    def size(self):
        """
        Returns:
            size(int | None): Number of variably sized b64 quadlets/b2 triplets
                                in primitive when varibly sized
                              None when not variably sized when (fs!=None)

        Number of quadlets/triplets of chars/bytes of variable sized material or
        None when not variably sized.

        Converted qb64 value to int of soft ss portion of full text code
        when variably sized primitive material (fs == None).
        """
        return (b64ToInt(self.soft) if self.soft else None)


    @property
    def both(self):
        """
        Returns:
            both (str):  hard + soft parts of full text code
        """
        #_, ss, _, _ = self.Sizes[self.code]

        #if self.size is not None:
            #return (f"{self.code}{intToB64(self.size, l=ss)}")
        #else:
            #return (f"{self.code}{self.soft}")

        return (f"{self.code}{self.soft}")


    @property
    def fullSize(self):
        """
        Returns full size of matter in bytes
        Fixed size codes returns fs from .Sizes
        Variable size codes where fs==None computes fs from .size and sizes
        """
        hs, ss, fs, _ = self.Sizes[self.code]  # get sizes

        if fs is None:  # compute fs from ss characters in code
            fs = hs + ss + (self.size * 4)
        return fs


    @property
    def raw(self):
        """
        Returns ._raw
        Makes .raw read only
        """
        return self._raw


    @property
    def qb64b(self):
        """
        Property qb64b:
        Returns Fully Qualified Base64 Version encoded as bytes
        Assumes self.raw and self.code are correctly populated
        """
        return self._infil()


    @property
    def qb64(self):
        """
        Property qb64:
        Returns Fully Qualified Base64 Version
        Assumes self.raw and self.code are correctly populated
        """
        return self.qb64b.decode("utf-8")


    @property
    def qb2(self):
        """
        Property qb2:
        Returns Fully Qualified Binary Version Bytes
        """
        return self._binfil()


    @property
    def transferable(self):
        """
        Property transferable:
        Returns True if identifier does not have non-transferable derivation code,
                False otherwise
        """
        return (self.code not in NonTransDex)


    @property
    def digestive(self):
        """
        Property digestable:
        Returns True if identifier has digest derivation code,
                False otherwise
        """
        return (self.code in DigDex)


    @property
    def prefixive(self):
        """
        Property prefixive:
        Returns True if identifier has prefix derivation code,
                False otherwise
        """
        return (self.code in PreDex)


    @property
    def special(self):
        """
        special (bool): True when self.code has special self.soft i.e. when
                    fs is not None and ss > 0  and fs = hs + ss and ls = 0
                    i.e. (fs fixed and soft not empty and raw is empty and no lead)
                False otherwise
        """
        return self._special(self.code)

    @property
    def composable(self):
        """
        composable (bool): True when both .qb64b and .qb2 are 24 bit aligned and
                           round trip using encodeB64 and decodeB64.
                           False otherwise
        """
        qb64b = self.qb64b
        qb2 = self.qb2
        return (len(qb64b) % 4 == 0 and len(qb2) % 3 == 0 and
                encodeB64(qb2) == qb64b and decodeB64(qb64b) == qb2)


    def _infil(self):
        """
        Returns:
            primitive (bytes): fully qualified base64 characters.
        """
        code = self.code  # hard part of full code == codex value
        both = self.both  # code + soft, soft may be empty
        raw = self.raw  # bytes or bytearray, raw may be empty
        rs = len(raw)  # raw size
        hs, ss, fs, ls = self.Sizes[code]
        cs = hs + ss
        # assumes unit tests on Matter.Sizes ensure valid size entries

        if cs != len(both):
            InvalidCodeSizeError(f"Invalid full code={both} for sizes {hs=} and"
                                f" {ss=}.")

        if not fs:  # variable sized
            # Tests on .Sizes table must ensure ls in (0,1,2) and cs % 4 == 0 but
            # can't know the variable size. So instance methods must ensure that
            # (ls + rs) % 3 == 0 i.e. both full code (B64) and lead+raw (B2)
            # are both 24 bit aligned.
            # If so then should not need following check.
            if (ls + rs) % 3 or cs % 4:
                raise InvalidCodeSizeError(f"Invalid full code{both=} with "
                                           f"variable raw size={rs} given "
                                           f" {cs=}, {hs=}, {ss=}, {fs=}, and "
                                           f"{ls=}.")

            # When ls+rs is 24 bit aligned then encodeB64 has no trailing
            # pad chars that need to be stripped. So simply prepad raw with
            # ls zero bytes and convert (encodeB64).
            full = (both.encode("utf-8") + encodeB64(bytes([0] * ls) + raw))

        else:  # fixed size
            ps = (3 - ((rs + ls) % 3)) % 3  # net pad size given raw with lead
            # net pad size must equal both code size remainder so that primitive
            # both + converted padded raw is fs long. Assumes ls in (0,1,2) and
            # cs % 4 != 3, fs % 4 == 0. Sizes table test must ensure these properties.
            # If so then should not need following check.
            if ps != (cs % 4):  # given cs % 4 != 3 then cs % 4 is pad size
                raise InvalidCodeSizeError(f"Invalid full code{both=} with "
                                           f"fixed raw size={rs} given "
                                           f" {cs=}, {hs=}, {ss=}, {fs=}, and "
                                           f"{ls=}.")

            # Predpad raw so we midpad the full primitive. Prepad with ps+ls
            # zero bytes ensures encodeB64 of prepad+lead+raw has no trailing
            # pad characters. Finally skip first ps == cs % 4 of the converted
            # characters to ensure that when full code is prepended, the full
            # primitive size is fs but midpad bits are zeros.
            full = (both.encode("utf-8") + encodeB64(bytes([0] * (ps + ls)) + raw)[ps:])

        if (len(full) % 4) or (fs and len(full) != fs):
            raise InvalidCodeSizeError(f"Invalid full size given code{both=} "
                                       f" with raw size={rs}, {cs=}, {hs=}, "
                                       f"{ss=}, {fs=}, and {ls=}.")

        return full


    def _binfil(self):
        """
        Returns bytes of fully qualified base2 bytes, that is .qb2
        self.code converted to Base2 + self.raw left shifted with pad bits
        equivalent of Base64 decode of .qb64 into .qb2
        """
        code = self.code  # hard part of full code == codex value
        both = self.both  # code + soft, soft may be empty
        raw = self.raw  # bytes or bytearray may be empty

        hs, ss, fs, ls = self.Sizes[code]
        cs = hs + ss
        # assumes unit tests on Matter.Sizes ensure valid size entries
        n = sceil(cs * 3 / 4)  # number of b2 bytes to hold b64 code
        # convert code both to right align b2 int then left shift in pad bits
        # then convert to bytes
        bcode = (b64ToInt(both) << (2 * (cs % 4))).to_bytes(n, 'big')
        full = bcode + bytes([0] * ls) + raw  # includes lead bytes

        bfs = len(full)
        if not fs:  # compute fs
            fs = hs + ss + (len(raw) + ls) * 4 // 3 # hs + ss + (size * 4)
        if bfs % 3 or (bfs * 4 // 3) != fs:  # invalid size
            raise InvalidCodeSizeError(f"Invalid full code={both} for raw size"
                                       f"={len(raw)}.")
        return full


    def _exfil(self, qb64b):
        """
        Extracts self.code and self.raw from qualified base64 str or bytes qb64b
        Detects is str and converts to bytes

        Parameters:
            qb64b (str | bytes | bytearray): fully qualified base64 from stream

        """
        if not qb64b:  # empty need more bytes
            raise ShortageError("Empty material.")

        first = qb64b[:1]  # extract first char code selector
        if hasattr(first, "decode"):
            first = first.decode("utf-8")
        if first not in self.Hards:
            if first[0] == '-':
                raise UnexpectedCountCodeError("Unexpected count code start"
                                               "while extracing Matter.")
            elif first[0] == '_':
                raise UnexpectedOpCodeError("Unexpected  op code start"
                                            "while extracing Matter.")
            else:
                raise UnexpectedCodeError(f"Unsupported code start char={first}.")

        hs = self.Hards[first]  # get hard code size
        if len(qb64b) < hs:  # need more bytes
            raise ShortageError(f"Need {hs - len(qb64b)} more characters.")

        hard = qb64b[:hs]  # extract hard code
        if hasattr(hard, "decode"):
            hard = hard.decode("utf-8")  # converts bytes/bytearray to str
        if hard not in self.Sizes:
            raise UnexpectedCodeError(f"Unsupported code ={hard}.")

        hs, ss, fs, ls = self.Sizes[hard]  # assumes hs in both tables match
        cs = hs + ss  # both hs and ss
        # assumes that unit tests on Matter .Sizes .Hards and .Bards ensure that
        # these are well formed.
        # when fs is None then ss > 0 otherwise fs > hs + ss when ss > 0

        soft = qb64b[hs:hs + ss]  # extract soft chars, empty when ss==0
        if hasattr(soft, "decode"):
            soft = soft.decode("utf-8")

        if not fs:  # compute fs from soft from ss part which provides size B64
            # compute variable size as int may have value 0
            fs = (b64ToInt(soft) * 4) + cs

        if len(qb64b) < fs:  # need more bytes
            raise ShortageError(f"Need {fs - len(qb64b)} more chars.")

        qb64b = qb64b[:fs]  # fully qualified primitive code plus material
        if hasattr(qb64b, "encode"):  # only convert extracted chars from stream
            qb64b = qb64b.encode("utf-8")

        # check for non-zeroed pad bits and/or lead bytes
        # net prepad ps == cs % 4 (remainer).  Assumes ps != 3 i.e ps in (0,1,2)
        # To ensure number of prepad bytes and prepad chars are same.
        # need net prepad chars ps to invert using decodeB64 of lead + raw

        ps = cs % 4  # net prepad bytes to ensure 24 bit align when encodeB64
        base =  ps * b'A' + qb64b[cs:]  # prepad ps 'A's to  B64 of (lead + raw)
        paw = decodeB64(base)  # now should have ps + ls leading sextexts of zeros
        raw = paw[ps+ls:]  # remove prepad midpat bytes to invert back to raw
        # ensure midpad bytes are zero
        pi = int.from_bytes(paw[:ps+ls], "big")
        if pi != 0:
            raise ConversionError(f"Nonzero midpad bytes=0x{pi:0{(ps + ls) * 2}x}.")

        if len(raw) != ((len(qb64b) - cs) * 3 // 4) - ls:  # exact lengths
            raise ConversionError(f"Improperly qualified material = {qb64b}")

        self._code = hard  # hard only
        self._soft = soft  # soft only
        self._raw = raw  # ensure bytes for crypto ops, may be empty


    def _bexfil(self, qb2):
        """
        Extracts self.code and self.raw from qualified base2 qb2

        Parameters:
            qb2 (bytes | bytearray): fully qualified base2 from stream
        """
        if not qb2:  # empty need more bytes
            raise ShortageError("Empty material, Need more bytes.")

        first = nabSextets(qb2, 1)  # extract first sextet as code selector
        if first not in self.Bards:
            if first[0] == b'\xf8':  # b64ToB2('-')
                raise UnexpectedCountCodeError("Unexpected count code start"
                                               "while extracing Matter.")
            elif first[0] == b'\xfc':  # b64ToB2('_')
                raise UnexpectedOpCodeError("Unexpected  op code start"
                                            "while extracing Matter.")
            else:
                raise UnexpectedCodeError(f"Unsupported code start sextet={first}.")

        hs = self.Bards[first]  # get code hard size equvalent sextets
        bhs = sceil(hs * 3 / 4)  # bhs is min bytes to hold hs sextets
        if len(qb2) < bhs:  # need more bytes
            raise ShortageError(f"Need {bhs - len(qb2)} more bytes.")

        hard = codeB2ToB64(qb2, hs)  # extract and convert hard part of code
        if hard not in self.Sizes:
            raise UnexpectedCodeError(f"Unsupported code ={hard}.")

        hs, ss, fs, ls = self.Sizes[hard]
        cs = hs + ss  # both hs and ss
        # assumes that unit tests on Matter .Sizes .Hards and .Bards ensure that
        # these are well formed.
        # when fs is None then ss > 0 otherwise fs > hs + ss when ss > 0

        bcs = sceil(cs * 3 / 4)  # bcs is min bytes to hold cs sextets
        if len(qb2) < bcs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bcs - len(qb2)))

        both = codeB2ToB64(qb2, cs)  # extract and convert both hard and soft part of code
        soft = both[hs:hs + ss]  # get soft may be empty

        if not fs:  # compute fs from size chars in ss part of code
            if len(qb2) < bcs:  # need more bytes
                raise ShortageError("Need {} more bytes.".format(bcs - len(qb2)))

            # compute size as int from soft part given by ss B64 chars
            fs = (b64ToInt(soft) * 4) + cs  # compute fs

        bfs = sceil(fs * 3 / 4)  # bfs is min bytes to hold fs sextets
        if len(qb2) < bfs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bfs - len(qb2)))

        qb2 = qb2[:bfs]  # extract qb2 fully qualified primitive code plus material

        # check for nonzero trailing full code mid pad bits
        ps = cs % 4  # full code (both) net pad size for 24 bit alignment
        pbs = 2 * ps  # mid pad bits = 2 per net pad
        # get pad bits in last byte of full code
        pi = (int.from_bytes(qb2[bcs-1:bcs], "big")) # convert byte to int
        pi = pi & (2 ** pbs - 1 ) # mask with 1's in pad bit locations
        if pi:  # not zero so raise error
            raise ConversionError(f"Nonzero code mid pad bits=0b{pi:0{pbs}b}.")

        # check nonzero leading mid pad lead bytes in lead + raw
        li = int.from_bytes(qb2[bcs:bcs+ls], "big")  # lead as int
        if li:  # midpad lead bytes must be zero
            raise ConversionError(f"Nonzero lead midpad bytes=0x{li:0{ls*2}x}.")

        # strip code and leader bytes from qb2 to get raw
        raw = qb2[(bcs + ls):]  # may be empty

        if len(raw) != (len(qb2) - bcs - ls):  # exact lengths
            raise ConversionError(r"Improperly qualified material = {qb2}")

        self._code = hard  # hard only
        self._soft = soft  # soft only may be empty
        self._raw = bytes(raw)  # ensure bytes for crypto ops may be empty

class Verfer(Matter):
    """
    Verfer is Matter subclass with method to verify signature of serialization
    using the .raw as verifier key and .code for signature cipher suite.

    See Matter for inherited attributes and properties:

    Attributes:

    Properties:

    Methods:
        verify: verifies signature

    """

    def __init__(self, **kwa):
        """
        Assign verification cipher suite function to ._verify

        """
        super(Verfer, self).__init__(**kwa)

        if self.code in [MtrDex.Ed25519N, MtrDex.Ed25519]:
            self._verify = self._ed25519
        elif self.code in [MtrDex.ECDSA_256r1N, MtrDex.ECDSA_256r1]:
            self._verify = self._secp256r1
        elif self.code in [MtrDex.ECDSA_256k1N, MtrDex.ECDSA_256k1]:
            self._verify = self._secp256k1
        else:
            raise ValueError("Unsupported code = {} for verifier.".format(self.code))

    def verify(self, sig, ser):
        """
        Returns True if bytes signature sig verifies on bytes serialization ser
        using .raw as verifier public key for ._verify cipher suite determined
        by .code

        Parameters:
            sig is bytes signature
            ser is bytes serialization
        """
        return (self._verify(sig=sig, ser=ser, key=self.raw))

    @staticmethod
    def _ed25519(sig, ser, key):
        """
        Returns True if verified False otherwise
        Verify Ed25519 sig on ser using key

        Parameters:
            sig is bytes signature
            ser is bytes serialization
            key is bytes public key
        """
        try:  # verify returns None if valid else raises ValueError
            pysodium.crypto_sign_verify_detached(sig, ser, key)
        except Exception as ex:
            return False

        return True

    @staticmethod
    def _secp256r1(sig, ser, key):
        """
        Returns True if verified False otherwise
        Verify secp256r1 sig on ser using key

        Parameters:
            sig is bytes signature
            ser is bytes serialization
            key is bytes public key
        """
        verkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key)
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        der = utils.encode_dss_signature(r, s)
        try:
            verkey.verify(der, ser, ec.ECDSA(hashes.SHA256()))
            return True
        except exceptions.InvalidSignature:
            return False

    @staticmethod
    def _secp256k1(sig, ser, key):
        """
        Returns True if verified False otherwise
        Verify secp256k1 sig on ser using key

        Parameters:
            sig is bytes signature
            ser is bytes serialization
            key is bytes public key
        """
        verkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), key)
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        der = utils.encode_dss_signature(r, s)
        try:
            verkey.verify(der, ser, ec.ECDSA(hashes.SHA256()))
            return True
        except exceptions.InvalidSignature:
            return False


class Cigar(Matter):
    """
    Cigar is Matter subclass holding a nonindexed signature with verfer property.
        From Matter .raw is signature and .code is signature cipher suite
    Adds .verfer property to hold Verfer instance of associated verifier public key
        Verfer's .raw as verifier key and .code is verifier cipher suite.

    See Matter for inherited attributes and properties:

    Attributes:

    Properties:  (Inherited)
        .code is str derivation code to indicate cypher suite
        .size is size (int): number of quadlets when variable sized material besides
                        full derivation code else None
        .raw is bytes crypto material only without code
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .transferable is Boolean, True when transferable derivation code False otherwise
        .digestive is Boolean, True when digest derivation code False otherwise

    Properties:
        .verfer is verfer of public key used to verify signature

    Hidden:
        ._code is str value for .code property
        ._size is int value for .size property
        ._raw is bytes value for .raw property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64

    Methods:

    Hidden:
        ._pad is method to compute  .pad property
        ._code is str value for .code property
        ._raw is bytes value for .raw property
        ._index is int value for .index property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64

    """

    def __init__(self, verfer=None, **kwa):
        """
        Assign verfer to ._verfer attribute

        """
        super(Cigar, self).__init__(**kwa)
        self._verfer = verfer

    @property
    def verfer(self):
        """
        Property verfer:
        Returns Verfer instance
        Assumes ._verfer is correctly assigned
        """
        return self._verfer

    @verfer.setter
    def verfer(self, verfer):
        """ verfer property setter """
        self._verfer = verfer



class Signer(Matter):
    """
    Signer is Matter subclass with method to create signature of serialization
    using:
        .raw as signing (private) key seed,
        .code as cipher suite for signing
        .verfer whose property .raw is public key for signing.

    If not provided .verfer is generated from private key seed using .code
    as cipher suite for creating key-pair.


    See Matter for inherited attributes and properties:

    Attributes:

    Properties:  (inherited)
        code (str): hard part of derivation code to indicate cypher suite
        both (int): hard and soft parts of full text code
        size (int): Number of triplets of bytes including lead bytes
            (quadlets of chars) of variable sized material. Value of soft size,
            ss, part of full text code.
            Otherwise None.
        rize (int): number of bytes of raw material not including
                    lead bytes
        raw (bytes): private signing key crypto material only without code
        qb64 (str): private signing key Base64 fully qualified with
                    derivation code + crypto mat
        qb64b (bytes): private signing keyBase64 fully qualified with
            derivation code + crypto mat
        qb2  (bytes): private signing key binary with
            derivation code + crypto material
        transferable (bool): True means transferable derivation code False otherwise
        digestive (bool): True means digest derivation code False otherwise

    Properties:

        .verfer is Verfer object instance of public key derived from private key
            seed which is .raw

    Methods:
        sign: create signature

    """

    def __init__(self, raw=None, code=MtrDex.Ed25519_Seed, transferable=True, **kwa):
        """
        Assign signing cipher suite function to ._sign

        Parameters:  See Matter for inherted parameters
            raw is bytes crypto material seed or private key
            code is derivation code
            transferable is Boolean True means make verifier code transferable
                                    False make non-transferable

        """
        try:
            super(Signer, self).__init__(raw=raw, code=code, **kwa)
        except EmptyMaterialError as ex:
            if code == MtrDex.Ed25519_Seed:
                raw = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
                super(Signer, self).__init__(raw=raw, code=code, **kwa)
            elif code == MtrDex.ECDSA_256r1_Seed:
                raw = pysodium.randombytes(ECDSA_256r1_SEEDBYTES)
                super(Signer, self).__init__(raw=bytes(raw), code=code, **kwa)
            elif code == MtrDex.ECDSA_256k1_Seed:
                raw = pysodium.randombytes(ECDSA_256k1_SEEDBYTES)
                super(Signer, self).__init__(raw=bytes(raw), code=code, **kwa)

            else:
                raise ValueError("Unsupported signer code = {}.".format(code))

        if self.code == MtrDex.Ed25519_Seed:
            self._sign = self._ed25519
            verkey, sigkey = pysodium.crypto_sign_seed_keypair(self.raw)
            verfer = Verfer(raw=verkey,
                            code=MtrDex.Ed25519 if transferable
                            else MtrDex.Ed25519N)
        elif self.code == MtrDex.ECDSA_256r1_Seed:
            self._sign = self._secp256r1
            d = int.from_bytes(self.raw, byteorder="big")
            sigkey = ec.derive_private_key(d, ec.SECP256R1())
            verkey = sigkey.public_key().public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint)
            verfer = Verfer(raw=verkey,
                            code=MtrDex.ECDSA_256r1 if transferable
                            else MtrDex.ECDSA_256r1N)
        elif self.code == MtrDex.ECDSA_256k1_Seed:
            self._sign = self._secp256k1
            d = int.from_bytes(self.raw, byteorder="big")
            sigkey = ec.derive_private_key(d, ec.SECP256K1())
            verkey = sigkey.public_key().public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint)
            verfer = Verfer(raw=verkey,
                            code=MtrDex.ECDSA_256k1 if transferable
                            else MtrDex.ECDSA_256k1N)
        else:
            raise ValueError("Unsupported signer code = {}.".format(self.code))

        self._verfer = verfer

    @property
    def verfer(self):
        """
        Property verfer:
        Returns Verfer instance
        Assumes ._verfer is correctly assigned
        """
        return self._verfer

    def sign(self, ser, index=None, only=False, ondex=None, **kwa):
        """
        Returns either Cigar or Siger (indexed) instance of cryptographic
        signature material on bytes serialization ser

        If index is None
            return Cigar instance
        Else
            return Siger instance

        Parameters:
            ser (bytes): serialization to be signed
            index (int):  main index of associated verifier key in event keys
            only (bool): True means main index only list, ondex ignored
                          False means both index lists (default), ondex used
            ondex (int | None): other index offset into list such as prior next

        """
        return (self._sign(ser=ser,
                           seed=self.raw,
                           verfer=self.verfer,
                           index=index,
                           only=only,
                           ondex=ondex,
                           **kwa))

    @staticmethod
    def _ed25519(ser, seed, verfer, index, only=False, ondex=None, **kwa):
        """
        Returns signature as either Cigar or Siger instance as appropriate for
        Ed25519 digital signatures given index and ondex values

        The seed's code determins the crypto key-pair algorithm and signing suite
        The signature type, Cigar or Siger, and when indexed the Siger code
        may be completely determined by the seed and index values (index, ondex)
        by assuming that the index values are intentional.
        Without the seed code its more difficult for Siger to
        determine when for the Indexer code value should be changed from the
        than the provided value with respect to provided but incompatible index
        values versus error conditions.

        Parameters:
            ser (bytes): serialization to be signed
            seed (bytes):  raw binary seed (private key)
            verfer (Verfer): instance. verfer.raw is public key
            index (int |None): main index offset into list such as current signing
                None means return non-indexed Cigar
                Not None means return indexed Siger with Indexer code derived
                    from index, conly, and ondex values
            only (bool): True means main index only list, ondex ignored
                          False means both index lists (default), ondex used
            ondex (int | None): other index offset into list such as prior next
        """
        # compute raw signature sig using seed on serialization ser
        sig = pysodium.crypto_sign_detached(ser, seed + verfer.raw)

        if index is None:  # Must be Cigar i.e. non-indexed signature
            return Cigar(raw=sig, code=MtrDex.Ed25519_Sig, verfer=verfer)
        else:  # Must be Siger i.e. indexed signature
            # should add Indexer class method to get ms main index size for given code
            if only:  # only main index ondex not used
                ondex = None
                if index <= 63: # (64 ** ms - 1) where ms is main index size
                    code = indexing.IdrDex.Ed25519_Crt_Sig  # use small current only
                else:
                    code = indexing.IdrDex.Ed25519_Big_Crt_Sig  # use big current only
            else:  # both
                if ondex == None:
                    ondex = index  # enable default to be same
                if ondex == index and index <= 63:  # both same and small
                    code = indexing.IdrDex.Ed25519_Sig  # use  small both same
                else:  # otherwise big or both not same so use big both
                    code = indexing.IdrDex.Ed25519_Big_Sig  # use use big both

            return indexing.Siger(raw=sig,
                                    code=code,
                                    index=index,
                                    ondex=ondex,
                                    verfer=verfer,)

    @staticmethod
    def _secp256r1(ser, seed, verfer, index, only=False, ondex=None, **kwa):
        """
        Returns signature as either Cigar or Siger instance as appropriate for
        Ed25519 digital signatures given index and ondex values

        The seed's code determins the crypto key-pair algorithm and signing suite
        The signature type, Cigar or Siger, and when indexed the Siger code
        may be completely determined by the seed and index values (index, ondex)
        by assuming that the index values are intentional.
        Without the seed code its more difficult for Siger to
        determine when for the Indexer code value should be changed from the
        than the provided value with respect to provided but incompatible index
        values versus error conditions.

        Parameters:
            ser (bytes): serialization to be signed
            seed (bytes):  raw binary seed (private key)
            verfer (Verfer): instance. verfer.raw is public key
            index (int |None): main index offset into list such as current signing
                None means return non-indexed Cigar
                Not None means return indexed Siger with Indexer code derived
                    from index, conly, and ondex values
            only (bool): True means main index only list, ondex ignored
                          False means both index lists (default), ondex used
            ondex (int | None): other index offset into list such as prior next
        """
        # compute raw signature sig using seed on serialization ser
        d = int.from_bytes(seed, byteorder="big")
        sigkey = ec.derive_private_key(d, ec.SECP256R1())
        der = sigkey.sign(ser, ec.ECDSA(hashes.SHA256()))
        (r, s) = utils.decode_dss_signature(der)
        sig = bytearray(r.to_bytes(32, "big"))
        sig.extend(s.to_bytes(32, "big"))

        if index is None:  # Must be Cigar i.e. non-indexed signature
            return Cigar(raw=sig, code=MtrDex.ECDSA_256r1_Sig, verfer=verfer)
        else:  # Must be Siger i.e. indexed signature
            # should add Indexer class method to get ms main index size for given code
            if only:  # only main index ondex not used
                ondex = None
                if index <= 63: # (64 ** ms - 1) where ms is main index size
                    code = indexing.IdrDex.ECDSA_256r1_Crt_Sig  # use small current only
                else:
                    code = indexing.IdrDex.ECDSA_256r1_Big_Crt_Sig  # use big current only
            else:  # both
                if ondex == None:
                    ondex = index  # enable default to be same
                if ondex == index and index <= 63:  # both same and small
                    code = indexing.IdrDex.ECDSA_256r1_Sig  # use  small both same
                else:  # otherwise big or both not same so use big both
                    code = indexing.IdrDex.ECDSA_256r1_Big_Sig  # use use big both

            return indexing.Siger(raw=sig,
                                    code=code,
                                    index=index,
                                    ondex=ondex,
                                    verfer=verfer,)

    @staticmethod
    def _secp256k1(ser, seed, verfer, index, only=False, ondex=None, **kwa):
        """
        Returns signature as either Cigar or Siger instance as appropriate for
        secp256k1 digital signatures given index and ondex values

        The seed's code determins the crypto key-pair algorithm and signing suite
        The signature type, Cigar or Siger, and when indexed the Siger code
        may be completely determined by the seed and index values (index, ondex)
        by assuming that the index values are intentional.
        Without the seed code its more difficult for Siger to
        determine when for the Indexer code value should be changed from the
        than the provided value with respect to provided but incompatible index
        values versus error conditions.

        Parameters:
            ser (bytes): serialization to be signed
            seed (bytes):  raw binary seed (private key)
            verfer (Verfer): instance. verfer.raw is public key
            index (int |None): main index offset into list such as current signing
                None means return non-indexed Cigar
                Not None means return indexed Siger with Indexer code derived
                    from index, conly, and ondex values
            only (bool): True means main index only list, ondex ignored
                          False means both index lists (default), ondex used
            ondex (int | None): other index offset into list such as prior next
        """
        # compute raw signature sig using seed on serialization ser
        d = int.from_bytes(seed, byteorder="big")
        sigkey = ec.derive_private_key(d, ec.SECP256K1())
        der = sigkey.sign(ser, ec.ECDSA(hashes.SHA256()))
        (r, s) = utils.decode_dss_signature(der)
        sig = bytearray(r.to_bytes(32, "big"))
        sig.extend(s.to_bytes(32, "big"))

        if index is None:  # Must be Cigar i.e. non-indexed signature
            return Cigar(raw=sig, code=MtrDex.ECDSA_256k1_Sig, verfer=verfer)
        else:  # Must be Siger i.e. indexed signature
            # should add Indexer class method to get ms main index size for given code
            if only:  # only main index ondex not used
                ondex = None
                if index <= 63: # (64 ** ms - 1) where ms is main index size
                    code = indexing.IdrDex.ECDSA_256k1_Crt_Sig  # use small current only
                else:
                    code = indexing.IdrDex.ECDSA_256k1_Big_Crt_Sig  # use big current only
            else:  # both
                if ondex == None:
                    ondex = index  # enable default to be same
                if ondex == index and index <= 63:  # both same and small
                    code = indexing.IdrDex.ECDSA_256k1_Sig  # use  small both same
                else:  # otherwise big or both not same so use big both
                    code = indexing.IdrDex.ECDSA_256k1_Big_Sig  # use use big both

            return indexing.Siger(raw=sig,
                                code=code,
                                index=index,
                                ondex=ondex,
                                verfer=verfer,)



class Salter(Matter):
    """
    Salter is Matter subclass to maintain random salt for secrets (private keys)
    Its .raw is random salt, .code as cipher suite for salt

    Attributes:
        .level is str security level code. Provides default level

    Inherited Properties
        .pad  is int number of pad chars given raw
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .index is int count of attached crypto material by context (receipts)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .transferable is Boolean, True when transferable derivation code False otherwise

    Properties:

    Methods:

    Hidden:
        ._pad is method to compute  .pad property
        ._code is str value for .code property
        ._raw is bytes value for .raw property
        ._index is int value for .index property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64

    """
    Tier = Tiers.low

    def __init__(self, raw=None, code=MtrDex.Salt_128, tier=None, **kwa):
        """
        Initialize salter's raw and code

        Inherited Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes

        Parameters:

        """
        try:
            super(Salter, self).__init__(raw=raw, code=code, **kwa)
        except EmptyMaterialError as ex:
            if code == MtrDex.Salt_128:
                raw = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
                super(Salter, self).__init__(raw=raw, code=code, **kwa)
            else:
                raise ValueError("Unsupported salter code = {}.".format(code))

        if self.code not in (MtrDex.Salt_128,):
            raise ValueError("Unsupported salter code = {}.".format(self.code))

        self.tier = tier if tier is not None else self.Tier

    def stretch(self, *, size=32, path="", tier=None, temp=False):
        """
        Returns (bytes): raw binary seed (secret) derived from path and .raw
        and stretched to size given by code using argon2d stretching algorithm.

        Parameters:
            size (int): number of bytes in stretched seed
            path (str): unique chars used in derivation of seed (secret)
            tier (str): value from Tierage for security level of stretch
            temp is Boolean, True means use quick method to stretch salt
                    for testing only, Otherwise use time set by tier to stretch
        """
        tier = tier if tier is not None else self.tier

        if temp:
            opslimit = 1  # pysodium.crypto_pwhash_OPSLIMIT_MIN
            memlimit = 8192  # pysodium.crypto_pwhash_MEMLIMIT_MIN
        else:
            if tier == Tiers.low:
                opslimit = 2  # pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
                memlimit = 67108864  # pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
            elif tier == Tiers.med:
                opslimit = 3  # pysodium.crypto_pwhash_OPSLIMIT_MODERATE
                memlimit = 268435456  # pysodium.crypto_pwhash_MEMLIMIT_MODERATE
            elif tier == Tiers.high:
                opslimit = 4  # pysodium.crypto_pwhash_OPSLIMIT_SENSITIVE
                memlimit = 1073741824  # pysodium.crypto_pwhash_MEMLIMIT_SENSITIVE
            else:
                raise ValueError("Unsupported security tier = {}.".format(tier))

        # stretch algorithm is argon2id
        seed = pysodium.crypto_pwhash(outlen=size,
                                      passwd=path,
                                      salt=self.raw,
                                      opslimit=opslimit,
                                      memlimit=memlimit,
                                      alg=pysodium.crypto_pwhash_ALG_ARGON2ID13)
        return (seed)

    def signer(self, *, code=MtrDex.Ed25519_Seed, transferable=True, path="",
               tier=None, temp=False):
        """
        Returns Signer instance whose .raw secret is derived from path and
        salter's .raw and stretched to size given by code. The signers public key
        for its .verfer is derived from code and transferable.

        Parameters:
            code is str code of secret crypto suite
            transferable is Boolean, True means use transferace code for public key
            path is str of unique chars used in derivation of secret seed for signer
            tier is str Tierage security level
            temp is Boolean, True means use quick method to stretch salt
                    for testing only, Otherwise use more time to stretch
        """
        seed = self.stretch(size=Matter._rawSize(code), path=path, tier=tier,
                            temp=temp)

        return (Signer(raw=seed, code=code, transferable=transferable))


    def signers(self, count=1, start=0, path="",  **kwa):
        """
        Returns list of count number of Signer instances with unique derivation
        path made from path prefix and suffix of start plus offset for each count
        value from 0 to count - 1.

        See .signer for parameters used to create each signer.

        """
        return [self.signer(path=f"{path}{i + start:x}", **kwa) for i in range(count)]
