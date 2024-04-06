import pytest

from kami.core.coring import Salter, MtrDex, Matter, Tiers
from kami.kering import ShortageError


def test_salter():
    """
    Test the support functionality for salter subclass of crymat
    """
    salter = Salter()  # defaults to CryTwoDex.Salt_128
    assert salter.code == MtrDex.Salt_128
    assert len(salter.raw) == Matter._rawSize(salter.code) == 16

    raw = b'0123456789abcdef'
    salter = Salter(raw=raw)
    assert salter.raw == raw
    assert salter.qb64 == '0AAwMTIzNDU2Nzg5YWJjZGVm'  #'0ACDEyMzQ1Njc4OWFiY2RlZg'

    signer = salter.signer(path="01", temp=True)  # defaults to Ed25519
    assert signer.code == MtrDex.Ed25519_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.verfer.code == MtrDex.Ed25519
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)
    assert signer.qb64 == 'AMPsqBZxWdtYpBhrWnKYitwFa77s902Q-nX3sPTzqs0R'
    #'Aw-yoFnFZ21ikGGtacpiK3AVrvuz3TZD6dfew9POqzRE'
    assert signer.verfer.qb64 == 'DFYFwZJOMNy3FknECL8tUaQZRBUyQ9xCv6F8ckG-UCrC'  #
    # 'DVgXBkk4w3LcWScQIvy1RpBlEFTJD3EK_oXxyQb5QKsI'

    signer = salter.signer(path="01")  # defaults to Ed25519 temp = False level="low"
    assert signer.code == MtrDex.Ed25519_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.verfer.code == MtrDex.Ed25519
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)
    assert signer.qb64 == 'AEkqQiNTexWB9fTLpgJp_lXW63tFlT-Y0_mgQww4o-dC'
    # 'ASSpCI1N7FYH19MumAmn-Vdbre0WVP5jT-aBDDDij50I'
    assert signer.verfer.qb64 == 'DPJGyH9H1M_SUSf18RzX8OqdyhxEyZJpKm5Em0PnpsWd'
    #'D8kbIf0fUz9JRJ_XxHNfw6p3KHETJkmkqbkSbQ-emxZ0'

    salter = Salter(qb64='0AAwMTIzNDU2Nzg5YWJjZGVm')
    assert salter.raw == raw
    assert salter.qb64 == '0AAwMTIzNDU2Nzg5YWJjZGVm'

    with pytest.raises(ShortageError):
        salter = Salter(qb64='')

    salter = Salter(raw=raw)
    assert salter.stretch(temp=True) == b'\xd4@\xeb\xa6x\x86\xdf\x93\xd6C\xdc\xb8\xa6\x9b\x02\xafh\xc1m(L\xd6\xf6\x86YU>$[\xf9\xef\xc0'
    assert salter.stretch(tier=Tiers.low) == b'\xf8e\x80\xbaX\x08\xb9\xba\xc6\x1e\x84\r\x1d\xac\xa7\\\x82Wc@`\x13\xfd\x024t\x8ct\xd3\x01\x19\xe9'
    assert salter.stretch(tier=Tiers.med) == b',\xf3\x8c\xbb\xe9)\nSQ\xec\xad\x8c9?\xaf\xb8\xb0\xb3\xcdB\xda\xd8\xb6\xf7\r\xf6D}Z\xb9Y\x16'
    assert salter.stretch(tier=Tiers.high) == b'(\xcd\xc4\xb85\xcd\xe8:\xfc\x00\x8b\xfd\xa6\tj.y\x98\x0b\x04\x1c\xe3hBc!I\xe49K\x16-'