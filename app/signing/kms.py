from __future__ import annotations

from typing import Callable


class KMSDelegatingKey:
    """Provider-neutral KMS/HSM adapter; inject sign and verify operations from AWS/GCP/Azure/Vault."""
    def __init__(self,key_id: str,sign_fn: Callable[[bytes],bytes],verify_fn: Callable[[bytes,bytes],None]):
        self._key_id,self._sign,self._verify=key_id,sign_fn,verify_fn
    @property
    def key_id(self)->str:return self._key_id
    def sign(self,payload:bytes)->bytes:return self._sign(payload)
    def verify(self,payload:bytes,signature:bytes)->None:self._verify(payload,signature)
