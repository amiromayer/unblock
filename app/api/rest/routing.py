"""
REST API Resource Routing

http://flask-restful.readthedocs.io/en/latest/
"""

import time
from flask import request
from app.api.rest.base import BaseResource, SecureResource, rest_resource

from bip32 import Wallet
from network import BitcoinMainNet


@rest_resource
class ResourceOne(BaseResource):
    """ /api/resource/one """
    endpoints = ['/resource/one']

    def get(self):
        time.sleep(1)
        return {'name': 'Resource One', 'data': True}

    def post(self):
        json_payload = request.json
        return {'name': 'Resource Post'}

@rest_resource
class SecureResourceOne(BaseResource):
    """ /api/resource/two """
    endpoints = ['/resource/two/<int:keysNumber>']

    def get(self, keysNumber):
        time.sleep(1)
        return {'name': 'Resource Two', 'data': keysNumber}

@rest_resource
class PublicKey(BaseResource):
    """ /api/get_pub_key """
    endpoints = ['/get_pub_key/<int:keysNumber>']

    def get(self, keysNumber):
        time.sleep(1)
        return {'name': 'Public key', 'data': keysNumber}

@rest_resource
class ExtendedKeys(BaseResource):
    """ /api/get_extended_keys """
    endpoints = ['/get_extended_keys/<string:seed>']

    def get(self, seed):
        time.sleep(1)

        master_wallet = Wallet.from_master_secret(seed = seed, network = BitcoinMainNet)

        master_private_key = master_wallet.serialize_b58(private=True)
        master_public_key = master_wallet.public_copy().serialize_b58(private=False)

        return {'name': 'Extended keys', 'ext_master_private_key': master_private_key, 'ext_master_public_key': master_public_key}