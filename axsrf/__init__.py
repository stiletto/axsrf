# Copyright 2014 by Stiletto <blasux@blasux.ru>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# This library is heavily based on CSRF protection of Facebook's Tornado
#

import array
import base64
import hmac
import os
import struct
import time
from itertools import izip

def _xor_mask(mask, data):
    mask = array.array("B", mask)
    data = array.array("B", data)
    masklen = len(mask)
    datalen = len(data)
    for i in xrange(datalen):
        data[i] ^= mask[i % masklen]
    if hasattr(data, 'tobytes'):
        return data.tobytes()
    else:
        return data.tostring()

if hasattr(hmac, 'compare_digest'):
    _compare_digest = hmac.compare_digest
else:
    def _compare_digest(a, b):
        if len(a) != len(b):
            return False
        result = 0
        for x,y in izip(a, b):
            result |= ord(x) ^ ord(y)
        return result == 0

_TOKEN_STRUCT = '>c4s16sq'

class Token(object):
    """ This is the main interface of aXSRF.
        Create a Token when your application receives new request, pass it a value of CSRF protection cookie and save Token in request context.
        *callback(new_cookie)* should be a function that could change value of CSRF protection cookie."""
    def __init__(self, cookie=None, callback=None):
        self._encoded = self._raw = None
        self._cookie = cookie
        self._callback = callback

    @property
    def encoded(self):
        """ Encoded form of token. This property is regenerated once per Token creation. Use it's value in hidden form fields. """
        if not self._encoded:
            token, timestamp = self.raw #_create_token(self.cookie)
            mask = os.urandom(4)
            raw_value = struct.pack(_TOKEN_STRUCT, 'A', mask, _xor_mask(mask, token), timestamp)
            self._encoded = base64.b64encode(raw_value)
            if self._callback:
                self._callback(self._encoded)
        return self._encoded

    @property
    def raw(self):
        """ I wonder why I made this property public. """
        if not self._raw:
            self._raw = _create_token(self._cookie)
        return self._raw

    def check(self, posted):
        """ Compares this token with encoded form of another token (usually from a hidden form field). If tokens match returns True. Use this function in form action handlers."""
        posted, _ = _decode_token(posted)
        if posted is None:
            return False
        current, _ = self.raw
        if not _compare_digest(posted, current):
            return False
        return True

def _create_token(current):
    token, timestamp = _decode_token(current)
    if token is None:
        token = os.urandom(16)
        timestamp = time.time()
    return token, timestamp

def _decode_token(current):
    try:
        raw_value = base64.b64decode(current)
        ver, mask, masked_token, timestamp = struct.unpack(_TOKEN_STRUCT, raw_value)
    except (TypeError, struct.error):
        return None, None
    if ver != 'A':
        return None, None
    token = _xor_mask(mask, masked_token)
    return token, timestamp
