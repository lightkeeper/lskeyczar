#!/usr/bin/python2.4
#
# Copyright 2011 LightKeeper LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Testcases to test behavior of Keyczar Crypters.

@author: rleftwich@lightkeeper.com (Robert Leftwich)
"""
import unittest
import json

from Crypto.PublicKey import pubkey

from keyczar import keys
from keyczar import util

class ExportTest(unittest.TestCase):

  # This data is taken from the unit tests for Twisted Conch
  # (the assumption being that it is valid)
  RSAData = {
    'n':long('1062486685755247411169438309495398947372127791189432809481'
             '382072971106157632182084539383569281493520117634129557550415277'
             '516685881326038852354459895734875625093273594925884531272867425'
             '864910490065695876046999646807138717162833156501L'),
    'e':35L,
    'd':long('6678487739032983727350755088256793383481946116047863373882'
             '973030104095847973715959961839578340816412167985957218887914482'
             '713602371850869127033494910375212470664166001439410214474266799'
             '85974425203903884190893469297150446322896587555L'),
    'q':long('3395694744258061291019136154000709371890447462086362702627'
             '9704149412726577280741108645721676968699696898960891593323L'),
    'p':long('3128922844292337321766351031842562691837301298995834258844'
             '4720539204069737532863831050930719431498338835415515173887L')}

  privateRSA_openssh = """-----BEGIN RSA PRIVATE KEY-----
MIIByAIBAAJhAK8ycfDmDpyZs3+LXwRLy4vA1T6yd/3PZNiPwM+uH8Yx3/YpskSW
4sbUIZR/ZXzY1CMfuC5qyR+UDUbBaaK3Bwyjk8E02C4eSpkabJZGB0Yr3CUpG4fw
vgUd7rQ0ueeZlQIBIwJgbh+1VZfr7WftK5lu7MHtqE1S1vPWZQYE3+VUn8yJADyb
Z4fsZaCrzW9lkIqXkE3GIY+ojdhZhkO1gbG0118sIgphwSWKRxK0mvh6ERxKqIt1
xJEJO74EykXZV4oNJ8sjAjEA3J9r2ZghVhGN6V8DnQrTk24Td0E8hU8AcP0FVP+8
PQm/g/aXf2QQkQT+omdHVEJrAjEAy0pL0EBH6EVS98evDCBtQw22OZT52qXlAwZ2
gyTriKFVoqjeEjt3SZKKqXHSApP/AjBLpF99zcJJZRq2abgYlf9lv1chkrWqDHUu
DZttmYJeEfiFBBavVYIF1dOlZT0G8jMCMBc7sOSZodFnAiryP+Qg9otSBjJ3bQML
pSTqy7c3a2AScC/YyOwkDaICHnnD3XyjMwIxALRzl0tQEKMXs6hH8ToUdlLROCrP
EhQ0wahUTCk1gKA4uPD6TMTChavbh4K63OvbKg==
-----END RSA PRIVATE KEY-----"""

  DSAData = {
    'y':long('2300663509295750360093768159135720439490120577534296730713'
             '348508834878775464483169644934425336771277908527130096489120714'
             '610188630979820723924744291603865L'),
    'g':long('4451569990409370769930903934104221766858515498655655091803'
             '866645719060300558655677517139568505649468378587802312867198352'
             '1161998270001677664063945776405L'),
    'p':long('7067311773048598659694590252855127633397024017439939353776'
             '608320410518694001356789646664502838652272205440894335303988504'
             '978724817717069039110940675621677L'),
    'q':1184501645189849666738820838619601267690550087703L,
    'x':863951293559205482820041244219051653999559962819L}

  privateDSA_openssh = """-----BEGIN DSA PRIVATE KEY-----
MIH4AgEAAkEAhvBM5KxnsGXtTUrIw2pXXdO7vJEC1OvvQ9UjdCd+s+6Z/ZTMKCkv
WWNsrFJ8CLTle+sT/W98IUCwVhdFkuFDLQIVAM965Akmo6eAi7K+k9qDR4TotFAX
AkAA2ZaU1veuIWkFkuLwtOtzRnZXU+saVBg3A0am5vdAqDxGtkZjTrjqovJZ24WK
2hM8qWB9yuBs7/28QgZyrR0VAkAr7WizJYFLT4/3S7+sC6SjpyFn3y2FRJjaQtIe
nqEsrLLZuOdPb2HuFoQsT5cd+rZsz19yQPHYUs5IgnPLzdWZAhUAl1TqdmlAG/b4
nnVchGiO9sML8MM=
-----END DSA PRIVATE KEY-----"""

  def _encode(self, val):
    """Helper to encode a number for use by Keyczar json format"""
    return util.Base64WSEncode(util.BigIntToBytes(val))

  def testRSA(self):
    p = self.RSAData['p']
    q = self.RSAData['q']
    d = self.RSAData['d']
    u = pubkey.inverse(p, q)
    params = {
      'crtCoefficient': self._encode(u),
      'primeExponentP': self._encode(d % (q - 1)),
      'primeExponentQ': self._encode(d % (p - 1)),
      'primeP': self._encode(p),
      'primeQ': self._encode(q),
      'privateExponent': self._encode(d),
      'publicKey': {
        'modulus': self._encode(self.RSAData['n']),
        'publicExponent': self._encode(self.RSAData['e']),
        'size': 2048
      },
      'size': 2048}

    rsaKey = keys.RsaPrivateKey.Read(json.dumps(params))
    self.assertEquals(rsaKey._Export_openssh(), self.privateRSA_openssh)

    # test base class handles export
    self.assertEquals(rsaKey.Export('OpenSSH'), self.privateRSA_openssh)

    # test base class handles mixed case export
    self.assertEquals(rsaKey.Export('oPEnSsh'), self.privateRSA_openssh)

    # test base class handles unsupported export
    self.assertRaises(NotImplementedError, rsaKey.Export, 'baz')

  def testDSA(self):
    y = self.DSAData['y']
    g = self.DSAData['g']
    p = self.DSAData['p']
    q = self.DSAData['q']
    x = self.DSAData['x']
    params = {
      'y': self._encode(y),
      'g': self._encode(g),
      'p': self._encode(p),
      'q': self._encode(q),
      'x': self._encode(x),
      'publicKey': {
        'y': self._encode(y),
        'g': self._encode(g),
        'p': self._encode(p),
        'q': self._encode(q),
        'size': 2048
      },
      'size': 2048
    }

    dsaKey = keys.DsaPrivateKey.Read(json.dumps(params))
    self.assertEquals(dsaKey._Export_openssh(), self.privateDSA_openssh)

    # test base class handles export
    self.assertEquals(dsaKey.Export('OpenSSH'), self.privateDSA_openssh)

    # test base class handles mixed case export
    self.assertEquals(dsaKey.Export('oPeNSsh'), self.privateDSA_openssh)

    # test base class handles unsupported export
    self.assertRaises(NotImplementedError, dsaKey.Export, 'baz')

def suite():
  alltests = unittest.TestSuite(
    [
     unittest.TestLoader().loadTestsFromTestCase(ExportTest)
    ])

  return alltests

if __name__ == "__main__":
  unittest.main(defaultTest='suite')

