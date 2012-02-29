#!/usr/bin/python
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
Testcases to test behavior of Keyczar utils.

@author: rleftwich@lightkeeper.com (Robert Leftwich)
"""

import unittest
import base64
import StringIO
import random
import os

from keyczar import util

class Base64WSStreamingReadTest(unittest.TestCase):

  def __readStream(self, stream, size=-1):
    result = ''
    read_data = True
    while read_data != '':
      if size >= 0:
        read_data = stream.read(size)
      else:
        read_data = stream.read()
      if read_data:
        result += read_data
    return result

  def __testRead(self, input_data, expected_result):
    for size in [1, 5, 4096, 99999, -1]:
      stream = util.IncrementalBase64WSStreamReader(StringIO.StringIO(input_data))
      self.assertEquals(self.__readStream(stream, size), expected_result)

  def testNoPadRead(self):
    no_pad_data = 'Some inspired test datum'
    b64_data = base64.urlsafe_b64encode(no_pad_data)
    self.assertFalse(b64_data.endswith('='))
    self.__testRead(b64_data, no_pad_data)

  def testSinglePadRead(self):
    single_pad_data = 'Some inspired test data'
    b64_data = base64.urlsafe_b64encode(single_pad_data)
    self.assertFalse(b64_data.endswith('=='))
    self.assertTrue(b64_data.endswith('='))
    self.__testRead(b64_data, single_pad_data)
    self.__testRead(b64_data[:-1], single_pad_data)

  def testDoublePadRead(self):
    double_pad_data = 'All inspired test data'
    b64_data = base64.urlsafe_b64encode(double_pad_data)
    self.assertTrue(b64_data.endswith('=='))
    self.__testRead(b64_data, double_pad_data)
    self.__testRead(b64_data[:-1], double_pad_data)
    self.__testRead(b64_data[:-2], double_pad_data)

  def testSimulateDecrypter(self):
    enc_data = \
    'AJehaFGwoOrkzpDCnF1zqIi721eCOMYWRmLyRyn3hxyhh_mYwpnDN6jKN057gr5lz' \
            'APFYhq9zoDwFMaGMEipEl__ECOZGeaxWw'
    expected_result = util.Base64WSDecode(enc_data)
    stream = util.IncrementalBase64WSStreamReader(StringIO.StringIO(enc_data))
    result = stream.read(5)
    result += stream.read(15)
    read_data = True
    while read_data:
      read_data = stream.read(4096)
      result += read_data
    self.assertEquals(result, expected_result)

class Base64WSStreamingWriteTest(unittest.TestCase):

  def __testWrite(self, input_data):

    expected_result = base64.urlsafe_b64encode(input_data)
    while expected_result[-1] == '=':
      expected_result = expected_result[:-1]

    for size in [1, 5, 4096, random.randrange(1, 9999), -1]:
      output_stream = StringIO.StringIO()
      stream = util.IncrementalBase64WSStreamWriter(output_stream)
      i = 0
      if size >= 0:
        while (i * size) <= len(input_data):
          stream.write(input_data[i * size:(i + 1) * size])
          i += 1
      else:
        stream.write(input_data)
      stream.flush()
      self.assertEquals(output_stream.getvalue(), expected_result)

  def testNoPadWrite(self):
    no_pad_data = 'Some inspired test datum'
    b64_data = base64.urlsafe_b64encode(no_pad_data)
    self.assertFalse(b64_data.endswith('='))
    self.__testWrite(no_pad_data)

  def testSinglePadWrite(self):
    single_pad_data = 'Some inspired test data'
    b64_data = base64.urlsafe_b64encode(single_pad_data)
    self.assertFalse(b64_data.endswith('=='))
    self.assertTrue(b64_data.endswith('='))
    self.__testWrite(single_pad_data)

  def testDoublePadWrite(self):
    double_pad_data = 'All inspired test data'
    b64_data = base64.urlsafe_b64encode(double_pad_data)
    self.assertTrue(b64_data.endswith('=='))
    self.__testWrite(double_pad_data)

  def testRandomLongerWrite(self):
    random_input_data = os.urandom(random.randrange(
      util.DEFAULT_STREAM_BUFF_SIZE * 2 + 1,
      50000))
    self.__testWrite(random_input_data)

class PackTest(unittest.TestCase):

  PackString = staticmethod(util.PackString)
  PackMPInt = staticmethod(util.PackMPInt)

  def testPackInt(self):
    self.assertEqual(
      self.PackMPInt(1),
      '\x00\x00\x00\x01\x01')
    self.assertEqual(
      self.PackMPInt(113),
      '\x00\x00\x00\x01q')

  def testPackBigInt(self):
    self.assertEqual(
      self.PackMPInt(16909060),
      '\x00\x00\x00\x04\x01\x02\x03\x04')
    self.assertEqual(
      self.PackMPInt(16909063),
      '\x00\x00\x00\x04\x01\x02\x03\x07')

class ExportOpenSSHPublicKeyTest(unittest.TestCase):

  ExportKey = staticmethod(util.ExportOpenSSHPublicKey)

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

  publicRSA_openssh = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAGEArzJx8OYOnJmzf4tfBE"
    "vLi8DVPrJ3/c9k2I/Az64fxjHf9imyRJbixtQhlH9lfNjUIx+4LmrJH5QNRsFporcHDKOTwTTYL"
    "h5KmRpslkYHRivcJSkbh/C+BR3utDS555mV comment")

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

  publicDSA_openssh = (
    "ssh-dss AAAAB3NzaC1kc3MAAABBAIbwTOSsZ7Bl7U1KyMNqV13Tu7"
    "yRAtTr70PVI3QnfrPumf2UzCgpL1ljbKxSfAi05XvrE/1vfCFAsFYXRZLhQy0AAAAVAM965Akmo"
    "6eAi7K+k9qDR4TotFAXAAAAQADZlpTW964haQWS4vC063NGdldT6xpUGDcDRqbm90CoPEa2RmNO"
    "uOqi8lnbhYraEzypYH3K4Gzv/bxCBnKtHRUAAABAK+1osyWBS0+P90u/rAuko6chZ98thUSY2kL"
    "SHp6hLKyy2bjnT29h7haELE+XHfq2bM9fckDx2FLOSIJzy83VmQ== comment")

  def testHandlesInvalidType(self):
    self.assertRaises(ValueError, self.ExportKey, 'foo', {})

  def testRSA(self):
    params = {'publicExponent': util.BigIntToBytes(self.RSAData['e']),
              'modulus': util.BigIntToBytes(self.RSAData['n'])}

    # check with comment
    self.assertEqual(self.ExportKey(
      'ssh-rsa', params, comment='comment'),
      self.publicRSA_openssh )

    # check with no comment
    self.assertEqual(self.ExportKey(
      'ssh-rsa', params),
      ' '.join(self.publicRSA_openssh.split()[:2])
    )

  def testDSA(self):
    params = {'p': util.BigIntToBytes(self.DSAData['p']),
              'q': util.BigIntToBytes(self.DSAData['q']),
              'g': util.BigIntToBytes(self.DSAData['g']),
              'y': util.BigIntToBytes(self.DSAData['y']),
              }

    # check with comment
    self.assertEqual(self.ExportKey(
      'ssh-dsa', params, comment='comment'),
      self.publicDSA_openssh )

    # check with no comment
    self.assertEqual(self.ExportKey(
      'ssh-dsa', params),
      ' '.join(self.publicDSA_openssh.split()[:2])
    )

def suite():
  alltests = unittest.TestSuite(
    [unittest.TestLoader().loadTestsFromTestCase(Base64WSStreamingReadTest),
     unittest.TestLoader().loadTestsFromTestCase(Base64WSStreamingWriteTest),
     unittest.TestLoader().loadTestsFromTestCase(PackTest),
     unittest.TestLoader().loadTestsFromTestCase(ExportOpenSSHPublicKeyTest),
    ])

  return alltests

if __name__ == "__main__":
  unittest.main(defaultTest='suite')
