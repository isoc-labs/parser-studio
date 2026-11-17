"""A JSON number is read when a double stands for exactly the number that was written.

The rule of src/jsonNumberSafety.ts, checked here against exact decimal arithmetic, which neither the browser, the
generated Ruby nor the preview uses. Counting digits (more than 15 declined) declined the `ts` of every Zeek JSON
record: 1731719701.123456 has sixteen digits and is exactly what a double prints.
"""
import math
import random
import struct
import sys
import unittest
from decimal import Decimal
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime/multipass'))
from engine import _decimal_identity,_unsafe_json_float
from multipass_preview_api import preview


def exact(token:str)->bool:
    """Independent statement of the rule for a decimal or exponent spelling."""
    value=float(token)
    if not math.isfinite(value):
        return False
    if value==math.floor(value) and abs(value)>2**53-1:
        return False
    return Decimal(token)==Decimal(repr(value))


class JsonNumberExactness(unittest.TestCase):
    def test_numbers_printed_from_a_double_are_read(self):
        for token in ('1731719701.123456','1731719701.1234567','0.30000000000000004','1.0000000000000002',
                      '123456789012345.6','100.000000000000000','1e2','-0.0','1.5e-7'):
            self.assertFalse(_unsafe_json_float(token,float(token)),token)

    def test_numbers_a_double_does_not_stand_for_are_declined(self):
        for token in ('0.1234567890123456789','0.1000000000000000055511151231257827','1731719701.12345678',
                      '9007199254740993.0','9.007199254740993e15','1e-400','4.9e-324'):
            self.assertTrue(_unsafe_json_float(token,float(token)),token)

    def test_the_rule_is_exact_decimal_equality_on_random_spellings(self):
        rng=random.Random(20261116)
        tokens=[]
        for _ in range(4000):
            digits=''.join(rng.choice('0123456789') for _ in range(rng.randint(1,21))).lstrip('0') or '0'
            point=rng.randint(0,len(digits))
            token=(digits[:point] or '0')+('.'+digits[point:] if point<len(digits) else '.0')
            if rng.random()<0.35:
                token+=rng.choice('eE')+rng.choice(['','+','-'])+str(rng.randint(0,330))
            tokens.append(token)
        for _ in range(4000):
            value=struct.unpack('>d',struct.pack('>Q',rng.getrandbits(64)))[0]
            if math.isfinite(value):
                tokens.append(repr(value))
        checked=0
        for token in tokens:
            value=float(token)
            if not math.isfinite(value):
                continue
            checked+=1
            self.assertEqual(_unsafe_json_float(token,value),not exact(token),token)
        self.assertGreater(checked,7000)

    def test_an_exponent_of_any_length_is_judged_not_refused(self):
        """Audit of 2026-11-17 (F7): int() refuses a text of more than 4,300 digits, so an exponent that long made
        the whole event a syntax error. Zero with any exponent is zero; leading zeros of an exponent are no value."""
        nines='9'*5000; zeros='0'*5000
        self.assertEqual(_decimal_identity('0e'+nines),'0')
        self.assertEqual(_decimal_identity('1.5e'+zeros+'1'),_decimal_identity('15.0'))
        self.assertFalse(_unsafe_json_float('0e'+nines,0.0))
        self.assertFalse(_unsafe_json_float('1.5e'+zeros+'1',15.0))
        self.assertTrue(_unsafe_json_float('1.5e-'+nines,0.0))
        for raw in ('{"n":0e'+nines+'}','{"n":1.5e'+zeros+'1}'):
            self.assertEqual(preview(raw)['status'],'SOURCE_PARSED',raw[:20])
        self.assertIn('JSON_NUMBER_PRECISION_UNSAFE',str(preview('{"n":1.5e-'+nines+'}')['issues']))
        self.assertIn('JSON_NUMBER_RANGE_OR_CONSTANT_UNSUPPORTED',str(preview('{"n":1.5e'+nines+'}')['issues']))

    def test_identity_of_a_spelling(self):
        self.assertEqual(_decimal_identity('1731719701.123456'),'1731719701123456e-6')
        self.assertEqual(_decimal_identity('1.731719701123456e9'),'1731719701123456e-6')
        self.assertEqual(_decimal_identity('1731719701.1234560'),'1731719701123456e-6')
        self.assertEqual(_decimal_identity('-0.0'),'0')
        self.assertEqual(_decimal_identity('1e+21'),'1e21')

    def test_a_zeek_record_is_parsed_and_an_inexact_number_is_named(self):
        zeek='{"ts":1731719701.123456,"uid":"CHhAvVGS1DHFjwGM9","id.orig_h":"10.1.10.25","id.orig_p":51544,"proto":"tcp","duration":35.2}'
        result=preview(zeek)
        self.assertEqual(result['status'],'SOURCE_PARSED')
        self.assertEqual(result['fields']['ts'],1731719701.123456)
        declined=preview('{"ts":1731719701.12345678,"uid":"C1"}')
        self.assertEqual(declined['status'],'RAW_ONLY')
        self.assertIn('SOURCE_SYNTAX_ERROR:JSON_NUMBER_PRECISION_UNSAFE',declined['issues'])


if __name__=='__main__':
    unittest.main()
