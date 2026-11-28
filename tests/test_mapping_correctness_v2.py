"""Independent TS/Python semantic-port-source contract; fixed negative truths."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1] / 'runtime' / 'multipass'))
from stellar_dictionary import _explicit_port_target


class PortIdentity(unittest.TestCase):
    def test_no_translated_field_becomes_original_port(self):
        for source in (
            'nat.source-port','nat_source.source-port','post_nat.source-port',
            'translated_source.source-port','source_nat.source-port',
            'postNat.source-port','sourceTranslation.source-port',
            'snat.source-port','dnat.source-port',
            'pre-nat.destination-port',
            'network_address_translation.destination-port',
        ):
            for syntax in ('JSON','KV','SYSLOG_RFC5424','SYSLOG_RFC3164+KV'):
                with self.subTest(source=source,syntax=syntax):
                    self.assertIsNone(_explicit_port_target(source,syntax))

    def test_a_port_label_is_a_port_only_where_it_stands_for_the_record(self):
        # At the root, in the body an envelope reader wrote, or as the SD-PARAM of an RFC 5424 element.
        self.assertEqual(_explicit_port_target('source-port','KV'),'srcport')
        self.assertEqual(_explicit_port_target('destination-port','JSON'),'dstport')
        self.assertEqual(_explicit_port_target('body.source-port','SYSLOG_RFC3164+KV'),'srcport')
        self.assertEqual(_explicit_port_target(
            'syslog.structured_data.junos@67.43.156.15.destination-port','SYSLOG_RFC5424'),'dstport')
        # Default deny (owner decision 2026-11-28): a member of any other object of the record names that
        # object. `national.source-port` was taken for the source port of the record until then.
        for source,syntax in (
            ('national.source-port','JSON'),('event.destination-port','JSON'),
            ('body.source-port','JSON'),('body.flow.source-port','SYSLOG_RFC3164+KV'),
            ('syslog.structured_data.x.source-port','JSON'),
            ('syslog_sd.element_1.params.source-port','JSON'),
        ):
            with self.subTest(source=source,syntax=syntax):
                self.assertIsNone(_explicit_port_target(source,syntax))


if __name__ == '__main__':
    unittest.main()
