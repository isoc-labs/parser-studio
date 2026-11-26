"""Independent ASA connection direction, NAT tuple and byte-span expectations."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"runtime"/"multipass"))
from security_asa import parse_asa_message
from source_parse import assert_source_accounting


class AsaDirection(unittest.TestCase):
    def test_built_direction_preserves_entire_socket_and_exact_spans(self):
        # Synthetic addresses, Cisco 302013/302015 layout; the first tuple
        # is the foreign endpoint, not necessarily the initiator.
        for message_id, proto in (("302013", "TCP"), ("302015", "UDP")):
            for direction, expected in (
                ("outbound", {
                    "src_interface":"inside","src_ip":"10.1.1.5","src_port":"52044",
                    "mapped_src_ip":"198.51.100.7","mapped_src_port":"61012",
                    "dst_interface":"outside","dst_ip":"203.0.113.10","dst_port":"443",
                    "mapped_dst_ip":"203.0.113.11","mapped_dst_port":"8443",
                }),
                ("inbound", {
                    "dst_interface":"inside","dst_ip":"10.1.1.5","dst_port":"52044",
                    "mapped_dst_ip":"198.51.100.7","mapped_dst_port":"61012",
                    "src_interface":"outside","src_ip":"203.0.113.10","src_port":"443",
                    "mapped_src_ip":"203.0.113.11","mapped_src_port":"8443",
                }),
            ):
                with self.subTest(message_id=message_id,direction=direction):
                    raw=(f"<166>Nov 26 2026 09:12:01 fw01 : %ASA-6-{message_id}: Built "
                         f"{direction} {proto} connection 7345 for outside:203.0.113.10/443 "
                         "(203.0.113.11/8443) to inside:10.1.1.5/52044 (198.51.100.7/61012)")
                    event=parse_asa_message(raw)
                    self.assertEqual(event.status,"SOURCE_PARSED")
                    assert_source_accounting(event)
                    for name,value in expected.items():
                        self.assertEqual(event.vendor_fields["asa"][name],value)
                        spans=[s for s in event.value_spans if s.path=="asa."+name]
                        self.assertEqual(len(spans),1)
                        self.assertEqual(raw.encode()[spans[0].start_byte:spans[0].end_byte].decode(),value)

    def test_explicit_deny_roles_do_not_change(self):
        event=parse_asa_message("%ASA-4-106023: Deny tcp src outside:192.0.2.10/54864 dst inside:198.51.100.3/22")
        self.assertEqual(event.vendor_fields["asa"]["src_ip"],"192.0.2.10")
        self.assertEqual(event.vendor_fields["asa"]["dst_ip"],"198.51.100.3")

    def test_deny_access_group_matches_native_grammar(self):
        raw='%ASA-4-106023: Deny tcp src v1:outside:192.0.2.9/40222 dst v2:inside:10.1.1.20/22 by access-group "OUTSIDE_IN" [0x0, 0x0]'
        event=parse_asa_message(raw)
        self.assertEqual(event.status,"SOURCE_PARSED")
        assert_source_accounting(event)
        expected={"src_context":"v1","dst_context":"v2","src_ip":"192.0.2.9",
                  "dst_ip":"10.1.1.20","src_port":"40222","dst_port":"22",
                  "access_group":"OUTSIDE_IN","flag_1":"0x0","flag_2":"0x0"}
        for name,value in expected.items():
            self.assertEqual(event.vendor_fields["asa"][name],value)
            spans=[s for s in event.value_spans if s.path=="asa."+name]
            self.assertEqual(len(spans),1)
            self.assertEqual(raw.encode()[spans[0].start_byte:spans[0].end_byte].decode(),value)

    def test_teardown_does_not_invent_initiator(self):
        event=parse_asa_message("%ASA-6-302014: Teardown TCP connection 9 for outside:192.0.2.10/443 to inside:198.51.100.3/52000 duration 0:00:08 bytes 42 TCP FINs")
        self.assertNotEqual(event.status,"SOURCE_PARSED")
        self.assertNotIn("src_ip",event.vendor_fields["asa"])


if __name__ == "__main__":
    unittest.main()
