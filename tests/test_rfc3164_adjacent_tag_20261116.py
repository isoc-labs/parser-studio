"""An RFC 3164 tag directly followed by the message (`ASM:unit_hostname="..."`).

F5 BIG-IP ASM sends its key-value log this way. The browser envelope (src/syslogEnvelope.ts) reads a tag followed
by zero or more blanks and the whole record; the preview asked for a blank after the colon, read four fields, and
the record was blocked on the Add Logs step because the two readings disagreed.
"""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime/multipass'))
from multipass_preview_api import preview
from structured_source import extract_rfc3164

BODY=('unit_hostname="bigip-4.pme-ds.f5.com",management_ip_address="172.16.73.34",'
      'http_class_name="/Common/topaz4-web4",policy_name="topaz4-web4",request_status="passed",'
      'response_code="200",ip_client="10.4.1.101",method="GET",protocol="HTTP",severity="Informational"')
HEAD='<134>Sep 19 13:40:27 bigip-4.pme-ds.f5.com ASM:'
EXPECTED={'unit_hostname':'bigip-4.pme-ds.f5.com','management_ip_address':'172.16.73.34',
          'http_class_name':'/Common/topaz4-web4','policy_name':'topaz4-web4','request_status':'passed',
          'response_code':'200','ip_client':'10.4.1.101','method':'GET','protocol':'HTTP',
          'severity':'Informational'}


class Rfc3164AdjacentTag(unittest.TestCase):
    def test_every_field_is_read_with_and_without_a_blank_after_the_tag(self):
        for raw in (HEAD+BODY,HEAD+' '+BODY):
            result=preview(raw)
            self.assertEqual(result['status'],'SOURCE_PARSED',raw[:60])
            self.assertEqual(result['issues'],[])
            self.assertEqual(result['fields']['generic']['fields'],EXPECTED)
            self.assertEqual(result['fields']['syslog']['tag'],'ASM')
            self.assertEqual(result['fields']['syslog']['host'],'bigip-4.pme-ds.f5.com')

    def test_the_adjacent_frame_is_narrow(self):
        self.assertIsNone(extract_rfc3164(HEAD+BODY))
        self.assertIsNotNone(extract_rfc3164(HEAD+BODY,adjacent=True))
        # A blank after the colon is the ordinary frame, not the adjacent one.
        self.assertIsNone(extract_rfc3164(HEAD+' '+BODY,adjacent=True))
        # CEF and LEEF are message families, never a tag.
        self.assertIsNone(extract_rfc3164('<134>Sep 19 13:40:27 host CEF:0|V|P|1|1|n|5|src=10.1.1.1',adjacent=True))
        self.assertIsNone(extract_rfc3164('<134>Sep 19 13:40:27 host LEEF:1.0|V|P|1|1|src=10.1.1.1',adjacent=True))

    def test_text_that_is_not_a_record_is_not_reported_as_parsed(self):
        for raw in ('<134>Sep 19 13:40:27 host http://example.com/a?x=1,b=2,c=3,d=4,e=5',
                    '<38>Nov 16 10:15:04 web01 sshd:Failed password for root from 203.0.113.5 port 22 ssh2'):
            self.assertNotEqual(preview(raw)['status'],'SOURCE_PARSED',raw)

    def test_cef_behind_an_adjacent_tag_is_still_read_as_cef(self):
        raw=HEAD+'CEF:0|F5|ASM|11.3.0|Successful Request|Successful Request|2| act=passed src=10.4.1.101 spt=52963 dst=10.4.1.200 dpt=80'
        result=preview(raw)
        self.assertEqual(result['status'],'SOURCE_PARSED')
        self.assertIn('CEF',result['syntax'])


if __name__=='__main__':
    unittest.main()
