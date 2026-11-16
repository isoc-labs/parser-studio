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
# The example of the F5 documentation (BIG-IP ASM, remote logging, key-value pairs), complete.
F5_DOCUMENTED=('<134>Sep 19 13:40:27 bigip-4.pme-ds.f5.com ASM:unit_hostname="bigip-4.pme-ds.f5.com", management'
              '_ip_address="172.16.73.34",http_class_name="/Common/topaz4-web4", policy_name="topaz4-web4",poli'
              'cy_apply_date="2012-09-19 11:38:36", violations="",support_id="18205860747014045701",request_sta'
              'tus="passed", response_code="200",ip_client="10.4.1.101",route_domain="0",method="GET",protocol='
              '"HTTP",query_string="",x_forwarded_for_header_value="N/A", sig_ids="",sig_names="",date_time="20'
              '12-09-19 13:40:27",severity="Informational",attack_type="",geo_location="N/A",ip_address_intelli'
              'gence="N/A",username="N/A",session_id="3c4ecb8d6ed32d1e",src_port="52974",dest_port="80",dest_ip'
              '="10.4.1.200",sub_violations="",virus_name="N/A",uri="/",request="GET / HTTP/1.0\\r\\nUser-Agent: '
              'Wget/1.12 (linux-gnu)\\r\\nAccept: */*\\r\\nHost: 10.4.1.200\\r\\nConnection: Keep-Alive\\r\\n\\r\\n"')
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

    def test_only_the_complete_comma_record_is_taken_and_nothing_else_changes_its_verdict(self):
        """Found by the independent audit of the first version: skipping the RFC 3164 guard for every adjacent tag
        let later fallbacks read the line from the PRI again, with the tag glued to the first pair
        (`app:srcip=10.0.0.1` as one positional token and no srcip field), and reported it as parsed."""
        head='<134>Nov 16 10:15:04 fw01 '
        not_this_form=(
            # space-separated pairs, one of them empty: the adjacent route declines, no fallback may take the line
            head+'app:srcip=10.0.0.1 dstip= srcport=1 dstport=2 action=allow user=bob',
            head+'kernel:IN=eth0 OUT= MAC=aa:bb SRC=1.2.3.4 DST=5.6.7.8 LEN=60 TOS=0x00 PROTO=TCP SPT=1 DPT=2',
            # not a tag at all
            head+'fe80::1 a=1 b=2 c=3 d=4 e=5',
            head+'http://x/a b=1 c=2 d=3 e=4 f=5',
            head+'ratio:1:2 a=1 b=2 c=3 d=4 e=5',
            # a message that claims CEF or LEEF and is not one the grammar reads
            head+'app:CEF:1|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232 dpt=80',
            head+'app:CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|src=10.0.0.1 dst=2.1.2.2',
            head+'app:LEEF:3.0|Acme Corp|Gateway|1|event|src=10.0.0.1 dst=2.1.2.2 srcPort=1 dstPort=2',
            # a repeated name (owner policy D-1)
            head+'ASM:ip_client="10.4.1.101",ip_client="10.9.9.9",management_ip_address="1.2.3.4",policy_name="p",request_status="passed",unit_hostname="h"',
            # text between the tag and the first name
            head+'app:Oct 23 00:14:27 bigip-waf01 ASM: unit_hostname="bigip-waf01",management_ip_address="192.0.2.1",policy_name="p",request_status="passed"',
            head+'http://ASM: attack_type="SQL Injection",support_id="12345",src=192.0.2.9,dst=198.51.100.40,request="/index.php",action="blocked"',
        )
        for raw in not_this_form:
            result=preview(raw)
            self.assertNotEqual(result['status'],'SOURCE_PARSED',raw)
            self.assertNotIn('prefix_tokens',str(result.get('fields',{}).get('generic',{})),raw)

    def test_only_double_quoted_pairs_with_plain_names_are_the_adjacent_record(self):
        """Found by the second independent audit. The route also took names with blanks and values without double
        quotes: `myapp:Login failed user=bob,...` came back as parsed with a field named "Login failed user", and
        two apostrophes in unquoted values swallowed the pairs between them into one value."""
        head='<134>Nov 16 10:15:04 web01 '
        not_this_form=(
            head+'myapp:Login failed user=bob,src=203.0.113.5,dst=10.1.1.9,port=22,proto=tcp,reason=badpass',
            head+'myapp:Login failed user="bob",src="203.0.113.5",dst="10.1.1.9",port="22",proto="tcp"',
            head+"portal:user=o'brien,src=203.0.113.5,dept=o'neil,dst=10.1.1.9,port=443,result=ok,proto=tcp,site=hq",
            head+"portal:user='bob',src='203.0.113.5',dst='10.1.1.9',port='443',result='ok'",
            head+'portal:user=bob,src=203.0.113.5,dst=10.1.1.9,port=443,result=ok',
            head+'portal:user="bob",src=203.0.113.5,dst="10.1.1.9",port="443",result="ok"',
            head+'portal:bytes(in)="10",sig#="7",user="bob",src="203.0.113.5",dst="10.1.1.9"',
            head+'portal:user="bo\\"b",src="203.0.113.5",dst="10.1.1.9",port="443",result="ok"',
            head+'portal:user="bob" ,src="203.0.113.5" ,dst="10.1.1.9" ,port="443" ,result="ok"',
            head+'portal:user="bob",\tsrc="203.0.113.5",\tdst="10.1.1.9",\tport="443",\tresult="ok"',
            head+'portal:user="bob" src="203.0.113.5" dst="10.1.1.9" port="443" result="ok"',
            head+'portal:user="bob",src="203.0.113.5",dst="10.1.1.9",port="443",result="ok",',
            head+'portal:user="bob",src="203.0.113.5",dst="10.1.1.9",port="443",result="ok" trailing words',
            head+'portal:user="bob"',
            # a name every JavaScript object has: the browser reading does not hold it as a plain field
            head+'portal:toString="x",src="203.0.113.5",dst="10.1.1.9",port="443",result="ok"',
            head+'portal:user="bob",constructor="203.0.113.5",dst="10.1.1.9",port="443",result="ok"',
            head+'portal:user="bob",src="203.0.113.5",dst="10.1.1.9",port="443",hasOwnProperty="ok"',
            head+'portal:__proto__="bob",src="203.0.113.5",dst="10.1.1.9",port="443",valueOf="ok"',
            # a blank around the equals sign
            head+'portal:user ="bob",src ="203.0.113.5",dst ="10.1.1.9",port ="443",result ="ok"',
            head+'portal:user= "bob",src= "203.0.113.5",dst= "10.1.1.9",port= "443",result= "ok"',
            # a backslash directly before a quote, in the middle of a value and at its end
            head+'portal:user="bo\\"b",src="203.0.113.5",dst="10.1.1.9",port="443",result="ok"',
            head+'portal:path="C:\\",src="203.0.113.5",dst="10.1.1.9",port="443",result="ok"',
            head+'portal:path="C:\\\\",src="203.0.113.5",dst="10.1.1.9",port="443",result="ok"',
        )
        for raw in not_this_form:
            # Whatever an older route makes of the line (some read it as one pair), it is not this record.
            result=preview(raw)
            self.assertNotIn('GENERIC_RFC3164_BODY',result.get('syntax') or '',raw)
            names=list((result.get('fields',{}).get('generic') or {}).get('fields',{}))
            self.assertEqual([name for name in names if ' ' in name],[],raw)
        # The record as the F5 documentation prints it: some pairs follow the comma after a blank.
        documented=('<134>Sep 19 13:40:27 bigip-4.pme-ds.f5.com ASM:unit_hostname="bigip-4.pme-ds.f5.com", '
                    'management_ip_address="172.16.73.34",http_class_name="/Common/topaz4-web4", '
                    'policy_name="topaz4-web4",policy_apply_date="2012-09-19 11:38:36", violations="",'
                    'support_id="18205860747014045701",request_status="passed", response_code="200",'
                    'ip_client="10.4.1.101",x_forwarded_for_header_value="N/A", sig_ids=""')
        result=preview(documented)
        self.assertEqual(result['status'],'SOURCE_PARSED')
        self.assertEqual(result['syntax'],'GENERIC_RFC3164_BODY+COMMA_KV')
        self.assertEqual(result['fields']['generic']['fields'],{
            'unit_hostname':'bigip-4.pme-ds.f5.com','management_ip_address':'172.16.73.34',
            'http_class_name':'/Common/topaz4-web4','policy_name':'topaz4-web4',
            'policy_apply_date':'2012-09-19 11:38:36','violations':'','support_id':'18205860747014045701',
            'request_status':'passed','response_code':'200','ip_client':'10.4.1.101',
            'x_forwarded_for_header_value':'N/A','sig_ids':''})
        # The whole record of the F5 documentation. F5 writes the line breaks of the request as backslash r backslash n
        # (found by the third audit pass: the value class excluded every backslash and the record was declined).
        result=preview(F5_DOCUMENTED)
        self.assertEqual(result['status'],'SOURCE_PARSED')
        self.assertEqual(result['syntax'],'GENERIC_RFC3164_BODY+COMMA_KV')
        fields=result['fields']['generic']['fields']
        self.assertEqual(len(fields),31)
        self.assertEqual(fields['request'],'GET / HTTP/1.0\\r\\nUser-Agent: Wget/1.12 (linux-gnu)\\r\\nAccept: */*'
                         '\\r\\nHost: 10.4.1.200\\r\\nConnection: Keep-Alive\\r\\n\\r\\n')
        self.assertEqual((fields['src_port'],fields['dest_port'],fields['dest_ip'],fields['uri'],fields['geo_location']),
                         ('52974','80','10.4.1.200','/','N/A'))
        # The form itself, with an empty value and a comma, an equals sign and an apostrophe inside the quotes.
        raw=head+'portal:user="o\'brien",note="a,b=c",empty="",src="203.0.113.5",dst="10.1.1.9"'
        result=preview(raw)
        self.assertEqual(result['status'],'SOURCE_PARSED')
        self.assertEqual(result['syntax'],'GENERIC_RFC3164_BODY+COMMA_KV')
        self.assertEqual(result['fields']['generic']['fields'],
                         {'user':"o'brien",'note':'a,b=c','empty':'','src':'203.0.113.5','dst':'10.1.1.9'})

    def test_cef_behind_an_adjacent_tag_is_still_read_as_cef(self):
        raw=HEAD+'CEF:0|F5|ASM|11.3.0|Successful Request|Successful Request|2| act=passed src=10.4.1.101 spt=52963 dst=10.4.1.200 dpt=80'
        result=preview(raw)
        self.assertEqual(result['status'],'SOURCE_PARSED')
        self.assertIn('CEF',result['syntax'])


if __name__=='__main__':
    unittest.main()
