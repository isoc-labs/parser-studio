import json, sys, unittest
sys.dont_write_bytecode = True
sys.path.insert(0, 'runtime/multipass')
import multipass_preview_api as api

# The Python preview names PAN-OS THREAT and SYSTEM records with the tables of the browser grammar.
TRAFFIC = "Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51514,443,62001,443,0x400053,tcp,allow,1840,1200,640,12,2026/10/15 00:03:01,20,any,0,987654321,0x0,10.0.0.0-10.255.255.255,United States,0,7,5,aged-out,0,0,0,0,vsys1,PA-FW01,from-policy"
THREAT = "Oct 15 00:03:25 PA-FW01 1,2026/10/15 00:03:25,012345678901,THREAT,url,2561,2026/10/15 00:03:25,10.10.20.15,203.0.113.50,203.0.113.10,203.0.113.50,allow-web,,,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:25,123457,1,51520,80,62002,80,0x408000,tcp,alert,\"example.com/index.html\",(9999),computer-and-internet-info,informational,client-to-server,987654322,0x0,10.0.0.0-10.255.255.255,United States,0,text/html"
SYSTEM = "Oct 15 00:05:00 PA-FW01 1,2026/10/15 00:05:00,012345678901,SYSTEM,general,0,2026/10/15 00:05:00,,general,,0,0,general,informational,\"User admin logged in via Web from 10.1.1.5 using https\",12345,0x0,0,0,0,0,,PA-FW01"


class PanosNamedRecordsTest(unittest.TestCase):
    def syntax(self, lines):
        return [e['preview'].get('syntax', '') for e in api.preview_batch('\n'.join(lines))['events']]

    def test_mixed_record_types_are_named(self):
        self.assertEqual(self.syntax([TRAFFIC, THREAT, SYSTEM]), [
            'SECURITY_SYSLOG_ENVELOPE+PANOS_TRAFFIC_CSV',
            'SECURITY_SYSLOG_ENVELOPE+PANOS_THREAT_CSV',
            'SECURITY_SYSLOG_ENVELOPE+PANOS_SYSTEM_CSV',
        ])

    def test_broken_invariant_stays_positional(self):
        self.assertEqual(self.syntax([THREAT.replace(',informational,', ',loud,')]),
                         ['SECURITY_SYSLOG_ENVELOPE+GENERIC_POSITIONAL_CSV'])

    def test_non_ascii_digits_are_not_ports(self):
        # Audit F2: str.isdigit() accepts superscript and Arabic-Indic digits; the browser and Ruby grammars
        # accept [0-9] only. Such a port must neither crash the preview nor name the record.
        for digit in ('\u00b2', '\u0665\u0661'):
            line = THREAT.replace(',51520,80,', ',' + digit + ',80,')
            self.assertEqual(self.syntax([line]), ['SECURITY_SYSLOG_ENVELOPE+GENERIC_POSITIONAL_CSV'])
            traffic = TRAFFIC.replace(',51514,443,', ',' + digit + ',443,')
            self.assertNotEqual(self.syntax([traffic]), ['SECURITY_SYSLOG_ENVELOPE+PANOS_TRAFFIC_CSV'])


if __name__ == '__main__':
    unittest.main()
