"""Deterministic Python Multi-Pass conformance from the shared fixture corpus."""
import json
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime"/"multipass"))
from multipass_preview_api import preview
from stellar_dictionary import _POLICY

CASES=json.loads((ROOT/"contracts"/"conformance-cases.v1.json").read_text())
POLICY=json.loads((ROOT/"runtime"/"multipass"/"semantic-policy.v1.json").read_text())

class SharedSemanticConformance(unittest.TestCase):
    def test_canonical_versioned_policy(self):
        self.assertEqual("parser-studio.cross-engine-corpus.v1",CASES["contract"])
        self.assertEqual("independently-authored-synthetic",CASES["origin"])
        self.assertEqual(_POLICY,POLICY)
        self.assertEqual([6,17],POLICY["transportPortProtocols"]["numeric"])

    def test_protocol_evidence_does_not_map_false_official_ports(self):
        for item in CASES["portEvidence"]:
            with self.subTest(id=item["id"]):
                field="proto" if "proto" in item else "proto_name"
                raw=f'{field}={item[field]} srcport=594 dstport=10400 srcip=192.0.2.1'
                result=preview(raw)
                mapped={m["targetField"] for m in result["dictionary"]["mapped"]}
                if item["allow"]:
                    self.assertTrue({"srcport","dstport"}.issubset(mapped),item["id"])
                else:
                    self.assertTrue({"srcport","dstport"}.isdisjoint(mapped),item["id"])
                self.assertEqual("SOURCE_PARSED",result["status"])
                self.assertEqual("594",str(result["fields"]["srcport"]))

    def test_a_field_is_official_from_its_name_only_when_the_policy_lists_it(self):
        # Same corpus and same answers as the browser (src/conformanceCorpus20261107.test.ts). An entry marked
        # "preview": false is a listed field this preview cannot coerce: the preview stays silent, never the reverse.
        from stellar_dictionary import FIELDS
        self.assertLessEqual(set(FIELDS),set(POLICY["autoApprovedTargets"]))
        self.assertFalse(set(FIELDS)&set(POLICY["autoApprovalDeclined"]))
        for item in CASES["defaultDeny"]:
            with self.subTest(id=item["id"]):
                field=item["field"]
                result=preview(f'{field}={item["value"]} srcip=192.0.2.1')
                mapped={m["targetField"] for m in result["dictionary"]["mapped"]}
                expected=item["allow"] and item.get("preview",True)
                self.assertEqual(expected,field in mapped,item["id"])
                if item["allow"]:
                    self.assertIn(field,POLICY["autoApprovedTargets"],item["id"])
                else:
                    self.assertNotIn(field,mapped,item["id"])
                self.assertIn("srcip",mapped)
                self.assertEqual("SOURCE_PARSED",result["status"])
                self.assertEqual(item["value"],str(result["fields"][field]))

    def test_a_member_of_an_object_of_the_record_is_not_a_field_of_the_record(self):
        # Same corpus and same answers as the browser: a name inside an object of a JSON log names that object.
        for item in CASES["memberOfObject"]:
            with self.subTest(id=item["id"]):
                result=preview(json.dumps(item["record"]))
                mapped={m["sourcePath"]:m["targetField"] for m in result["dictionary"]["mapped"]}
                self.assertEqual("SOURCE_PARSED",result["status"])
                self.assertNotIn(item["path"],mapped,item["id"])
                self.assertEqual({"dstip":"dstip"},mapped,item["id"])

    def test_an_sd_param_is_read_for_the_explicit_port_labels_only(self):
        # The browser accepts an EXACT_DICTIONARY_NAME projection at the root or in the body only
        # (src/guided/multipassPreviewClient.ts); a listed name among the SD-PARAMs is left to the browser proposals.
        raw=('<14>1 2019-11-14T11:12:46.573+01:00 SRX-GW1 RT_FLOW - RT_FLOW_SESSION_CREATE '
             '[junos@67.43.156.15 source-port="37233" destination-port="161" username="alice" action="deny"]')
        result=preview(raw)
        self.assertEqual("SOURCE_PARSED",result["status"])
        self.assertEqual({"srcport":"EXPLICIT_SOURCE_ALIAS","dstport":"EXPLICIT_SOURCE_ALIAS"},
                         {m["targetField"]:m["mappingClass"] for m in result["dictionary"]["mapped"]})

    def test_versioned_named_source_aliases_are_cross_engine_and_value_guarded(self):
        self.assertEqual({'source-port':'srcport','destination-port':'dstport'},
                         POLICY['explicitPortSourceAliases'])
        for case in CASES['explicitPortAliasEvidence']:
            with self.subTest(case=case['id']):
                raw=(f'proto={case["proto"]} source-port={case["sourcePort"]} '
                     f'destination-port={case["destinationPort"]} srcip=192.0.2.1')
                result=preview(raw)
                mapped={item['targetField']:item for item in result['dictionary']['mapped']}
                self.assertEqual('SOURCE_PARSED',result['status'])
                self.assertEqual(case['sourcePort'],str(result['fields']['source-port']))
                self.assertEqual(case['destinationPort'],str(result['fields']['destination-port']))
                for key,source in [('srcport','source-port'),('dstport','destination-port')]:
                    if case[key] is None:
                        self.assertNotIn(key,mapped)
                    else:
                        self.assertEqual(source,mapped[key]['sourcePath'])
                        self.assertEqual('EXPLICIT_SOURCE_ALIAS',mapped[key]['mappingClass'])
                        self.assertEqual('integer',mapped[key]['documentedType'])
        nat=preview('proto=1 nat-source-port=594 srcip=192.0.2.1')
        self.assertNotIn('srcport',
            {item['targetField'] for item in nat['dictionary']['mapped']})
        for source in ['nat.source-port','translated.destination-port']:
            nested=preview(f'proto=6 {source}=594 srcip=192.0.2.1')
            self.assertFalse({'srcport','dstport'}.intersection(
                {item['targetField'] for item in nested['dictionary']['mapped']}),source)


    def test_unknown_proto_name_preserved_but_not_official(self):
        for value in ["unknown","https","gre","ospf","icmpv6"]:
            with self.subTest(name=value):
                result=preview(f"proto_name={value} srcip=192.0.2.1")
                mapped={m["targetField"] for m in result["dictionary"]["mapped"]}
                self.assertNotIn("proto_name",mapped)
                self.assertIn("DICTIONARY_PROTOCOL_NAME_UNSUPPORTED:proto_name",
                              result["dictionary"]["issues"])
                self.assertEqual(value,result["fields"]["proto_name"])
        for value in POLICY["officialProtocolNames"]:
            result=preview(f"proto_name={value} srcip=192.0.2.1")
            self.assertIn("proto_name",{m["targetField"] for m in result["dictionary"]["mapped"]})

    def test_preview_package_contains_canonical_policy(self):
        package_script=(ROOT/"ops"/"preview-domain"/"prepare-private-preview.sh").read_text()
        self.assertIn(
            'cp runtime/multipass/semantic-policy.v1.json "$STAGE/multipass/"',
            package_script,
        )
        self.assertEqual("parser-studio.semantic-policy.v1",_POLICY["contract"])

    def test_fixed_seed_protocol_mutations(self):
        seed=0x512042
        illegal=[1,2,47,50,58,89,132,253]
        for index in range(128):
            seed=(seed*1664525+1013904223)&0xffffffff
            proto=illegal[seed%len(illegal)]
            seed=(seed*1664525+1013904223)&0xffffffff
            port=1+seed%65535
            result=preview(f"proto={proto} srcport={port} dstport=443")
            mapped={m["targetField"] for m in result["dictionary"]["mapped"]}
            self.assertNotIn("srcport",mapped,(index,proto))
            self.assertNotIn("dstport",mapped,(index,proto))

if __name__=="__main__":
    unittest.main()
