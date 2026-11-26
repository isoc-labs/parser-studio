import assert from "node:assert/strict";
import test from "node:test";
import {analyzeRuby24RegexCost} from "../src/ruby24-regex-cost.js";
import {createPortableRegex} from "../src/portable-regex.js";

import {ACCEPTED,ADVERSARIAL_INPUTS} from './ruby24-regex-cost-corpus.js';

/** Each entry must be refused for its documented reason. */
const REJECTED:Array<[string,string]>=[
  [String.raw`(?<digits>\d+)`,"REGEX_POLYNOMIAL_AMBIGUITY"],
  [String.raw`^(?<a>.*),(?<b>.*)$`,"REGEX_POLYNOMIAL_AMBIGUITY"],
  [String.raw`^.*a(?<x>[a-z]+)1$`,"REGEX_POLYNOMIAL_AMBIGUITY"],
  [String.raw`^(?<a>a|ab)(?<b>c|bcd)$`,"REGEX_NONDETERMINISTIC_CHOICE"],
];

test("operator-style anchored patterns are classified as constant-ambiguity",()=>{
  for(const pattern of ACCEPTED){
    const result=analyzeRuby24RegexCost(pattern);
    assert.equal(result.ok,true,pattern+" => "+JSON.stringify(result));
    if(result.ok)assert.equal(result.anchored,true);
  }
});

test("quadratic, exponential and ambiguous-choice patterns are refused with a precise reason",()=>{
  for(const [pattern,reason] of REJECTED){
    const result=analyzeRuby24RegexCost(pattern);
    assert.equal(result.ok,false,pattern);
    if(!result.ok)assert.equal(result.reason,reason,pattern);
  }
});

test("non-portable syntax is refused before any cost analysis",()=>{
  assert.equal(analyzeRuby24RegexCost(String.raw`^(?<a>a+)\1$`).ok,false);
  assert.equal(analyzeRuby24RegexCost(String.raw`^(?<a>\h+)$`).ok,false);
});

test("accepted patterns stay fast on adversarial input under an independent backtracking engine",()=>{
  for(const pattern of ACCEPTED){
    const regex=createPortableRegex(pattern);
    for(const input of ADVERSARIAL_INPUTS){
      const started=process.hrtime.bigint();
      regex.exec(input);
      const millis=Number(process.hrtime.bigint()-started)/1e6;
      assert.ok(millis<250,`${millis.toFixed(1)}ms for ${pattern.slice(0,40)} on ${input.slice(0,12)}`);
    }
  }
});

// The position automaton collapses repeated traversal of one syntactic atom.
// Nested choices must be rejected before that abstraction loses multiplicity.
test("nested repetition cannot obtain a native static cost proof",()=>{
  const patterns=[
    "^(a+)+$", "^(a*)*$", "^([a-z]+)+$", "^(a+){2,}$",
    String.raw`^(\w+\s?)*$`, String.raw`^(\d+)*$`,
    "^(?<value>(?:a+)+)$", "^(?<value>(?:(?:a?)){2,8})$",
    "^(?<value>(?:a|b)+)$", "^(?<value>(?:a{2})+)$",
    "^(?<value>(?:a*){2})$",
  ];
  for(const pattern of patterns){
    const result=analyzeRuby24RegexCost(pattern);
    assert.deepEqual(result,{ok:false,reason:"REGEX_NESTED_REPETITION"},pattern);
  }
});
