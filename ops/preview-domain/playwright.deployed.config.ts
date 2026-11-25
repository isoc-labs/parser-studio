import {defineConfig,devices} from '@playwright/test';

// Browser check of the DEPLOYED Development Preview (UPDATE_RUNBOOK.md; run by `release.sh <sha> verify`).
// Chromium opens the public site: there is no local web server, backend or engine, and no route is mocked by this
// configuration. The journeys are the committed ones that already run against a real backend and engine, plus the
// first-user journey written for the deployed site. Replies "from ChatGPT" in these journeys are written by the
// tests themselves: they exercise the paste-and-apply route and say nothing about the quality of a real reply.
const url=process.env.PARSER_STUDIO_DEPLOYED_URL||'https://app.parser.isoc.ooo';
const out=process.env.PARSER_STUDIO_DEPLOYED_OUT||'test-results/deployed-preview';
// The journeys below skip themselves unless they are told that the backend and the engine are real.
process.env.PARSER_STUDIO_LIVE_BACKEND='1';
process.env.PARSER_STUDIO_TEST_MULTIPASS='1';
// Each journey writes its downloaded parser and the lines to run it on below <out>/<case>/ (Ruby 2.4.9 input).
for(const name of ['D2_PRI_OUT','G5_OUT','KV_BARE_OUT','CHATGPT_KEY_OUT','MAP_TYPES_OUT','READABLE_GATE_OUT'])
  process.env[name]=out;
process.env.H2_CHATGPT_OUT=out+'/h2_residuals';
process.env.PARSER_STUDIO_DEPLOYED_OUT=out;
process.env.PARSER_STUDIO_E2E_ARTIFACT_DIR=out+'/downloads';

export default defineConfig({
  testDir:'../../tests',
  testMatch:[
    '**/deployed-preview-journey.deployed.ts',
    '**/d2-pri-cef-journey-20261125.spec.ts',
    '**/g5-reserved-names-journey-20261125.spec.ts',
    '**/readable-events-gate-20261125.spec.ts',
    '**/kv-bare-token-verdict-20261125.spec.ts',
    '**/chatgpt-key-outside-region-20261125.spec.ts',
    '**/chatgpt-h2-residuals-20261125.spec.ts',
    '**/map-fields-event-types-20261125.spec.ts',
    '**/map-fields-event-type-manual-20261125.spec.ts',
    '**/chatgpt-jsonata-event-profile-20261123.spec.ts',
  ],
  outputDir:out+'/test-results',
  retries:0,
  workers:1,
  reporter:'list',
  timeout:300_000,
  use:{baseURL:url,trace:'retain-on-failure',screenshot:'only-on-failure',viewport:{width:1440,height:900}},
  projects:[{name:'chromium',use:{...devices['Desktop Chrome'],viewport:{width:1440,height:900}}}],
});
