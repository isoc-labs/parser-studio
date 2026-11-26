const ftd=String.raw`^.*%FTD-\d-(?<event_id>\d+): Built inbound (?<protocol>TCP|UDP) connection \d+ for \w+:(?<srcip>[\d.]+)/(?<srcport>\d+) \([\d.]+/\d+\) to \w+:(?<dstip>[\d.]+)/(?<dstport>\d+) \([\d.]+/\d+\)$`;

/** Patterns a real operator writes: anchored, delimiter-separated, one scan loop. */
export const ACCEPTED=[
  ftd,
  String.raw`^(?<ts>\w+ \d+ [\d:]+) (?<host>\S+) (?<proc>[\w-]+)\[(?<pid>\d+)\]: (?<msg>.*)$`,
  String.raw`^src=(?<src>[\d.]+) dst=(?<dst>[\d.]+) proto=(?<proto>\w+)$`,
  String.raw`^(?<action>ACCEPT|DENY),(?<srcip>\d+\.\d+\.\d+\.\d+),(?<port>\d{1,5})$`,
  String.raw`^(?<a>[^,]*),(?<b>[^,]*),(?<c>[^,]*)$`,
];


/** Maximum-size synthetic counterexamples, independent of parser output. */
export const ADVERSARIAL_INPUTS=[
  "a".repeat(4096), "1".repeat(4096), ",".repeat(4096),
  "a=1 ".repeat(1024), "x ".repeat(2048), "1.".repeat(2048),
  "%FTD-6-1: Built inbound TCP connection 1 for a:1.1/1 ".repeat(80).slice(0,4096),
  "1".repeat(4095)+"!", "a".repeat(4095)+"!", "é".repeat(2047)+"!"
];
