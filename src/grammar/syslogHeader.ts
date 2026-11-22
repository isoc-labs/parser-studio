/**
 * Contract-driven Syslog header matcher.
 *
 * Every regular expression, capture name and numeric limit used here comes from
 * the code generated out of contracts/syslog-header-grammar.v1.json. This module
 * adds only the semantic checks the contract declares (PRI range, calendar,
 * supported RFC 5424 VERSION). Do not add a hand-written header pattern here or
 * anywhere else: change the contract and regenerate.
 */
import {
  GRAMMAR_FRAGMENTS,
  SYSLOG_HEADER_ALTERNATIVES,
  SYSLOG_HEADER_RULES,
  SYSLOG_HEADER_SEMANTICS,
  SYSLOG_HEADER_TOKENS,
  type SyslogHeaderRuleName,
} from './syslogHeaderGrammar.generated';

import { matchAt } from './primitives';

export type HeaderCaptures = Readonly<Record<string, string | undefined>>;

// Every contract rule and token, compiled once. The generated Ruby holds the same table.
const COMPILED_RULES: Readonly<Record<string, RegExp>> = Object.fromEntries(
  Object.entries(SYSLOG_HEADER_RULES).map(([name, rule]) => [name, new RegExp(rule.source,'u')]));

/** Whole-line match of one contract rule; captures are returned by contract name. */
export function matchHeaderRule(rule: SyslogHeaderRuleName, text: string): HeaderCaptures | null {
  const match = COMPILED_RULES[rule]!.exec(text);
  if (!match) return null;
  const captures: Record<string, string | undefined> = {};
  for (const name of SYSLOG_HEADER_RULES[rule].captures) captures[name] = match.groups?.[name];
  return captures;
}

const COMPILED_TOKENS: Readonly<Record<string, RegExp>> = Object.fromEntries(
  Object.entries(SYSLOG_HEADER_TOKENS).map(([name, source]) => [name, new RegExp('^(?:' + source + ')$','u')]));

/** True when the whole text is one contract token (for example a STRUCTURED_BODY). */
export function matchesHeaderToken(token: keyof typeof SYSLOG_HEADER_TOKENS, text: string): boolean {
  return COMPILED_TOKENS[token]!.test(text);
}

export type Rfc3164Rule = (typeof SYSLOG_HEADER_ALTERNATIVES.rfc3164)[number];
export type Rfc3164HeaderFailure = 'NO_MATCH' | 'PRI_OUT_OF_RANGE' | 'CALENDAR_INVALID';
export type Rfc3164Header =
  | {
      ok: true;
      rule: Rfc3164Rule;
      pri?: number;
      /** Normalized "Mmm dd hh:mm:ss" with a space-padded day, as RFC 3164 writes it. */
      timestamp: string;
      hostname?: string;
      tag?: string;
      procid?: string;
      message: string;
    }
  | { ok: false; reason: Rfc3164HeaderFailure };

/**
 * Ordered alternatives of the RFC 3164 header: the tagged rule is tried before
 * the tagless rule because every tagged line is also a tagless one. A relay or a log file
 * drops the PRI; the tagged rule reads such a record as well ("Nov 21 10:00:03 fw1 traffic: srcip=..."). The hostless
 * rule is disjoint from both by construction: BSD_HOSTNAME cannot contain '=' or
 * open a structured body, so a line without HOSTNAME never donates its first
 * field to the header.
 */
export function matchRfc3164Header(text: string): Rfc3164Header {
  for (const rule of SYSLOG_HEADER_ALTERNATIVES.rfc3164) {
    const captures = matchHeaderRule(rule, text);
    if (!captures) continue;
    // Without a PRI a tagged line is a Syslog record only before a structured body - the bound of every
    // PRI-less form. "Nov 21 10:00:03 the service restarted: see the log" is free text behind a time stamp;
    // it is left to the next alternatives, as it was while this rule required the PRI.
    if (rule === 'rfc3164_tagged' && captures.pri === undefined &&
        !matchesHeaderToken('STRUCTURED_BODY', captures.message!)) continue;
    const pri = captures.pri === undefined ? undefined : Number(captures.pri);
    if (pri !== undefined && pri > SYSLOG_HEADER_SEMANTICS.priMax) return { ok: false, reason: 'PRI_OUT_OF_RANGE' };
    const month = captures.month!;
    const day = Number(captures.day);
    const days = (SYSLOG_HEADER_SEMANTICS.bsdMonthDays as Record<string, number>)[month];
    if (!days || day < 1 || day > days || Number(captures.hour) > 23 ||
        Number(captures.minute) > 59 || Number(captures.second) > 59) return { ok: false, reason: 'CALENDAR_INVALID' };
    return {
      ok: true,
      rule,
      ...(pri === undefined ? {} : { pri }),
      timestamp: `${month} ${String(day).padStart(2, ' ')} ${captures.hour}:${captures.minute}:${captures.second}`,
      ...(captures.hostname === undefined ? {} : { hostname: captures.hostname }),
      ...(captures.tag === undefined ? {} : { tag: captures.tag }),
      ...(captures.procid === undefined ? {} : { procid: captures.procid }),
      message: captures.message!,
    };
  }
  return { ok: false, reason: 'NO_MATCH' };
}

export type Rfc5424HeaderFailure = 'NO_MATCH' | 'PRI_OUT_OF_RANGE' | 'VERSION_UNSUPPORTED';
export type Rfc5424Header =
  | {
      ok: true;
      pri: number;
      version: string;
      timestamp: string;
      hostname: string;
      appname: string;
      procid: string;
      msgid: string;
      /** STRUCTURED-DATA and the optional MSG, still unparsed. */
      rest: string;
    }
  | { ok: false; reason: Rfc5424HeaderFailure };

/** One policy for every consumer: only the VERSION values the contract lists are parsed. */
export function isSupportedRfc5424Version(version: string): boolean {
  return (SYSLOG_HEADER_SEMANTICS.rfc5424SupportedVersions as readonly string[]).includes(version);
}

const VERSION_HEAD = new RegExp(GRAMMAR_FRAGMENTS.rfc5424_version_head.source, 'yu');

/**
 * VERSION of a line that claims to be RFC 5424 (<PRI>VERSION SP, then NILVALUE
 * or an RFC 3339 date) with a VERSION the contract does not support; null for
 * every other line. Owner policy: such a line is never parsed by any grammar,
 * its original text is kept and it is reported as unsupported.
 */
export function unsupportedRfc5424Version(text: string): string | null {
  const match = matchAt(VERSION_HEAD, text, 0);
  if (!match) return null;
  const version = match.groups!.version!;
  return isSupportedRfc5424Version(version) ? null : version;
}

export function matchRfc5424Header(text: string): Rfc5424Header {
  const captures = matchHeaderRule('rfc5424', text);
  if (!captures) return { ok: false, reason: 'NO_MATCH' };
  const pri = Number(captures.pri);
  if (pri > SYSLOG_HEADER_SEMANTICS.priMax) return { ok: false, reason: 'PRI_OUT_OF_RANGE' };
  if (!isSupportedRfc5424Version(captures.version!)) return { ok: false, reason: 'VERSION_UNSUPPORTED' };
  return {
    ok: true,
    pri,
    version: captures.version!,
    timestamp: captures.timestamp!,
    hostname: captures.hostname!,
    appname: captures.appname!,
    procid: captures.procid!,
    msgid: captures.msgid!,
    rest: captures.rest!,
  };
}
