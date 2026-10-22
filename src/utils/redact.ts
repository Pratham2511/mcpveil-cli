import { Writable } from "node:stream";
import { StringDecoder } from "node:string_decoder";
import { stripVTControlCharacters } from "node:util";
import { SECRET_PATTERNS } from "../payloads/secretPatterns.js";

const sensitiveKey = /(?:^|[_-])(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|credential)(?:$|[_-])/i;
const registered = new Map<string, number>();
const credentialFlag = /^--?[A-Za-z0-9_-]*(?:password|passwd|secret|token|api[-_]?key|authorization|cookie)[A-Za-z0-9_-]*(?:=|$)/i;

export function commandSecrets(command: string[]): string[] {
  return command.flatMap((argument, index) => {
    if (!credentialFlag.test(argument)) return [];
    const equal = argument.indexOf("=");
    return equal >= 0 ? [argument.slice(equal + 1)] : [command[index + 1] ?? ""];
  });
}

/** Register explicitly supplied credentials for the lifetime of a connection. */
export function registerSecrets(values: string[]): () => void {
  const unique = [...new Set(values.filter((value) => value.length > 0))];
  for (const value of unique) registered.set(value, (registered.get(value) ?? 0) + 1);
  let released = false;
  return () => {
    if (released) return; released = true;
    for (const value of unique) {
      const count = registered.get(value) ?? 0;
      if (count <= 1) registered.delete(value); else registered.set(value, count - 1);
    }
  };
}

/** Detect supplied credentials in a response without exposing their values. */
export function containsSuppliedSecret(text: string): boolean {
  return [...registered.keys()].some((value) => value.length >= 6 && text.includes(value));
}

export function redactText(text: string): string {
  let safe = stripVTControlCharacters(text);
  for (const value of [...registered.keys()].sort((a, b) => b.length - a.length)) {
    safe = safe.split(value).join("[REDACTED]");
  }
  safe = safe.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, "[REDACTED PRIVATE KEY]");
  for (const pattern of SECRET_PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags.replace(/g/g, "") + "g");
    safe = safe.replace(regex, (...args: unknown[]) => {
      const match = String(args[0]);
      const captured = pattern.group ? String(args[pattern.group] ?? match) : match;
      return match.replace(captured, "[REDACTED]");
    });
  }
  safe = safe.replace(/(\b(?:Bearer|Basic)\s+)[^\s"'<>]+/gi, "$1[REDACTED]");
  safe = safe.replace(/("[A-Za-z0-9_-]*(?:password|passwd|secret|token|api[_-]?key|authorization|cookie)[A-Za-z0-9_-]*"\s*:\s*)"(?:\\.|[^"\\])*"/gi, '$1"[REDACTED]"');
  safe = safe.replace(/https?:\/\/[^\s<>"']+/gi, (raw) => {
    try {
      const url = new URL(raw);
      let changed = false;
      if (url.username || url.password) { url.username = "REDACTED"; url.password = ""; changed = true; }
      for (const key of [...url.searchParams.keys()]) {
        if (sensitiveKey.test(key.replace(/([a-z])([A-Z])/g, "$1_$2")) || /signature/i.test(key)) {
          url.searchParams.set(key, "REDACTED"); changed = true;
        }
      }
      return changed ? url.href : raw;
    } catch { return raw; }
  });
  safe = safe.replace(/([?&](?:access_token|api_key|token|password|secret|key)=)[^&#\s]*/gi, "$1[REDACTED]");
  safe = safe.replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi, "$1[REDACTED]@");
  safe = safe.replace(/((?:--?(?:password|passwd|secret|token|api[-_]?key|authorization|cookie)[=:\s]+|\b(?:password|passwd|secret|token|api[-_]?key|authorization|cookie)[=:]\s*))[^\s"']+/gi, "$1[REDACTED]");
  return safe;
}

export function redactValue<T>(value: T): T {
  if (typeof value === "string") return redactText(value) as T;
  if (Array.isArray(value)) return value.map((item) => redactValue(item)) as T;
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [
      key, sensitiveKey.test(key) && typeof item === "string" ? "[REDACTED]" : key === "command" && Array.isArray(item) && item.every((arg) => typeof arg === "string") ? redactCommand(item) : redactValue(item),
    ])) as T;
  }
  return value;
}

export function redactCommand(command: string[]): string[] {
  let hideNext = false;
  return command.map((arg) => {
    if (hideNext) { hideNext = false; return "[REDACTED]"; }
    if (credentialFlag.test(arg)) {
      const equal = arg.indexOf("=");
      if (equal >= 0) return arg.slice(0, equal + 1) + "[REDACTED]";
      hideNext = true;
    }
    return redactText(arg);
  });
}

/** Line buffering prevents a token split across stderr chunks from bypassing masking. */
export function redactingStream(write: (text: string) => void): Writable {
  const decoder = new StringDecoder("utf8");
  let pending = "";
  let privateKey = false;
  const emit = (line: string) => {
    if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(line)) privateKey = true;
    if (privateKey) {
      if (/-----END [A-Z ]*PRIVATE KEY-----/.test(line)) privateKey = false;
      write("[REDACTED PRIVATE KEY]\n");
    } else write(redactText(line));
  };
  return new Writable({
    write(chunk: Buffer, _encoding, done) {
      pending += decoder.write(chunk);
      let end: number;
      while ((end = pending.indexOf("\n")) >= 0) {
        emit(pending.slice(0, end + 1)); pending = pending.slice(end + 1);
      }
      if (pending.length > 16384) { pending = ""; write("[REDACTED oversized target output]\n"); }
      done();
    },
    final(done) { pending += decoder.end(); if (pending) emit(pending); done(); },
  });
}
