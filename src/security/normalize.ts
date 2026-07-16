/**
 * Evasion normalization: produce alternative "views" of a text so that heuristic rules survive the
 * common tricks used to hide a payload from an ASCII pattern matcher —
 *
 *   - **Unicode compatibility** (fullwidth / stylized forms) — folded with NFKC;
 *   - **homoglyphs** (Cyrillic / Greek look-alikes such as а, е, о, с standing in for a, e, o, c) —
 *     folded to their ASCII look-alike with a curated confusables table; and
 *   - **base64-wrapped payloads** — decoded and scanned as plain text.
 *
 * The scanner runs its rules over every view and unions the findings, so a payload written as
 * `Ignоrе prеviоus…` (Cyrillic) or as a base64 blob is caught the same as its plain-ASCII form. This
 * only *adds* views — it never suppresses a match — and the views are cheap, linear-time transforms.
 *
 * @packageDocumentation
 */

/**
 * Confusables map: characters that render like an ASCII letter but are a different code point.
 * Curated (Cyrillic + Greek look-alikes most used in homoglyph attacks); NFKC does not fold these.
 */
const HOMOGLYPHS: Record<string, string> = {
  // Cyrillic → Latin
  а: "a",
  е: "e",
  о: "o",
  с: "c",
  р: "p",
  х: "x",
  у: "y",
  ѕ: "s",
  і: "i",
  ј: "j",
  ԛ: "q",
  ѡ: "w",
  к: "k",
  м: "m",
  н: "h",
  т: "t",
  в: "b",
  г: "r",
  п: "n",
  д: "d",
  л: "l",
  А: "A",
  Е: "E",
  О: "O",
  С: "C",
  Р: "P",
  Х: "X",
  У: "Y",
  К: "K",
  М: "M",
  Н: "H",
  Т: "T",
  В: "B",
  // Greek → Latin
  ο: "o",
  ι: "i",
  ν: "v",
  α: "a",
  ρ: "p",
  ε: "e",
  τ: "t",
  υ: "u",
  χ: "x",
  κ: "k",
  ς: "s",
  β: "b",
  Ο: "O",
  Ι: "I",
  Α: "A",
  Ρ: "P",
  Ε: "E",
  Τ: "T",
  Χ: "X",
  Κ: "K",
  Β: "B",
  Ν: "N",
  Μ: "M",
};

/** Replace homoglyph code points with their ASCII look-alike. Other characters pass through. */
export function foldHomoglyphs(text: string): string {
  let out = "";
  for (const ch of text) out += HOMOGLYPHS[ch] ?? ch;
  return out;
}

/** A base64-shaped run long enough to carry a meaningful payload. */
const BASE64 = /[A-Za-z0-9+/]{16,}={0,2}/g;
/** Printable ASCII (plus tab/newline/carriage-return) — a decoded blob must be text to be scanned. */
const PRINTABLE = /^[\t\n\r\x20-\x7E]+$/;

/**
 * Decode base64-looking substrings that round-trip cleanly and decode to printable text. Non-base64
 * runs, binary blobs, and anything that does not re-encode to itself are skipped (no noise).
 */
export function decodeBase64Segments(text: string): string[] {
  const out: string[] = [];
  for (const m of text.match(BASE64) ?? []) {
    try {
      const buf = Buffer.from(m, "base64");
      if (buf.length < 8) continue;
      const decoded = buf.toString("utf8");
      if (!PRINTABLE.test(decoded)) continue;
      // Round-trip check: only accept runs that were genuinely base64 (ignoring padding).
      if (buf.toString("base64").replace(/=+$/, "") !== m.replace(/=+$/, "")) continue;
      out.push(decoded);
    } catch {
      // not decodable — skip
    }
  }
  return out;
}

/**
 * Return the distinct normalized views of `text` to scan: the original, its NFKC form, homoglyph-folded
 * forms, and any decoded base64 payloads. Always includes the original, so normalization can only add
 * detections, never remove them.
 */
export function normalizedViews(text: string): string[] {
  if (!text) return [];
  const views = new Set<string>();
  views.add(text);
  const nfkc = text.normalize("NFKC");
  views.add(nfkc);
  views.add(foldHomoglyphs(text));
  views.add(foldHomoglyphs(nfkc));
  for (const decoded of decodeBase64Segments(text)) views.add(decoded);
  return [...views];
}
