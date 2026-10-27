/** Renders model output as TEXT (React escapes it) with the leaked-canary spans highlighted via <mark>.
 *  Never uses dangerouslySetInnerHTML: LLM output and attack payloads are untrusted. */
export function CanaryText({ text, spans }: { text: string; spans: [number, number][] }) {
  const parts: { s: string; hit: boolean }[] = [];
  let pos = 0;
  for (const [a, b] of [...spans].sort((x, y) => x[0] - y[0])) {
    if (a < pos) continue;
    if (a > pos) parts.push({ s: text.slice(pos, a), hit: false });
    parts.push({ s: text.slice(a, b), hit: true });
    pos = b;
  }
  if (pos < text.length) parts.push({ s: text.slice(pos), hit: false });
  return (
    <p className="whitespace-pre-wrap break-words text-sm">
      {parts.map((p, i) =>
        p.hit ? (
          <mark key={i} className="rounded bg-bad px-0.5 font-semibold text-page" title="leaked canary">⚠ {p.s}</mark>
        ) : (
          <span key={i}>{p.s}</span>
        ),
      )}
    </p>
  );
}
