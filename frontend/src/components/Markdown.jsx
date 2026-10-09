// Minimal, safe Markdown renderer for copilot output: headings, lists, code
// blocks, bold, inline code and links. It builds React elements only - no
// raw HTML is ever injected.
import { Fragment } from "react";

function inline(text, keyBase) {
  const parts = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\((https?:\/\/[^)\s]+)\))/g;
  let last = 0;
  let m;
  let i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    const tok = m[0];
    const key = `${keyBase}-${i++}`;
    if (tok.startsWith("**")) parts.push(<strong key={key} className="font-semibold text-white">{tok.slice(2, -2)}</strong>);
    else if (tok.startsWith("`")) parts.push(<code key={key} className="rounded bg-slate-800 px-1 font-mono text-[12px] text-teal-200">{tok.slice(1, -1)}</code>);
    else {
      const label = tok.slice(1, tok.indexOf("]"));
      parts.push(<a key={key} href={m[2]} target="_blank" rel="noreferrer noopener" className="text-teal-300 underline">{label}</a>);
    }
    last = m.index + tok.length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts;
}

export default function Markdown({ text }) {
  const lines = text.split("\n");
  const out = [];
  let list = [];
  let code = null;
  const flushList = () => {
    if (list.length) {
      out.push(<ul key={`ul-${out.length}`} className="my-2 list-disc space-y-1 pl-5">{list}</ul>);
      list = [];
    }
  };
  lines.forEach((line, idx) => {
    if (line.trim().startsWith("```")) {
      if (code === null) {
        flushList();
        code = [];
      } else {
        out.push(<pre key={`pre-${idx}`} className="my-2 overflow-x-auto rounded-lg bg-slate-950 p-3 font-mono text-xs text-teal-200">{code.join("\n")}</pre>);
        code = null;
      }
      return;
    }
    if (code !== null) {
      code.push(line);
      return;
    }
    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    const bullet = line.match(/^\s*[-*]\s+(.*)$/) || line.match(/^\s*\d+\.\s+(.*)$/);
    if (heading) {
      flushList();
      out.push(<h4 key={idx} className="mb-1 mt-4 text-sm font-semibold text-white first:mt-0">{inline(heading[2], idx)}</h4>);
    } else if (bullet) {
      list.push(<li key={idx}>{inline(bullet[1], idx)}</li>);
    } else if (line.startsWith(">")) {
      flushList();
      out.push(<p key={idx} className="my-2 border-l-2 border-violet-400 pl-3 text-violet-200">{inline(line.replace(/^>\s?/, ""), idx)}</p>);
    } else if (line.trim()) {
      flushList();
      out.push(<p key={idx} className="my-1.5">{inline(line, idx)}</p>);
    } else {
      flushList();
    }
  });
  flushList();
  if (code) out.push(<pre key="pre-end" className="my-2 rounded-lg bg-slate-950 p-3 font-mono text-xs">{code.join("\n")}</pre>);
  return <div className="text-sm leading-relaxed text-slate-300">{out.map((el, i) => <Fragment key={i}>{el}</Fragment>)}</div>;
}
