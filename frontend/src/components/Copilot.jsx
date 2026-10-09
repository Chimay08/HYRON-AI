import { useEffect, useState } from "react";
import { Bot, Sparkles } from "lucide-react";
import { api, errorMessage } from "../api.js";
import Markdown from "./Markdown.jsx";
import { Badge, Button, ErrorBox, Loading, Modal } from "./ui.jsx";

// AI Security Copilot: explains a finding (or the whole scan) from verified scan data.
export default function Copilot({ open, onClose, scanId, finding }) {
  const [state, setState] = useState({ status: "idle" });

  useEffect(() => {
    if (!open) return;
    let alive = true;
    setState({ status: "loading" });
    api.explain(scanId, finding?.finding_id)
      .then((data) => alive && setState({ status: "done", data }))
      .catch((e) => alive && setState({ status: "error", error: errorMessage(e) }));
    return () => {
      alive = false;
    };
  }, [open, scanId, finding]);

  const title = finding ? `Copilot - ${finding.package}@${finding.version}` : "Copilot - scan summary";
  return (
    <Modal open={open} onClose={onClose} title={title} wide footer={<Button onClick={onClose}>Close</Button>}>
      {state.status === "loading" && <Loading label="Preparing explanation from verified scan data..." />}
      {state.status === "error" && <ErrorBox>{state.error}</ErrorBox>}
      {state.status === "done" && (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-2 text-xs text-slate-400">
            {state.data.source === "ai" ? (
              <Badge tone="teal"><Sparkles className="h-3 w-3" />AI-generated - {state.data.model}</Badge>
            ) : (
              <Badge tone="slate"><Bot className="h-3 w-3" />Deterministic template</Badge>
            )}
            <span>{state.data.note}</span>
          </div>
          <Markdown text={state.data.explanation} />
        </>
      )}
    </Modal>
  );
}
