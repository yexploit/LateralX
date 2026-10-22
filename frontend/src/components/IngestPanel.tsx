import { useRef, useState } from "react";
import { api } from "../api";

interface Props {
  onChanged: () => Promise<void> | void;
}

export function IngestPanel({ onChanged }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [path, setPath] = useState("");
  const [replace, setReplace] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const runUpload = async (file: File) => {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const res = await api.upload(file, replace);
      setMessage(
        `Ingested ${res.ingested} events from ${file.name}. Total ${res.total_events}. Findings ${res.findings}.`
      );
      await onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Upload failed");
    } finally {
      setBusy(false);
    }
  };

  const runPath = async () => {
    if (!path.trim()) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const res = await api.ingestPath(path.trim(), replace);
      setMessage(
        `Ingested ${res.ingested} events. Total ${res.total_events}. Findings ${res.findings}.`
      );
      await onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Path ingest failed");
    } finally {
      setBusy(false);
    }
  };

  const clearAll = async () => {
    if (!confirm("Clear all ingested telemetry and analysis?")) return;
    setBusy(true);
    try {
      await api.clearIngest();
      setMessage("Cleared all events.");
      await onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Clear failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="ingest-panel">
      <h3>Ingest real telemetry</h3>
      <p className="ingest-help">
        Upload Windows <strong>.evtx</strong>, Sysmon/Security <strong>.xml</strong>,{" "}
        <strong>.json / .jsonl</strong>, or <strong>.csv</strong>. LateralX normalizes,
        correlates, detects, and rebuilds the attack graph from your data.
      </p>

      <div className="ingest-row">
        <button className="btn btn-primary" disabled={busy} onClick={() => inputRef.current?.click()}>
          {busy ? "Working…" : "Upload log file"}
        </button>
        <input
          ref={inputRef}
          type="file"
          accept=".evtx,.xml,.json,.jsonl,.ndjson,.csv"
          hidden
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void runUpload(f);
            e.target.value = "";
          }}
        />
        <label className="toggle" style={{ marginLeft: 8 }}>
          <input type="checkbox" checked={replace} onChange={(e) => setReplace(e.target.checked)} />
          Replace existing data
        </label>
      </div>

      <div className="ingest-row" style={{ marginTop: 10 }}>
        <input
          className="field"
          placeholder="Or server path: C:\\logs\\Security.evtx or /var/log/windows/"
          value={path}
          onChange={(e) => setPath(e.target.value)}
        />
        <button className="btn" disabled={busy || !path.trim()} onClick={() => void runPath()}>
          Ingest path
        </button>
      </div>

      <div className="list-actions">
        <button className="btn" disabled={busy} onClick={() => void api.reload().then(onChanged)}>
          Re-analyze DB
        </button>
        <button className="btn" disabled={busy} onClick={() => void clearAll()}>
          Clear all
        </button>
      </div>

      {message && <p className="ingest-ok">{message}</p>}
      {error && <p className="error" style={{ padding: 0 }}>{error}</p>}
    </div>
  );
}
