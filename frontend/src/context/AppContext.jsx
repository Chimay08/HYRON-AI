import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { api, errorMessage } from "../api.js";

const AppContext = createContext(null);
const CURRENT_KEY = "hyron.currentScan";

function readCurrent() {
  try {
    return localStorage.getItem(CURRENT_KEY);
  } catch {
    return null;
  }
}

export function AppProvider({ children }) {
  const [health, setHealth] = useState({ status: "checking" });
  const [meta, setMeta] = useState(null);
  const [scans, setScans] = useState([]);
  const [scansLoaded, setScansLoaded] = useState(false);
  const [currentScanId, setCurrentScanIdState] = useState(readCurrent);
  const [activeScan, setActiveScan] = useState(null); // { label, startedAt } while a scan runs
  const cache = useRef(new Map()); // scanId -> { report, graph }
  const [cacheVersion, setCacheVersion] = useState(0);

  const setCurrentScanId = useCallback((id) => {
    setCurrentScanIdState(id);
    try {
      if (id) localStorage.setItem(CURRENT_KEY, id);
      else localStorage.removeItem(CURRENT_KEY);
    } catch {
      /* ignore */
    }
  }, []);

  const refreshScans = useCallback(async () => {
    try {
      const list = await api.scans();
      setScans(list);
      return list;
    } catch {
      return [];
    } finally {
      setScansLoaded(true);
    }
  }, []);

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth({ status: "down" }));
    api.meta().then(setMeta).catch(() => setMeta(null));
    refreshScans().then((list) => {
      // Server memory is cleared on restart: drop a stale "current" selection.
      setCurrentScanIdState((cur) => {
        if (cur && list.some((s) => s.scan_id === cur)) return cur;
        const firstDep = list.find((s) => s.kind === "dependency");
        return firstDep ? firstDep.scan_id : null;
      });
    });
  }, [refreshScans]);

  const putReport = useCallback((report) => {
    const prev = cache.current.get(report.scan_id) ?? {};
    cache.current.set(report.scan_id, { ...prev, report });
    setCacheVersion((v) => v + 1);
  }, []);

  const loadReport = useCallback(async (id, force = false) => {
    const hit = cache.current.get(id);
    if (hit?.report && !force) return hit.report;
    const report = await api.report(id);
    putReport(report);
    return report;
  }, [putReport]);

  const loadGraph = useCallback(async (id) => {
    const hit = cache.current.get(id);
    if (hit?.graph) return hit.graph;
    const graph = await api.graph(id);
    cache.current.set(id, { ...(cache.current.get(id) ?? {}), graph });
    setCacheVersion((v) => v + 1);
    return graph;
  }, []);

  // Runs any scan action, tracks global status, records the result as current.
  const runScan = useCallback(async (label, action) => {
    setActiveScan({ label, startedAt: Date.now() });
    try {
      const report = await action();
      putReport(report);
      if (report.kind === "dependency") setCurrentScanId(report.scan_id);
      await refreshScans();
      return report;
    } catch (e) {
      throw new Error(errorMessage(e));
    } finally {
      setActiveScan(null);
    }
  }, [putReport, refreshScans, setCurrentScanId]);

  const value = useMemo(() => ({
    health, meta, scans, scansLoaded, refreshScans, currentScanId, setCurrentScanId,
    activeScan, runScan, loadReport, loadGraph, putReport, cacheVersion,
    cachedReport: (id) => cache.current.get(id)?.report ?? null,
  }), [health, meta, scans, scansLoaded, refreshScans, currentScanId, setCurrentScanId, activeScan, runScan,
    loadReport, loadGraph, putReport, cacheVersion]);

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp() {
  return useContext(AppContext);
}

// Loads the report for a scan (defaults to the current scan) with loading/error state.
export function useReport(scanId) {
  const { currentScanId, loadReport, cachedReport, cacheVersion } = useApp();
  const id = scanId ?? currentScanId;
  const [state, setState] = useState({ loading: !!id, error: "" });

  useEffect(() => {
    if (!id) {
      setState({ loading: false, error: "" });
      return undefined;
    }
    let alive = true;
    setState((s) => ({ ...s, loading: !cachedReport(id), error: "" }));
    loadReport(id)
      .then(() => alive && setState({ loading: false, error: "" }))
      .catch((e) => alive && setState({ loading: false, error: errorMessage(e) }));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, loadReport]);

  // cacheVersion keeps this in sync when a report is updated (e.g. remediation status).
  void cacheVersion;
  return { id, report: id ? cachedReport(id) : null, ...state };
}
