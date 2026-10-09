import { Suspense, lazy } from "react";
import { Route, Routes } from "react-router-dom";
import { AppProvider } from "./context/AppContext.jsx";
import Layout from "./layout/Layout.jsx";
import { Loading } from "./components/ui.jsx";

// Route-level code splitting keeps Cytoscape and Recharts out of the initial bundle.
const Overview = lazy(() => import("./pages/Overview.jsx"));
const NewScan = lazy(() => import("./pages/NewScan.jsx"));
const Repositories = lazy(() => import("./pages/Repositories.jsx"));
const Findings = lazy(() => import("./pages/Findings.jsx"));
const GraphPage = lazy(() => import("./pages/GraphPage.jsx"));
const Remediation = lazy(() => import("./pages/Remediation.jsx"));
const History = lazy(() => import("./pages/History.jsx"));
const Settings = lazy(() => import("./pages/Settings.jsx"));
const Report = lazy(() => import("./pages/Report.jsx"));
const NotFound = lazy(() => import("./pages/NotFound.jsx"));

const page = (Component) => (
  <Suspense fallback={<Loading />}>
    <Component />
  </Suspense>
);

export default function App() {
  return (
    <AppProvider>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={page(Overview)} />
          <Route path="scan/new" element={page(NewScan)} />
          <Route path="repositories" element={page(Repositories)} />
          <Route path="findings" element={page(Findings)} />
          <Route path="graph" element={page(GraphPage)} />
          <Route path="remediation" element={page(Remediation)} />
          <Route path="history" element={page(History)} />
          <Route path="settings" element={page(Settings)} />
          <Route path="reports/:scanId" element={page(Report)} />
          <Route path="*" element={page(NotFound)} />
        </Route>
      </Routes>
    </AppProvider>
  );
}
