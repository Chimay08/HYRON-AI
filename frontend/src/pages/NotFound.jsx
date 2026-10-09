import { useNavigate } from "react-router-dom";
import { Compass } from "lucide-react";
import { Button, EmptyState, Panel } from "../components/ui.jsx";

export default function NotFound() {
  const navigate = useNavigate();
  return (
    <Panel>
      <EmptyState icon={Compass} title="Page not found" action={<Button variant="primary" onClick={() => navigate("/")}>Back to overview</Button>}>
        The page you asked for does not exist.
      </EmptyState>
    </Panel>
  );
}
