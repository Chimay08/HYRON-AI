import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ScoreBadge } from "./ui.jsx";
import SummaryCards from "./SummaryCards.jsx";

describe("security dashboard primitives", () => {
  it("renders the new critical V-RPS priority distinctly", () => {
    render(<ScoreBadge score={91.4} priority="critical" urgent />);
    expect(screen.getByText("91.4")).toBeVisible();
    expect(screen.getByText("critical")).toBeVisible();
    expect(screen.getByText("Urgent review")).toBeVisible();
  });

  it("renders real zero values rather than an empty placeholder", () => {
    render(<SummaryCards items={[{ label: "Findings", value: 0, sub: "current scan" }]} />);
    expect(screen.getByText("0")).toBeVisible();
    expect(screen.getByText("current scan")).toBeVisible();
  });
});
