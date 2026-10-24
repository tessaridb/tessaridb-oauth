// The audit trail view: the company's trail in the order the server keeps it, a page at a time behind the position
// cursor, with no total. Each message shows only the fields it was written with.

import { refusedOn, unreadable } from "./console-change.ts";
import { type Screen, heading, link, make, show } from "./console-dom.ts";
import { call, say } from "./dom.ts";
import { type AuditEvent, auditPath, readAuditPage } from "./audit-read.ts";

/** A time in seconds since the epoch, as the operator's locale writes a moment. */
function moment(seconds: number): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" }).format(
    new Date(seconds * 1000),
  );
}

/** One message as a row: position, when, kind, and its own fields. */
function row(event: AuditEvent): HTMLTableRowElement {
  const details = make("dl", "facts");
  for (const [label, value] of event.details) {
    details.append(make("dt", "", label), make("dd", "", make("code", "", value)));
  }
  return make(
    "tr",
    "",
    make("td", "", make("code", "", String(event.position))),
    make("td", "", moment(event.at)),
    make("td", "", make("code", "", event.kind)),
    make("td", "", event.details.length > 0 ? details : ""),
  );
}

/** The trail page after the position `after`. */
export async function auditView(screen: Screen, after: number | null): Promise<void> {
  say("Loading the audit trail.");
  const answer = await call("GET", auditPath(after));
  if (!screen.live()) {
    return;
  }
  if (!answer.ok) {
    refusedOn(screen, "Audit trail", answer, "That page");
    return;
  }
  const page = readAuditPage(answer.body);
  if (page === null) {
    unreadable(screen, "Audit trail");
    return;
  }
  const parts: Node[] = [
    heading("Audit trail"),
    make("p", "lead", "What was done in this company, oldest first, with the fields each event was recorded with."),
  ];
  if (page.events.length === 0) {
    parts.push(make("p", "empty", after === null ? "Nothing has been recorded yet." : "No later events."));
  } else {
    const head = make(
      "tr",
      "",
      make("th", "", "Position"),
      make("th", "", "When"),
      make("th", "", "Event"),
      make("th", "", "Details"),
    );
    for (const cell of head.children) {
      cell.setAttribute("scope", "col");
    }
    parts.push(make("table", "grid", make("thead", "", head), make("tbody", "", ...page.events.map(row))));
  }
  const paging = make("p", "paging");
  if (after !== null) {
    paging.append(link("#/audit", "First page"));
  }
  if (page.next !== null) {
    paging.append(link(`#/audit?after=${page.next}`, "Next page"));
  }
  if (paging.childElementCount > 0) {
    parts.push(paging);
  }
  show(screen.view, ...parts);
  say("");
}
