// What the companies view decides, kept apart from the document: the directory page as the system console's server
// answers it, and the id and name a new company may have. The id and name rules repeat the server's so the form can
// say what is wrong before sending; the server's answer is the one that counts.

import { field } from "./flow.ts";

/** Where a company is in its life, as the server names it. */
export type CompanyStatus = "provisioning" | "active" | "suspended";

/** One company of the directory. */
export interface Company {
  id: string;
  name: string;
  status: CompanyStatus;
  createdAt: number;
  createdBy: string;
}

/** A page of the directory and the cursor of the next one, when there is one. */
export interface CompaniesPage {
  companies: Company[];
  next: string | null;
}

/** The most characters a company id and name may have, as the server counts them. */
const ID_MAX_BYTES = 63;
const NAME_MAX_CHARS = 100;

const STATUSES: readonly CompanyStatus[] = ["provisioning", "active", "suspended"];

function isStatus(name: unknown): name is CompanyStatus {
  return STATUSES.some((status) => status === name);
}

/** The address of the directory page after the cursor `after`. */
export function companiesPath(after: string | null): string {
  return after === null ? "api/companies" : `api/companies?${new URLSearchParams({ after }).toString()}`;
}

/** One company as the server answers it, or null for any other shape. */
export function readCompany(value: unknown): Company | null {
  const id = field(value, "id");
  const name = field(value, "name");
  const status = field(value, "status");
  const createdAt = field(value, "created_at");
  const createdBy = field(value, "created_by");
  if (
    typeof id !== "string" || id === "" || typeof name !== "string" || !isStatus(status)
    || typeof createdAt !== "number" || !Number.isSafeInteger(createdAt) || createdAt < 0
    || typeof createdBy !== "string"
  ) {
    return null;
  }
  return { id, name, status, createdAt, createdBy };
}

/** `GET api/companies`'s answer, or null when any part of it is not the shape the console knows. */
export function readCompaniesPage(body: unknown): CompaniesPage | null {
  const listed = field(body, "companies");
  const next = field(body, "next");
  if (!Array.isArray(listed) || (next !== null && typeof next !== "string")) {
    return null;
  }
  const companies: Company[] = [];
  for (const value of listed) {
    const company = readCompany(value);
    if (company === null) {
      return null;
    }
    companies.push(company);
  }
  return { companies, next };
}

/** `typed` trimmed when it is a company id (1 to 63 lowercase letters, digits and inner hyphens), else null. */
export function companyIdOf(typed: string): string | null {
  const id = typed.trim();
  return id.length <= ID_MAX_BYTES && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(id) ? id : null;
}

/** `typed` trimmed when it is a company name (1 to 100 characters, no control character), else null. */
export function companyNameOf(typed: string): string | null {
  const name = typed.trim();
  const length = [...name].length;
  return length >= 1 && length <= NAME_MAX_CHARS && !/\p{Cc}/u.test(name) ? name : null;
}
