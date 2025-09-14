export interface EmailCheckResult {
  email: string;
  syntaxValid: boolean;
  mx?: { ok: boolean };
  smtp?: { ok: boolean; error?: string };
  inBlocklist?: boolean;
  inTrustedDomains?: boolean;
  isRole?: boolean;
  isDisposable?: boolean;
  hasSPF?: boolean;
  hasDMARC?: boolean;
  domainAgeYears?: number;
  noProbeList?: boolean;
  requestsLeft: number
}
