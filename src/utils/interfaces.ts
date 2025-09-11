export interface EmailCheckResult {
  syntaxValid: boolean;

  // Optional fields because they depend on checks
  isRole?: boolean;
  inBlocklist?: boolean;
  inTrustedDomains?: boolean;

  mx?: {
    ok: boolean;
    error?: string;
  };

  noProbeList?: boolean;

  smtp?: {
    ok: boolean;
    error?: string;
  };
}
