import * as yaml from "js-yaml";
import fs from "fs";
import { syntaxCheck, checkMX, isDomainInList, isRoleEmail, isSMTP } from "./email-validate";
import { NO_PROBE_PROVIDERS } from "./noProbeList";
import { EmailCheckResult } from "./interfaces";

/**
 * Run all checks on a single email and return a structured result.
 */
export const checkEmail = async (
  email: string,
  blocklist: Set<string> = new Set(),
  allowlist: Set<string> = new Set(),
  skipSMTP: boolean = false
): Promise<EmailCheckResult> => {
  const result: EmailCheckResult = {syntaxValid: syntaxCheck(email) };

  if (!result.syntaxValid) return result;

  const domain = email.split("@")[1].toLowerCase();

  // Role-based
  result.isRole = isRoleEmail(email);

  // Domain lists
  result.inBlocklist = isDomainInList(domain, blocklist);
  result.inTrustedDomains = isDomainInList(domain, allowlist);

  // MX check
  const mx = await checkMX(domain);
  if (mx instanceof Error) {
    result.mx = { ok: false, error: mx.message };
  } else {
    result.mx = { ok: true };
  }

  // NO_PROBE check
  result.noProbeList = NO_PROBE_PROVIDERS.includes(domain);

  // SMTP (only if MX ok and not in no-probe)
  if (!skipSMTP && result.mx.ok && !result.noProbeList) {
    const smtp = await isSMTP(domain);
    result.smtp = smtp instanceof Error
      ? { ok: false, error: smtp.message }
      : { ok: smtp };
  } else if (skipSMTP) {
    result.smtp = { ok: false, error: "SMTP check skipped by request" };
  } else if (result.noProbeList) {
    result.smtp = { ok: false, error: "Provider blocks SMTP probes" };
  }

  return result;
};