import * as yaml from "js-yaml";
import fs from "fs";
import { syntaxCheck, checkMX, isDomainInList, isRoleEmail, isSMTP, hasSPF, hasDMARC, getDomainAge } from "./email-validate";
import { NO_PROBE_PROVIDERS } from "./noProbeList";
import { EmailCheckResult } from "./interfaces";

/**
 * Run all checks on a single email and return a structured result.
 */
export const checkEmail = async (
  email: string,
  blocklist: Set<string> = new Set(),
  allowlist: Set<string> = new Set(),
  skipSMTP: boolean = false,
  requestsLeft: number = 0
): Promise<EmailCheckResult> => {
  const result: EmailCheckResult = {email, syntaxValid: syntaxCheck(email), requestsLeft};

  if (!result.syntaxValid) return result;

  const domain = email.split("@")[1].toLowerCase();

  // Role-based
  result.isRole = isRoleEmail(email);

  // Domain lists
  result.inBlocklist = isDomainInList(domain, blocklist);
  result.inTrustedDomains = isDomainInList(domain, allowlist);
  result.isDisposable = result.inBlocklist; // disposable = in blocklist

  // MX check
  const mx = await checkMX(domain);
  if (mx instanceof Error) {
    result.mx = { ok: false };
  } else {
    result.mx = { ok: true };
  }

  // NO_PROBE check
  const noProbe = NO_PROBE_PROVIDERS.includes(domain);
  result.noProbeList = noProbe;

  // SMTP (only if MX ok and not in no-probe)
  if (!skipSMTP && result.mx.ok && !noProbe) {
    const smtp = await isSMTP(domain);
    result.smtp = smtp instanceof Error
      ? { ok: false, error: smtp.message }
      : { ok: smtp };
  } else if (skipSMTP) {
    result.smtp = { ok: false, error: "SMTP check skipped by request" };
  } else if (noProbe) {
    result.smtp = { ok: false, error: "Provider blocks SMTP probes" };
  }

  // SPF / DMARC
  result.hasSPF = await hasSPF(domain);
  result.hasDMARC = await hasDMARC(domain);

  // Domain age
  result.domainAgeYears = await getDomainAge(domain);
  result.requestsLeft = requestsLeft;
  return result;
};
