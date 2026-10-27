// Unit tests for the evidence-gathering checks (thesis Table 5.1).
// Run with: npm test
//
// The fake keys below are built from pieces (for example "sk_" + "live_") so that
// GitHub's secret scanning does not mistake this file for a leaked key.
import { describe, it, expect } from "vitest";
import {
  validateAndNormalizeUrl,
  normalizeBody,
  looksLikeBaseline,
  validateSignature,
  scanTextForSecrets,
  type CalibrationResult,
} from "../lib/checks";

// ---------------------------------------------------------------------------
// FR1: address check
// ---------------------------------------------------------------------------
describe("FR1 address check", () => {
  it("accepts a public address", () => {
    expect(validateAndNormalizeUrl("example.com")).toBe("https://example.com/");
  });

  it("refuses localhost", () => {
    expect(validateAndNormalizeUrl("http://localhost:3000")).toBeNull();
  });

  it("refuses a private address such as 192.168.1.1", () => {
    expect(validateAndNormalizeUrl("192.168.1.1")).toBeNull();
  });

  it("refuses text that is not an address", () => {
    expect(validateAndNormalizeUrl("not a url")).toBeNull();
  });

  // Known gap (thesis Section 4.3): the check only reads the name, so a public
  // name that points to 127.0.0.1 (localtest.me does) gets through. This test is
  // expected to FAIL until host names are resolved before fetching (Section 7.4).
  it("refuses a public name that points to a private address", () => {
    expect(validateAndNormalizeUrl("localtest.me")).toBeNull();
  });

  it("accepts a local test app only when the test-only setting is on", () => {
    expect(validateAndNormalizeUrl("http://127.0.0.1:3001", false)).toBeNull();
    expect(validateAndNormalizeUrl("http://127.0.0.1:3001", true)).toBe("http://127.0.0.1:3001/");
  });
});

// ---------------------------------------------------------------------------
// FR3: not-found calibration and content checks for exposed files
// ---------------------------------------------------------------------------
const normalPage = "<!doctype html><html><head><title>Shop</title></head><body><h1>Welcome to the shop</h1><p>Browse our products.</p></body></html>";

function calibrationFor(page: string, catchAll: boolean): CalibrationResult {
  return {
    catchAll,
    baselineStatus: catchAll ? 200 : 404,
    baselineLen: catchAll ? page.length : 0,
    baselineContentType: "text/html",
    baselineNorm: catchAll ? normalizeBody(page) : "",
    samples: 2,
  };
}

describe("FR3 not-found calibration and file checks", () => {
  it("a site that returns 404 for missing files: a real file is not mistaken for the not-found page", () => {
    const calib = calibrationFor(normalPage, false);
    expect(looksLikeBaseline("DB_PASSWORD=example\n", calib)).toBe(false);
  });

  it("a site that returns its normal page for every address: /.env is not reported", () => {
    const calib = calibrationFor(normalPage, true);
    expect(looksLikeBaseline(normalPage, calib)).toBe(true);
    expect(validateSignature("/.env", "text/html", normalPage).matched).toBe(false);
  });

  it("a real .env file is reported as critical", () => {
    const env = "DB_PASSWORD=example-password\nAPI_KEY=example-key\n";
    const result = validateSignature("/.env", "text/plain", env);
    expect(result.matched).toBe(true);
    expect(result.severity).toBe("critical");
  });

  it("a page that only mentions .env is not reported", () => {
    const page = "<html><body><p>Never commit your .env file to Git.</p></body></html>";
    expect(validateSignature("/.env", "text/html", page).matched).toBe(false);
  });

  it("a real .git/HEAD file is reported, an HTML page at the same path is not", () => {
    expect(validateSignature("/.git/HEAD", "text/plain", "ref: refs/heads/main\n").matched).toBe(true);
    expect(validateSignature("/.git/HEAD", "text/html", normalPage).matched).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// FR5: secret patterns, one valid example of each format, plus look-alikes
// ---------------------------------------------------------------------------
const a = (n: number) => "a1B2c3D4e5".repeat(Math.ceil(n / 10)).slice(0, n);

const validKeys: Array<[string, string]> = [
  ["AWS Access Key ID", "AKI" + "A" + "ABCDEFGHIJ123456"],
  ["AWS Secret Key", 'aws_secret_access_key = "' + a(40) + '"'],
  ["Google API Key", "AI" + "za" + a(35)],
  ["OpenAI-style Secret Key", "sk" + "-" + a(32)],
  ["Stripe Live Secret Key", "sk_" + "live_" + a(24)],
  ["GitHub Token", "gh" + "p_" + a(36)],
  ["Slack Token", "xo" + "xb-" + "1234567890-" + a(12)],
  ["Private Key", "-----BEGIN " + "RSA PRIVATE KEY-----"],
  ["JWT (verify it is not a public token)", "ey" + "J" + a(20) + "." + a(20) + "." + a(20)],
  ["Hardcoded credential-like assignment", 'apiKey = "' + a(16) + '"'],
];

describe("FR5 secret patterns", () => {
  for (const [label, sample] of validKeys) {
    it(`finds a ${label}`, () => {
      expect(scanTextForSecrets(`<script>\n${sample}\n</script>`)).toContain(label);
    });
  }

  // Newer OpenAI keys start with "sk-proj-". This checks whether the pattern
  // still finds them; a failure here is a real gap to report.
  it("finds a newer OpenAI project key (sk-proj-...)", () => {
    expect(scanTextForSecrets("sk" + "-proj-" + a(40))).toContain("OpenAI-style Secret Key");
  });

  const lookAlikes: Array<[string, string]> = [
    ["a short AKIA string", "AKIA1234"],
    ["a short sk- string", "sk-abc"],
    ["a Stripe test key", "sk_" + "test_" + a(24)],
    ["a public key", "-----BEGIN PUBLIC KEY-----"],
    ["a password field label", '<input type="password" placeholder="Enter your password">'],
  ];
  for (const [name, sample] of lookAlikes) {
    it(`does not report ${name}`, () => {
      expect(scanTextForSecrets(sample)).toEqual([]);
    });
  }
});
