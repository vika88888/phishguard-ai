import { NextResponse } from "next/server";
import { knownThreatUrls } from "../../../data/threatUrls";

const suspiciousPatterns = [
  "verify",
  "secure",
  "login",
  "account",
  "update",
  "bank",
  "payment",
  "alert",
  "confirm",
];

const riskyTlds = [".xyz", ".click", ".top", ".store", ".info", ".support"];

const suspiciousWords = [
  "secure",
  "login",
  "verify",
  "account",
  "update",
  "payment",
  "auth",
  "support",
  "service",
  "spid",
];

const typoSpoofs = [
  { fake: "paypa1", brand: "PayPal" },
  { fake: "paypal-", brand: "PayPal" },
  { fake: "micros0ft", brand: "Microsoft" },
  { fake: "microsoft-", brand: "Microsoft" },
  { fake: "g00gle", brand: "Google" },
  { fake: "google-", brand: "Google" },
  { fake: "amaz0n", brand: "Amazon" },
  { fake: "amazon-", brand: "Amazon" },
  { fake: "app1e", brand: "Apple" },
  { fake: "apple-", brand: "Apple" },
];

const trustedBrands = ["paypal", "amazon", "bank", "apple", "microsoft"];

function analyseDomain(url: string) {
  const indicatorSet = new Set<string>();

  try {
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname.toLowerCase();

    typoSpoofs.forEach((item) => {
      if (hostname.includes(item.fake)) {
        indicatorSet.add(
          `Possible typo-squatting detected: domain may imitate ${item.brand}.`
        );
      }
    });

    if (riskyTlds.some((tld) => hostname.endsWith(tld))) {
      indicatorSet.add("Suspicious top-level domain detected.");
    }

    if (suspiciousWords.some((word) => hostname.includes(word))) {
      indicatorSet.add("Suspicious keyword detected in domain name.");
    }

    if (trustedBrands.some((brand) => hostname.includes(brand))) {
      indicatorSet.add("Possible brand impersonation detected.");
    }

    if ((hostname.match(/-/g) || []).length >= 2) {
      indicatorSet.add("Domain contains multiple hyphens, common in phishing.");
    }

    if (hostname.length > 35) {
      indicatorSet.add("Unusually long domain detected.");
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      indicatorSet.add("URL uses an IP address instead of a normal domain.");
    }
  } catch {
    indicatorSet.add("URL could not be parsed for domain analysis.");
  }

  return Array.from(indicatorSet);
}

async function checkPhishTank(url: string) {
  try {
    const formData = new URLSearchParams();
    formData.append("url", url);
    formData.append("format", "json");

    const response = await fetch("https://checkurl.phishtank.com/checkurl/", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "phishtank/viktoriia-phishguard-ai",
      },
      body: formData.toString(),
    });

    const text = await response.text();

    if (!text.trim().startsWith("{")) {
      return {
        checked: false,
        found: false,
        message: "PhishTank returned a non-JSON or rate-limited response.",
      };
    }

    const data = JSON.parse(text);

    return {
      checked: true,
      found: Boolean(data?.results?.valid && data?.results?.in_database),
      message: "PhishTank lookup completed.",
    };
  } catch {
    return {
      checked: false,
      found: false,
      message: "PhishTank lookup failed.",
    };
  }
}

export async function POST(req: Request) {
  try {
    const { url } = await req.json();

    if (!url) {
      return NextResponse.json({
        checked: false,
        foundInThreatFeed: false,
        phishTankChecked: false,
        phishTankMatch: false,
        patternMatch: false,
        domainIndicators: [],
      });
    }

    const cleanUrl = url.trim().toLowerCase().replace(/[.,)]$/, "");

    const foundExact = knownThreatUrls.some(
      (threat) => threat.toLowerCase() === cleanUrl
    );

    const foundPattern = suspiciousPatterns.some((pattern) =>
      cleanUrl.includes(pattern)
    );

    const domainIndicators = analyseDomain(cleanUrl);
    const phishTank = await checkPhishTank(cleanUrl);

    return NextResponse.json({
      checked: true,
      foundInThreatFeed: foundExact,
      phishTankChecked: phishTank.checked,
      phishTankMatch: phishTank.found,
      phishTankMessage: phishTank.message,
      patternMatch: foundPattern,
      domainIndicators,
    });
  } catch {
    return NextResponse.json({
      checked: false,
      foundInThreatFeed: false,
      phishTankChecked: false,
      phishTankMatch: false,
      patternMatch: false,
      domainIndicators: [],
    });
  }
}