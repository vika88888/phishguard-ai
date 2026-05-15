"use client";

import { useState } from "react";

function generateExplanation(reasons: string[], score: number) {
  if (score >= 80) {
    return "This content is highly suspicious because it contains multiple phishing indicators, such as unsafe links, credential-related language, or deceptive domain patterns.";
  }

  if (score >= 50) {
    return "This content shows several warning signs of phishing. You should avoid clicking links or sharing personal information until it is verified.";
  }

  if (score >= 20) {
    return "Some minor risk indicators were detected. Be cautious and verify the sender or website before taking action.";
  }

  return "No significant phishing indicators were detected, but you should still remain cautious with unexpected messages or links.";
}

export default function Home() {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<null | {
    score: number;
    level: string;
    reasons: string[];
    threatFeedChecked: boolean;
    explanation: string;
  }>(null);

  async function scanInput() {
    setLoading(true);
    setResult(null);

    const text = input.toLowerCase();
    let score = 0;
    const reasons: string[] = [];
    let threatFeedChecked = false;

    if (text.includes("password")) {
      score += 50;
      reasons.push("Direct request for password detected.");
    }

    if (text.includes("bank") || text.includes("account")) {
      score += 25;
      reasons.push("Sensitive financial or account-related context detected.");
    }

    if (text.includes("login") || text.includes("verify")) {
      score += 25;
      reasons.push("Credential verification or login-related language detected.");
    }

    if (text.includes("payment") || text.includes("card") || text.includes("billing")) {
      score += 25;
      reasons.push("Payment or billing-related request detected.");
    }

    if (
      text.includes("urgent") ||
      text.includes("immediately") ||
      text.includes("act now") ||
      text.includes("suspended") ||
      text.includes("expire")
    ) {
      score += 25;
      reasons.push("Urgency or pressure-based wording detected.");
    }

    if (text.includes("http://")) {
      score += 25;
      reasons.push("Unsecured HTTP link detected.");
    }

    if (
      text.includes("send me") ||
      text.includes("provide your") ||
      text.includes("confirm your") ||
      text.includes("update your")
    ) {
      score += 20;
      reasons.push("Direct request for user information detected.");
    }

    if (text.includes("password") && text.includes("urgent")) {
      score += 25;
      reasons.push("High-risk combination detected: password request plus urgency.");
    }

    if ((text.includes("bank") || text.includes("account")) && text.includes("http://")) {
      score += 20;
      reasons.push("High-risk combination detected: account-related request with unsecured link.");
    }

    const urlMatch = input.match(/(https?:\/\/[^\s]+)/i);

    if (urlMatch) {
      try {
        const extractedUrl = urlMatch[0].replace(/[.,)]$/, "");

        const response = await fetch("/api/threat-check", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ url: extractedUrl }),
        });

        const data = await response.json();
        threatFeedChecked = data.checked;

        if (data.foundInThreatFeed) {
          score += 70;
          reasons.push("URL matches a known phishing threat database.");
        }
        if (data.phishTankChecked && data.phishTankMatch) {
          score += 80;
          reasons.push("URL was found in the live PhishTank phishing database.");
        }

        if (data.phishTankChecked && !data.phishTankMatch) {
          reasons.push("No match found in live PhishTank database (may still be suspicious).");
        }

        if (!data.phishTankChecked) {
          reasons.push("Live PhishTank lookup was unavailable or rate-limited, so local detection was used.");
        }
        if (data.patternMatch) {
          score += 30;
          reasons.push("Phishing-related language detected in URL content.");
        }

        if (data.domainIndicators && data.domainIndicators.length > 0) {
          score += data.domainIndicators.length * 15;
          data.domainIndicators.forEach((indicator: string) => {
            reasons.push(indicator);
          });
        }

        if (
          data.checked &&
          !data.foundInThreatFeed &&
          !data.patternMatch &&
          (!data.domainIndicators || data.domainIndicators.length === 0)
        ) {
          reasons.push("URL checked against local threat intelligence dataset with no direct match.");
        }
      } catch {
        reasons.push("Threat intelligence lookup failed, so local detection was used only.");
      }
    } else {
      reasons.push("No URL detected for threat intelligence analysis.");
    }

    
    // Smarter scoring adjustment
    const warningCount = reasons.length;

    // If several weak indicators exist, increase risk
    if (warningCount >= 3) {
      score += 20;
    } else if (warningCount >= 2) {
    score += 10;
    }

// Unknown URL with suspicious domain should not look too safe
    const hasSuspiciousUrlSignal = reasons.some((reason) =>
      reason.toLowerCase().includes("top-level domain") ||
      reason.toLowerCase().includes("domain") ||
      reason.toLowerCase().includes("http")
    );

    const hasKnownThreatMatch = reasons.some((reason) =>
      reason.toLowerCase().includes("phishtank") ||
      reason.toLowerCase().includes("known phishing")
    );

    if (hasSuspiciousUrlSignal && !hasKnownThreatMatch) {
      score += 15;
    }

// Cap final score
    const finalScore = Math.min(score, 100);

    let level = "Low Risk";
    if (finalScore >= 85) level = "High Risk";
    else if (finalScore >= 40) level = "Medium Risk";

    const explanation = generateExplanation(reasons, finalScore);

    setTimeout(() => {
      setResult({
        score: finalScore,
        level,
        reasons,
        threatFeedChecked,
        explanation,
      });
      setLoading(false);
    }, 700);
  }

  const riskColor =
    result?.level === "High Risk"
      ? "text-red-400"
      : result?.level === "Medium Risk"
      ? "text-yellow-300"
      : "text-green-400";

  return (
    <main className="min-h-screen bg-[#020617] text-white">
      <nav className="border-b border-slate-800 bg-slate-950/70 backdrop-blur">
        <div className="mx-auto max-w-6xl px-6 py-5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-blue-600 flex items-center justify-center text-xl">
              🛡️
            </div>
            <div>
              <h1 className="text-xl font-bold">PhishGuard AI</h1>
              <p className="text-xs text-slate-400">
                AI-assisted phishing risk analysis
              </p>
            </div>
          </div>

          <span className="rounded-full border border-blue-500/40 px-4 py-2 text-sm text-blue-300">
            Threat Intelligence Enabled
          </span>
        </div>
      </nav>

      <section className="mx-auto max-w-6xl px-6 py-14 grid gap-8 lg:grid-cols-2">
        <div className="flex flex-col justify-center">
          <p className="mb-4 text-sm font-semibold uppercase tracking-widest text-blue-400">
            Cybersecurity Awareness Tool
          </p>

          <h2 className="text-5xl font-bold leading-tight mb-5">
            Detect suspicious messages before they become a risk.
          </h2>

          <p className="text-lg text-slate-300 mb-8">
            Paste an email, message, or URL and receive a quick risk score with
            explainable phishing indicators, domain analysis, and local threat
            intelligence checks.
          </p>

          <div className="grid grid-cols-3 gap-4">
            <div className="rounded-2xl border border-slate-800 bg-slate-900 p-4">
              <p className="text-2xl font-bold">10+</p>
              <p className="text-sm text-slate-400">risk signals</p>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-900 p-4">
              <p className="text-2xl font-bold">$0</p>
              <p className="text-sm text-slate-400">free MVP</p>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-900 p-4">
              <p className="text-2xl font-bold">Live</p>
              <p className="text-sm text-slate-400">local scan</p>
            </div>
          </div>
        </div>

        <div className="rounded-3xl border border-slate-800 bg-slate-900/80 p-6 shadow-2xl">
          <div className="mb-5 flex items-center justify-between">
            <div>
              <h3 className="text-2xl font-bold">Scan Content</h3>
              <p className="text-sm text-slate-400">
                Check phishing signals and threat intelligence patterns
              </p>
            </div>

            <div className="h-3 w-3 rounded-full bg-green-400 shadow-[0_0_20px_rgba(74,222,128,0.8)]" />
          </div>

          <textarea
            className="h-56 w-full resize-none rounded-2xl border border-slate-700 bg-slate-950 p-4 text-white outline-none transition focus:border-blue-500"
            placeholder="Paste suspicious email text, SMS, or URL here..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />

          <button
            onClick={scanInput}
            disabled={loading || input.trim().length === 0}
            className="mt-4 w-full rounded-2xl bg-blue-600 py-4 font-semibold transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
          >
            {loading ? "Scanning..." : "Scan for Phishing Risk"}
          </button>

          {loading && (
            <div className="mt-6 rounded-2xl border border-slate-700 bg-slate-950 p-5">
              <p className="font-semibold text-blue-400 animate-pulse">
                🤖 Analysing content, domain signals, and threat intelligence...
              </p>
            </div>
          )}

          {result && (
            <div className="mt-6 rounded-2xl border border-slate-700 bg-slate-950 p-5">
              <div className="mb-4 flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Risk Assessment</p>
                  <h4 className={`text-3xl font-bold ${riskColor}`}>
                    {result.level}
                  </h4>
                </div>

                <div className="text-right">
                  <p className="text-sm text-slate-400">Score</p>
                  <p className="text-3xl font-bold">{result.score}/100</p>
                </div>
              </div>

              <div className="mb-4 h-3 overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full rounded-full bg-blue-500"
                  style={{ width: `${result.score}%` }}
                />
              </div>

              <div className="mb-4 rounded-xl bg-slate-900 p-3 text-sm text-slate-300">
                {result.threatFeedChecked
                  ? "✅ Threat intelligence check completed."
                  : "ℹ️ No URL was available for threat intelligence lookup."}
              </div>

              <div className="mb-4 rounded-xl border border-blue-500/30 bg-blue-950/30 p-4">
                <p className="mb-1 text-sm text-blue-300">AI Analysis Summary</p>
                <p className="text-slate-100">{result.explanation}</p>
              </div>

              <h5 className="mb-2 font-semibold">Detected indicators</h5>

              <ul className="space-y-2 text-slate-300">
                {result.reasons.map((reason, index) => (
                  <li key={index} className="rounded-xl bg-slate-900 p-3">
                    ⚠️ {reason}
                  </li>
                ))}
              </ul>

              <p className="mt-4 text-xs text-slate-500">
                Disclaimer: This tool is for educational use and does not
                replace professional security advice.
              </p>
            </div>
          )}
        </div>
      </section>
    </main>
  );
}