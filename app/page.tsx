"use client"

import type React from "react"
import { useCallback, useMemo, useRef, useState } from "react"
import {
  ArrowRight,
  Check,
  ChevronDown,
  Download,
  Eye,
  FileText,
  Fingerprint,
  Info,
  Loader2,
  Lock,
  RotateCcw,
  Scan,
  Shield,
  ShieldCheck,
  Upload,
  X,
} from "lucide-react"

/* -------------------------------------------------------------------------- */
/*  TYPES & DOMAIN MODEL                                                       */
/* -------------------------------------------------------------------------- */

type Phase = "idle" | "scanning" | "analysis" | "protecting" | "protected"
type Mode = "REDACT" | "MASK" | "ANONYMIZE"
type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
type Category = "Identity" | "Contact" | "Location" | "Financial" | "Other"

interface Signal {
  index: number
  type: string
  value: string
  category: Category
  severity: Severity
  why: string
  exposure: string[]
  recommended: Mode
  context: string
  transforms: Record<Mode, string>
}

interface ScanResult {
  scanId: string
  fileName: string
  fileSize: string
  hash: string
  score: number
  status: string
  narrative: string
  signals: Signal[]
  originalText: string
}

/* -------------------------------------------------------------------------- */
/*  MOCK INTELLIGENCE ENGINE                                                   */
/*  Swap to a FastAPI backend by setting NEXT_PUBLIC_API_URL.                  */
/*                                                                            */
/*  const base = process.env.NEXT_PUBLIC_API_URL                              */
/*  if (base) {                                                               */
/*    const fd = new FormData(); fd.append("file", file)                      */
/*    const res = await fetch(`${base}/scan`, { method: "POST", body: fd })   */
/*    return (await res.json()) as ScanResult                                 */
/*  }                                                                         */
/* -------------------------------------------------------------------------- */

const SAMPLE_TEXT = `EXECUTIVE RESUME — CONFIDENTIAL

Rahul Kumar
Senior Product Manager

Phone: +91 98765 43210
Email: rahul.kumar@gmail.com
Location: Bangalore, Karnataka
Residential Address: 12/4 Palm Grove Avenue, Indiranagar

IDENTIFICATION & FINANCIAL
PAN: ABCDE1234F
Corporate Card: 4092-8812-9901

PERSONAL NOTES
Diagnosed with Type-2 Diabetes; requires flexible hours.`

const SAMPLE_SIGNALS: Signal[] = [
  {
    index: 1,
    type: "PERSON",
    value: "Rahul Kumar",
    category: "Identity",
    severity: "HIGH",
    why: "A full legal name is the primary key that links every other data point in this document back to a single real individual.",
    exposure: [
      "Enables cross-referencing with public records and social profiles",
      "Anchors doxxing and targeted social-engineering attempts",
      "Turns anonymous data into personally identifiable information",
    ],
    recommended: "ANONYMIZE",
    context: "…Rahul Kumar — Senior Product Manager…",
    transforms: { REDACT: "[PERSON REDACTED]", MASK: "R**** K****", ANONYMIZE: "Alex Morgan" },
  },
  {
    index: 2,
    type: "PHONE",
    value: "+91 98765 43210",
    category: "Contact",
    severity: "HIGH",
    why: "A direct phone number is a high-value contact channel for SIM-swap fraud, phishing calls, and account recovery abuse.",
    exposure: [
      "SMS OTP interception and SIM-swap attacks",
      "Voice phishing (vishing) targeting the individual",
      "Correlation across leaked marketing databases",
    ],
    recommended: "MASK",
    context: "…Phone: +91 98765 43210…",
    transforms: { REDACT: "[PHONE REDACTED]", MASK: "+91 98*****210", ANONYMIZE: "+91 90000 00000" },
  },
  {
    index: 3,
    type: "EMAIL",
    value: "rahul.kumar@gmail.com",
    category: "Contact",
    severity: "HIGH",
    why: "A personal email is the most common account identifier online and a direct vector for credential-stuffing and phishing.",
    exposure: [
      "Account enumeration across services",
      "Targeted spear-phishing campaigns",
      "Password-reset and takeover attempts",
    ],
    recommended: "MASK",
    context: "…Email: rahul.kumar@gmail.com…",
    transforms: {
      REDACT: "[EMAIL REDACTED]",
      MASK: "r*********@gmail.com",
      ANONYMIZE: "alex.morgan@example.com",
    },
  },
  {
    index: 4,
    type: "LOCATION",
    value: "Bangalore, Karnataka",
    category: "Location",
    severity: "MEDIUM",
    why: "City-level location narrows physical whereabouts and, combined with other signals, meaningfully raises re-identification risk.",
    exposure: [
      "Regional targeting for scams and fraud",
      "Narrows candidate pool for de-anonymization",
      "Reveals jurisdiction and timezone patterns",
    ],
    recommended: "ANONYMIZE",
    context: "…Location: Bangalore, Karnataka…",
    transforms: { REDACT: "[LOCATION REDACTED]", MASK: "B********, K*******", ANONYMIZE: "Metro City, State" },
  },
  {
    index: 5,
    type: "ADDRESS",
    value: "12/4 Palm Grove Avenue, Indiranagar",
    category: "Location",
    severity: "CRITICAL",
    why: "A precise residential address exposes the individual to physical-world harm — stalking, break-ins, and unwanted contact.",
    exposure: [
      "Direct physical safety risk to the individual",
      "Enables stalking and unsolicited in-person contact",
      "Links identity to a specific property and household",
    ],
    recommended: "REDACT",
    context: "…Residential Address: 12/4 Palm Grove Avenue, Indiranagar…",
    transforms: {
      REDACT: "[ADDRESS REDACTED]",
      MASK: "**/* Palm Grove *****, ***********",
      ANONYMIZE: "45 Cedar Lane, Downtown",
    },
  },
  {
    index: 6,
    type: "PAN",
    value: "ABCDE1234F",
    category: "Financial",
    severity: "CRITICAL",
    why: "A PAN is a government tax identifier that unlocks financial identity and is a prime target for identity theft.",
    exposure: [
      "Financial identity theft and fraudulent accounts",
      "Tax and loan application fraud",
      "Permanent identifier that cannot be rotated",
    ],
    recommended: "REDACT",
    context: "…PAN: ABCDE1234F…",
    transforms: { REDACT: "[PAN REDACTED]", MASK: "AB*****34F", ANONYMIZE: "ZZZZZ0000Z" },
  },
  {
    index: 7,
    type: "FINANCIAL",
    value: "4092-8812-9901",
    category: "Financial",
    severity: "CRITICAL",
    why: "A card number is directly monetizable — even partial exposure combined with a name enables fraud attempts.",
    exposure: [
      "Direct financial fraud and unauthorized charges",
      "Card-not-present transaction abuse",
      "Sale on illicit carding marketplaces",
    ],
    recommended: "REDACT",
    context: "…Corporate Card: 4092-8812-9901…",
    transforms: { REDACT: "[CARD REDACTED]", MASK: "4092-****-9901", ANONYMIZE: "4000-0000-0000" },
  },
  {
    index: 8,
    type: "MEDICAL",
    value: "Diagnosed with Type-2 Diabetes",
    category: "Other",
    severity: "CRITICAL",
    why: "Health conditions are special-category data. Disclosure can drive discrimination in hiring, insurance, and social contexts.",
    exposure: [
      "Employment and insurance discrimination",
      "Sensitive-category data under privacy law (GDPR/HIPAA-adjacent)",
      "Reputational and social harm",
    ],
    recommended: "ANONYMIZE",
    context: "…Diagnosed with Type-2 Diabetes; requires flexible hours…",
    transforms: {
      REDACT: "[MEDICAL REDACTED]",
      MASK: "Diagnosed with T****-* D*******",
      ANONYMIZE: "Diagnosed with [health condition]",
    },
  },
]

function pseudoHash(seed: string): string {
  // Deterministic, display-only SHA-256-style fingerprint for the demo.
  let h = 0x811c9dc5
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  let out = ""
  let x = h >>> 0
  const chars = "0123456789abcdef"
  for (let i = 0; i < 64; i++) {
    x = (Math.imul(x, 1103515245) + 12345) >>> 0
    out += chars[(x >>> ((i % 6) * 4)) & 0xf]
  }
  return out
}

async function scanDocument(file: { name: string; size: number; text: string }): Promise<ScanResult> {
  // MOCK MODE. Replace with POST ${NEXT_PUBLIC_API_URL}/scan (see notes above).
  const mb = (file.size / (1024 * 1024)).toFixed(1)
  return {
    scanId: "scan_" + pseudoHash(file.name + file.size).slice(0, 12),
    fileName: file.name,
    fileSize: `${mb} MB`,
    hash: pseudoHash(file.text + file.name),
    score: 82,
    status: "CRITICAL EXPOSURE",
    narrative:
      "Your document contains information that could meaningfully increase privacy exposure if shared.",
    signals: SAMPLE_SIGNALS,
    originalText: file.text,
  }
}

function protectDocument(scan: ScanResult, mode: Mode): string {
  // MOCK MODE. Replace with POST ${NEXT_PUBLIC_API_URL}/protect
  //   body: { scan_id: scan.scanId, mode }
  let text = scan.originalText
  for (const s of scan.signals) {
    text = text.split(s.value).join(s.transforms[mode])
  }
  return text
}

/* -------------------------------------------------------------------------- */
/*  STYLE HELPERS                                                              */
/* -------------------------------------------------------------------------- */

const CATEGORIES: Category[] = ["Identity", "Contact", "Location", "Financial", "Other"]

function severityClasses(sev: Severity): string {
  switch (sev) {
    case "CRITICAL":
      return "text-rose-300 border-rose-400/25 bg-rose-500/10"
    case "HIGH":
      return "text-amber-200 border-amber-300/25 bg-amber-400/10"
    case "MEDIUM":
      return "text-violet-200 border-violet-300/20 bg-violet-400/10"
    default:
      return "text-zinc-300 border-white/15 bg-white/5"
  }
}

/* -------------------------------------------------------------------------- */
/*  PAGE                                                                       */
/* -------------------------------------------------------------------------- */

export default function Page() {
  const [phase, setPhase] = useState<Phase>("idle")
  const [scan, setScan] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)

  // scanning / protecting animation state
  const [progress, setProgress] = useState(0)
  const [stepIndex, setStepIndex] = useState(0)
  const [scanMeta, setScanMeta] = useState<{ name: string; size: string } | null>(null)

  // analysis state
  const [filter, setFilter] = useState<Category | "ALL">("ALL")
  const [openSignal, setOpenSignal] = useState<number | null>(null)
  const [mode, setMode] = useState<Mode>("REDACT")

  // protected state
  const [view, setView] = useState<"document" | "ledger">("document")

  // modal
  const [modal, setModal] = useState<null | "how" | "privacy" | "about">(null)

  const fileRef = useRef<HTMLInputElement | null>(null)

  const scanSteps = [
    "Document loaded",
    "Extracting information",
    "Checking local patterns",
    "Understanding contextual risk",
    "Calculating privacy exposure",
  ]
  const protectSteps = [
    "Identifying sensitive regions",
    "Applying cryptographic policy transformation",
    "Verifying protected output integrity",
  ]

  const reset = useCallback(() => {
    setPhase("idle")
    setScan(null)
    setError(null)
    setProgress(0)
    setStepIndex(0)
    setScanMeta(null)
    setFilter("ALL")
    setOpenSignal(null)
    setMode("REDACT")
    setView("document")
  }, [])

  const runScan = useCallback(async (file: { name: string; size: number; text: string }) => {
    setError(null)
    setPhase("scanning")
    setProgress(0)
    setStepIndex(0)
    setScanMeta({ name: file.name, size: (file.size / (1024 * 1024)).toFixed(1) + " MB" })

    const totalSteps = 5
    const stepTimers: ReturnType<typeof setTimeout>[] = []
    for (let i = 1; i < totalSteps; i++) {
      stepTimers.push(setTimeout(() => setStepIndex(i), i * 520))
    }
    const progTimer = setInterval(() => {
      setProgress((p) => Math.min(100, p + Math.random() * 9 + 3))
    }, 120)

    const result = await scanDocument(file)

    setTimeout(() => {
      clearInterval(progTimer)
      stepTimers.forEach(clearTimeout)
      setProgress(100)
      setStepIndex(totalSteps - 1)
      setScan(result)
      setMode(result.signals[0]?.recommended ?? "REDACT")
      setTimeout(() => setPhase("analysis"), 420)
    }, 2900)
  }, [])

  const validateAndScan = useCallback(
    (file: File) => {
      const okExt = /\.(pdf|docx|txt)$/i.test(file.name)
      if (!okExt) {
        setError("That file type isn't supported. Please upload a PDF, DOCX, or TXT document.")
        return
      }
      if (file.size === 0) {
        setError("This file looks empty. Please choose a document with content in it.")
        return
      }
      if (file.size > 10 * 1024 * 1024) {
        setError("That document is larger than 10 MB. Please choose a smaller file.")
        return
      }
      // For the demo we analyze against the sample corpus regardless of contents.
      runScan({ name: file.name, size: file.size, text: SAMPLE_TEXT })
    },
    [runScan],
  )

  const runSample = useCallback(() => {
    runScan({ name: "executive-resume.pdf", size: Math.round(2.4 * 1024 * 1024), text: SAMPLE_TEXT })
  }, [runScan])

  const runProtect = useCallback(() => {
    if (!scan) return
    setPhase("protecting")
    setProgress(0)
    setStepIndex(0)
    const stepTimers: ReturnType<typeof setTimeout>[] = []
    for (let i = 1; i < 3; i++) stepTimers.push(setTimeout(() => setStepIndex(i), i * 640))
    const progTimer = setInterval(() => {
      setProgress((p) => Math.min(100, p + Math.random() * 10 + 4))
    }, 130)
    setTimeout(() => {
      clearInterval(progTimer)
      stepTimers.forEach(clearTimeout)
      setProgress(100)
      setStepIndex(2)
      setView("document")
      setTimeout(() => setPhase("protected"), 420)
    }, 2200)
  }, [scan])

  const filteredSignals = useMemo(() => {
    if (!scan) return []
    return filter === "ALL" ? scan.signals : scan.signals.filter((s) => s.category === filter)
  }, [scan, filter])

  const categoryCounts = useMemo(() => {
    const c: Record<string, number> = {}
    scan?.signals.forEach((s) => (c[s.category] = (c[s.category] ?? 0) + 1))
    return c
  }, [scan])

  const protectedText = useMemo(() => (scan ? protectDocument(scan, mode) : ""), [scan, mode])

  const download = useCallback(() => {
    if (!scan) return
    const header = `# PrivacyLens — Protected Document\n# Method: ${mode}\n# Signals neutralized: ${scan.signals.length}\n# Source hash: ${scan.hash}\n\n`
    const blob = new Blob([header + protectedText], { type: "text/plain;charset=utf-8" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `protected-${scan.fileName.replace(/\.[^.]+$/, "")}.txt`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }, [scan, mode, protectedText])

  return (
    <main className="relative min-h-screen overflow-x-hidden bg-[#0a0518] font-sans text-zinc-200 antialiased">
      <Backdrop />
      <Keyframes />

      <TopNav phase={phase} onReset={reset} onOpen={setModal} />

      <div className="relative z-10 mx-auto w-full max-w-5xl px-5 pb-32 pt-10 sm:px-8">
        {phase === "idle" && (
          <Hero
            dragging={dragging}
            error={error}
            onBrowse={() => fileRef.current?.click()}
            onSample={runSample}
            onDragState={setDragging}
            onFile={validateAndScan}
          />
        )}

        {phase === "scanning" && (
          <ProcessPanel
            title="Scanning privacy surface"
            meta={scanMeta ? `${scanMeta.name} · ${scanMeta.size} · Scanning privacy surface…` : ""}
            steps={scanSteps}
            stepIndex={stepIndex}
            progress={progress}
            variant="scan"
          />
        )}

        {phase === "analysis" && scan && (
          <Analysis
            scan={scan}
            filter={filter}
            setFilter={setFilter}
            filteredSignals={filteredSignals}
            categoryCounts={categoryCounts}
            openSignal={openSignal}
            setOpenSignal={setOpenSignal}
            mode={mode}
            setMode={setMode}
            onProtect={runProtect}
          />
        )}

        {phase === "protecting" && scan && (
          <ProcessPanel
            title="Applying protection"
            meta={`${scan.fileName} · ${scan.fileSize} · Transforming ${scan.signals.length} signals…`}
            steps={protectSteps}
            stepIndex={stepIndex}
            progress={progress}
            variant="protect"
          />
        )}

        {phase === "protected" && scan && (
          <Protected
            scan={scan}
            mode={mode}
            setMode={setMode}
            view={view}
            setView={setView}
            protectedText={protectedText}
            onDownload={download}
            onReset={reset}
          />
        )}
      </div>

      <input
        ref={fileRef}
        type="file"
        accept=".pdf,.docx,.txt"
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0]
          if (f) validateAndScan(f)
          e.currentTarget.value = ""
        }}
      />

      {modal && <Modal kind={modal} onClose={() => setModal(null)} />}
    </main>
  )
}

/* -------------------------------------------------------------------------- */
/*  BACKDROP + KEYFRAMES                                                       */
/* -------------------------------------------------------------------------- */

function Backdrop() {
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 z-0 overflow-hidden">
      {/* deep base wash */}
      <div className="absolute inset-0 bg-[#0a0518]" />

      {/* slow-drifting saturated color field — the moving background */}
      <div
        className="absolute inset-[-30%]"
        style={{
          background:
            "radial-gradient(42% 48% at 18% 22%, rgba(217,70,239,0.6), transparent 62%)," +
            "radial-gradient(40% 46% at 84% 16%, rgba(59,130,246,0.55), transparent 62%)," +
            "radial-gradient(50% 54% at 66% 80%, rgba(139,92,246,0.6), transparent 64%)," +
            "radial-gradient(38% 42% at 10% 84%, rgba(236,72,153,0.5), transparent 62%)",
          filter: "blur(40px)",
          animation: "pl-aurora 22s ease-in-out infinite alternate",
        }}
      />

      {/* second counter-drifting layer for iridescent blending */}
      <div
        className="absolute inset-[-30%] mix-blend-screen"
        style={{
          background:
            "radial-gradient(36% 40% at 72% 30%, rgba(99,102,241,0.5), transparent 60%)," +
            "radial-gradient(34% 38% at 26% 62%, rgba(232,121,249,0.45), transparent 60%)," +
            "radial-gradient(40% 44% at 88% 74%, rgba(56,189,248,0.4), transparent 62%)",
          filter: "blur(50px)",
          animation: "pl-aurora2 28s ease-in-out infinite alternate",
        }}
      />

      {/* floating glow orbs */}
      <div
        className="absolute h-[380px] w-[380px] rounded-full mix-blend-screen"
        style={{
          left: "6%",
          top: "16%",
          background: "radial-gradient(closest-side, rgba(232,121,249,0.5), transparent)",
          filter: "blur(30px)",
          animation: "pl-float1 16s ease-in-out infinite",
        }}
      />
      <div
        className="absolute h-[320px] w-[320px] rounded-full mix-blend-screen"
        style={{
          right: "5%",
          top: "40%",
          background: "radial-gradient(closest-side, rgba(96,165,250,0.45), transparent)",
          filter: "blur(30px)",
          animation: "pl-float2 19s ease-in-out infinite",
        }}
      />

      {/* subtle film grain to smooth the gradient banding */}
      <div
        className="absolute inset-0 opacity-[0.06] mix-blend-overlay"
        style={{
          backgroundImage:
            "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='3'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E\")",
        }}
      />

      {/* vignette to keep content legible */}
      <div
        className="absolute inset-0"
        style={{ background: "radial-gradient(ellipse 120% 82% at 50% 42%, transparent 48%, rgba(8,4,20,0.9))" }}
      />
    </div>
  )
}

function Keyframes() {
  return (
    <style>{`
      @keyframes pl-sweep { 0%{transform:translateY(-100%)} 100%{transform:translateY(1400%)} }
      @keyframes pl-scanline { 0%{top:0%} 100%{top:100%} }
      @keyframes pl-fade { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
      @keyframes pl-pulse { 0%,100%{opacity:0.5} 50%{opacity:1} }
      @keyframes pl-aurora {
        0%   { transform: translate3d(-4%, -2%, 0) rotate(0deg) scale(1.05); }
        50%  { transform: translate3d(3%, 2%, 0) rotate(8deg) scale(1.18); }
        100% { transform: translate3d(-2%, 4%, 0) rotate(-6deg) scale(1.08); }
      }
      @keyframes pl-aurora2 {
        0%   { transform: translate3d(3%, 4%, 0) rotate(0deg) scale(1.1); }
        50%  { transform: translate3d(-4%, -3%, 0) rotate(-10deg) scale(1.22); }
        100% { transform: translate3d(2%, -2%, 0) rotate(6deg) scale(1.12); }
      }
      @keyframes pl-float1 {
        0%,100% { transform: translate3d(0,0,0) scale(1); }
        50%     { transform: translate3d(40px,-30px,0) scale(1.12); }
      }
      @keyframes pl-float2 {
        0%,100% { transform: translate3d(0,0,0) scale(1); }
        50%     { transform: translate3d(-36px,28px,0) scale(1.1); }
      }
      @keyframes pl-shimmer {
        0% { background-position: 0% 50%; }
        100% { background-position: 200% 50%; }
      }
      .pl-fade{animation:pl-fade .5s ease both}
      .pl-gradient-text {
        background: linear-gradient(100deg, #f5f3ff 0%, #c4b5fd 35%, #a78bfa 55%, #f5f3ff 90%);
        background-size: 200% auto;
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent;
        animation: pl-shimmer 6s linear infinite;
      }
      @media (prefers-reduced-motion: reduce) {
        .pl-fade, .pl-gradient-text { animation: none !important; }
      }
    `}</style>
  )
}

/* -------------------------------------------------------------------------- */
/*  TOP NAV                                                                    */
/* -------------------------------------------------------------------------- */

function LensMark() {
  return (
    <span className="relative inline-flex h-8 w-8 items-center justify-center rounded-md border border-white/10 bg-white/[0.03]">
      <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none">
        <circle cx="10" cy="10" r="6.2" stroke="#a78bfa" strokeWidth="1.6" />
        <circle cx="10" cy="10" r="2.4" stroke="#a78bfa" strokeWidth="1.6" />
        <path d="M14.6 14.6L20 20" stroke="#e4e4e7" strokeWidth="1.6" strokeLinecap="round" />
      </svg>
    </span>
  )
}

function TopNav({
  phase,
  onReset,
  onOpen,
}: {
  phase: Phase
  onReset: () => void
  onOpen: (m: "how" | "privacy" | "about") => void
}) {
  return (
    <header className="sticky top-0 z-30 border-b border-white/[0.08] bg-[#0a0518]/60 backdrop-blur-xl">
      <div className="mx-auto flex w-full max-w-5xl items-center justify-between px-5 py-3.5 sm:px-8">
        <button onClick={onReset} className="group flex items-center gap-2.5">
          <LensMark />
          <span className="flex flex-col items-start leading-none">
            <span className="text-[13px] font-semibold tracking-tight text-white">PrivacyLens</span>
            <span className="font-mono text-[9px] uppercase tracking-[0.18em] text-zinc-500">Intelligence</span>
          </span>
        </button>

        <nav className="flex items-center gap-1">
          {(["how", "privacy", "about"] as const).map((k) => (
            <button
              key={k}
              onClick={() => onOpen(k)}
              className="hidden rounded-md px-3 py-1.5 text-[12.5px] text-zinc-400 transition-colors hover:text-white sm:inline-block"
            >
              {k === "how" ? "How it works" : k === "privacy" ? "Privacy" : "About"}
            </button>
          ))}
          {phase !== "idle" && (
            <button
              onClick={onReset}
              className="ml-1 inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/[0.03] px-3 py-1.5 text-[12.5px] font-medium text-zinc-200 transition-colors hover:border-white/20 hover:bg-white/[0.06]"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              New analysis
            </button>
          )}
        </nav>
      </div>
    </header>
  )
}

/* -------------------------------------------------------------------------- */
/*  HERO / DROPZONE (IDLE)                                                     */
/* -------------------------------------------------------------------------- */

function Hero({
  dragging,
  error,
  onBrowse,
  onSample,
  onDragState,
  onFile,
}: {
  dragging: boolean
  error: string | null
  onBrowse: () => void
  onSample: () => void
  onDragState: (b: boolean) => void
  onFile: (f: File) => void
}) {
  return (
    <section className="pl-fade pt-8 sm:pt-16">
        <div className="mx-auto max-w-3xl text-center">
          <span className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-white/[0.03] px-3 py-1 font-mono text-[10px] uppercase tracking-[0.2em] text-violet-300/90">
            <span className="h-1.5 w-1.5 rounded-full bg-violet-400" style={{ animation: "pl-pulse 2s infinite" }} />
            Local-first privacy analysis
          </span>
          <h1 className="mt-7 text-balance font-display text-5xl font-extrabold leading-[0.95] tracking-[-0.03em] text-white sm:text-7xl">
            Know what your{" "}
            <span className="pl-gradient-text">document reveals.</span>
          </h1>
          <p className="mx-auto mt-6 max-w-xl text-pretty text-[15px] leading-relaxed text-zinc-400">
            Privacy intelligence for the documents you share. Detect sensitive information, understand the risk, and
            create a safer version before it leaves your hands.
          </p>
        </div>

      {/* Dropzone */}
      <div
        onDragOver={(e) => {
          e.preventDefault()
          onDragState(true)
        }}
        onDragLeave={() => onDragState(false)}
        onDrop={(e) => {
          e.preventDefault()
          onDragState(false)
          const f = e.dataTransfer.files?.[0]
          if (f) onFile(f)
        }}
        className={`group relative mx-auto mt-10 max-w-2xl overflow-hidden rounded-xl border bg-white/[0.015] p-10 transition-colors sm:p-14 ${
          dragging ? "border-violet-400/50 bg-violet-500/[0.04]" : "border-white/[0.1]"
        }`}
      >
        <Crosshairs />
        {/* laser sweep on hover */}
        <div className="pointer-events-none absolute inset-x-0 top-0 h-full opacity-0 transition-opacity duration-300 group-hover:opacity-100">
          <div
            className="absolute inset-x-8 h-px bg-gradient-to-r from-transparent via-violet-400/70 to-transparent"
            style={{ animation: "pl-scanline 2.2s ease-in-out infinite" }}
          />
        </div>

        <div className="relative flex flex-col items-center text-center">
          <span className="mb-5 inline-flex h-14 w-14 items-center justify-center rounded-xl border border-white/[0.08] bg-white/[0.03]">
            <FileText className="h-6 w-6 text-violet-300" />
          </span>
          <p className="text-[15px] font-medium text-zinc-100">Drop your document here or browse files</p>
          <button
            onClick={onBrowse}
            className="mt-5 inline-flex items-center gap-2 rounded-lg bg-white px-4 py-2 text-[13px] font-semibold text-[#050505] transition-transform hover:scale-[1.02] active:scale-95"
          >
            <Upload className="h-3.5 w-3.5" />
            Browse files
          </button>
          <p className="mt-5 font-mono text-[10px] uppercase tracking-[0.16em] text-zinc-500">
            PDF · DOCX · TXT — Maximum 10 MB
          </p>
        </div>
      </div>

      {/* Sample doc CTA */}
      <div className="mx-auto mt-4 flex max-w-2xl justify-center">
        <button
          onClick={onSample}
          className="inline-flex items-center gap-2 rounded-lg border border-violet-400/25 bg-violet-500/[0.06] px-4 py-2.5 text-[13px] font-medium text-violet-200 transition-colors hover:border-violet-400/40 hover:bg-violet-500/[0.1]"
        >
          <Scan className="h-4 w-4" />
          Try with sample document
          <span className="font-mono text-[10px] uppercase tracking-wider text-violet-300/70">
            Executive Resume — 8 signals
          </span>
          <ArrowRight className="h-3.5 w-3.5" />
        </button>
      </div>

      {error && (
        <div className="mx-auto mt-5 flex max-w-2xl items-start gap-2.5 rounded-lg border border-rose-400/25 bg-rose-500/[0.07] px-4 py-3 text-[13px] text-rose-200">
          <Info className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <FeatureRow />
    </section>
  )
}

function Crosshairs() {
  const base = "absolute h-4 w-4 border-violet-400/40"
  return (
    <>
      <span className={`${base} left-3 top-3 border-l border-t`} />
      <span className={`${base} right-3 top-3 border-r border-t`} />
      <span className={`${base} bottom-3 left-3 border-b border-l`} />
      <span className={`${base} bottom-3 right-3 border-b border-r`} />
    </>
  )
}

function FeatureRow() {
  const items = [
    { icon: Scan, title: "Detect", body: "Local pattern + contextual detection of sensitive signals." },
    { icon: Shield, title: "Understand", body: "A calibrated exposure score with per-signal reasoning." },
    { icon: ShieldCheck, title: "Protect", body: "Redact, mask, or anonymize — then export a safer file." },
  ]
  return (
    <div className="mx-auto mt-14 grid max-w-2xl grid-cols-1 gap-px overflow-hidden rounded-xl border border-white/[0.08] bg-white/[0.04] sm:grid-cols-3">
      {items.map((it) => (
        <div key={it.title} className="bg-[#070707] p-5">
          <it.icon className="h-4 w-4 text-violet-300" />
          <p className="mt-3 text-[13px] font-semibold text-white">{it.title}</p>
          <p className="mt-1 text-[12px] leading-relaxed text-zinc-500">{it.body}</p>
        </div>
      ))}
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/*  PROCESS PANEL (SCANNING / PROTECTING)                                      */
/* -------------------------------------------------------------------------- */

function ProcessPanel({
  title,
  meta,
  steps,
  stepIndex,
  progress,
  variant,
}: {
  title: string
  meta: string
  steps: string[]
  stepIndex: number
  progress: number
  variant: "scan" | "protect"
}) {
  return (
    <section className="pl-fade pt-10 sm:pt-16">
      <div className="mx-auto max-w-3xl">
        <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-violet-300/80">{title}</p>
        <p className="mt-2 text-[13px] text-zinc-400">{meta}</p>

        <div className="mt-6 grid gap-4 sm:grid-cols-[1fr_1.1fr]">
          {/* Document silhouette with laser */}
          <div className="relative aspect-[3/4] overflow-hidden rounded-xl border border-white/[0.1] bg-white/[0.015]">
            <Crosshairs />
            <div className="absolute inset-8 flex flex-col gap-2.5 opacity-40">
              {Array.from({ length: 11 }).map((_, i) => (
                <div key={i} className="h-2 rounded-sm bg-white/10" style={{ width: `${45 + ((i * 37) % 55)}%` }} />
              ))}
            </div>
            <div
              className="absolute inset-x-0 h-16"
              style={{
                background:
                  variant === "scan"
                    ? "linear-gradient(180deg, transparent, rgba(16,185,129,0.35), transparent)"
                    : "linear-gradient(180deg, transparent, rgba(16,185,129,0.25), transparent)",
                animation: "pl-scanline 1.6s ease-in-out infinite",
              }}
            />
            <div className="absolute inset-x-0 top-0 h-px bg-violet-400/60" style={{ animation: "pl-scanline 1.6s ease-in-out infinite" }} />
          </div>

          {/* Steps + meter */}
          <div className="rounded-xl border border-white/[0.1] bg-white/[0.015] p-5">
            <div className="mb-4 flex items-center justify-between">
              <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-zinc-500">Progress</span>
              <span className="font-mono text-[11px] tabular-nums text-violet-300">{Math.round(progress)}%</span>
            </div>
            <div className="h-1 w-full overflow-hidden rounded-full bg-white/[0.06]">
              <div
                className="h-full rounded-full bg-violet-400 transition-all duration-150"
                style={{ width: `${progress}%` }}
              />
            </div>

            <ul className="mt-6 space-y-3">
              {steps.map((s, i) => {
                const done = i < stepIndex
                const active = i === stepIndex
                return (
                  <li key={s} className="flex items-center gap-3">
                    <span
                      className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full border text-[10px] ${
                        done
                          ? "border-violet-400/40 bg-violet-500/15 text-violet-300"
                          : active
                            ? "border-violet-400/40 text-violet-300"
                            : "border-white/10 text-zinc-600"
                      }`}
                    >
                      {done ? <Check className="h-3 w-3" /> : active ? <Loader2 className="h-3 w-3 animate-spin" /> : "→"}
                    </span>
                    <span
                      className={`text-[13px] ${done ? "text-zinc-300" : active ? "text-white" : "text-zinc-600"}`}
                    >
                      {s}
                    </span>
                  </li>
                )
              })}
            </ul>
          </div>
        </div>
      </div>
    </section>
  )
}

/* -------------------------------------------------------------------------- */
/*  ANALYSIS                                                                   */
/* -------------------------------------------------------------------------- */

function Analysis({
  scan,
  filter,
  setFilter,
  filteredSignals,
  categoryCounts,
  openSignal,
  setOpenSignal,
  mode,
  setMode,
  onProtect,
}: {
  scan: ScanResult
  filter: Category | "ALL"
  setFilter: (c: Category | "ALL") => void
  filteredSignals: Signal[]
  categoryCounts: Record<string, number>
  openSignal: number | null
  setOpenSignal: (n: number | null) => void
  mode: Mode
  setMode: (m: Mode) => void
  onProtect: () => void
}) {
  return (
    <section className="pl-fade">
      {/* Report header */}
      <div className="mt-4 flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-white/[0.08] pb-4">
        <FileText className="h-4 w-4 text-zinc-500" />
        <span className="text-[14px] font-medium text-white">{scan.fileName}</span>
        <span className="font-mono text-[11px] text-zinc-500">{scan.fileSize}</span>
        <span className="flex items-center gap-1.5 font-mono text-[10px] text-zinc-600">
          <Fingerprint className="h-3 w-3" />
          <span className="max-w-[220px] truncate sm:max-w-none">SHA-256 {scan.hash.slice(0, 24)}…</span>
        </span>
      </div>

      {/* Score centerpiece */}
      <div className="mt-8 grid gap-6 sm:grid-cols-[auto_1fr] sm:items-center">
        <div className="flex items-end gap-3">
          <span className="font-display text-[84px] font-extrabold leading-none tracking-[-0.04em] text-white sm:text-[104px]">
            {scan.score}
          </span>
          <span className="mb-3 font-mono text-[13px] text-zinc-500">/ 100</span>
        </div>
        <div>
          <span className="inline-flex items-center gap-1.5 rounded-md border border-rose-400/25 bg-rose-500/10 px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.16em] text-rose-300">
            <span className="h-1.5 w-1.5 rounded-full bg-rose-400" />
            {scan.status}
          </span>
          <p className="mt-3 max-w-md text-pretty text-[15px] leading-relaxed text-zinc-300">{scan.narrative}</p>
        </div>
      </div>

      {/* Data ledger */}
      <div className="mt-8 grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-white/[0.08] bg-white/[0.04] sm:grid-cols-6">
        <Stat label="Total signals" value={String(scan.signals.length)} accent />
        {CATEGORIES.map((c) => (
          <Stat key={c} label={c} value={String(categoryCounts[c] ?? 0)} />
        ))}
      </div>

      {/* Filter pills */}
      <div className="mt-6 flex flex-wrap gap-2">
        <Pill active={filter === "ALL"} onClick={() => setFilter("ALL")}>
          All ({scan.signals.length})
        </Pill>
        {CATEGORIES.map((c) => (
          <Pill key={c} active={filter === c} onClick={() => setFilter(c)}>
            {c} ({categoryCounts[c] ?? 0})
          </Pill>
        ))}
      </div>

      {/* Signals list */}
      <div className="mt-4 divide-y divide-white/[0.06] overflow-hidden rounded-xl border border-white/[0.08] bg-white/[0.012]">
        {filteredSignals.map((s) => (
          <SignalRow key={s.index} signal={s} open={openSignal === s.index} onToggle={() => setOpenSignal(openSignal === s.index ? null : s.index)} />
        ))}
      </div>

      {/* Protection controls */}
      <div className="mt-12">
          <h2 className="text-balance font-display text-3xl font-bold tracking-[-0.02em] text-white">Ready to make this document safer?</h2>
        <p className="mt-1.5 font-mono text-[10px] uppercase tracking-[0.18em] text-violet-300/80">Choose protection method</p>

        <div className="mt-5 grid gap-3 sm:grid-cols-3">
          <MethodCard
            active={mode === "REDACT"}
            onClick={() => setMode("REDACT")}
            title="Redact"
            desc="Complete removal of the sensitive value."
            example="[PERSON REDACTED]"
          />
          <MethodCard
            active={mode === "MASK"}
            onClick={() => setMode("MASK")}
            title="Mask"
            desc="Format-preserving obfuscation of the value."
            example="98*****210"
          />
          <MethodCard
            active={mode === "ANONYMIZE"}
            onClick={() => setMode("ANONYMIZE")}
            title="Anonymize"
            desc="Synthetic, realistic pseudonymization."
            example="Alex Morgan"
          />
        </div>

        <button
          onClick={onProtect}
            className="group mt-6 inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-violet-500 to-fuchsia-500 px-5 py-2.5 text-[13px] font-semibold text-white shadow-[0_0_24px_-4px_rgba(139,92,246,0.7)] transition-transform hover:scale-[1.02] active:scale-95"
        >
          <Lock className="h-4 w-4" />
          Protect document
          <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
        </button>
      </div>
    </section>
  )
}

function Stat({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div className="bg-[#070707] p-4">
      <p className={`text-2xl font-semibold tracking-tight ${accent ? "text-violet-300" : "text-white"}`}>{value}</p>
      <p className="mt-1 font-mono text-[9px] uppercase tracking-[0.14em] text-zinc-500">{label}</p>
    </div>
  )
}

function Pill({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full border px-3 py-1.5 text-[12px] transition-colors ${
        active
          ? "border-violet-400/40 bg-violet-500/10 text-violet-200"
          : "border-white/10 bg-white/[0.02] text-zinc-400 hover:border-white/20 hover:text-zinc-200"
      }`}
    >
      {children}
    </button>
  )
}

function SignalRow({ signal, open, onToggle }: { signal: Signal; open: boolean; onToggle: () => void }) {
  return (
    <div>
      <button onClick={onToggle} className="flex w-full items-center gap-4 px-4 py-3.5 text-left transition-colors hover:bg-white/[0.02]">
        <span className="font-mono text-[11px] tabular-nums text-zinc-600">{String(signal.index).padStart(2, "0")}</span>
        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-zinc-500 w-20 shrink-0">{signal.type}</span>
        <span className="min-w-0 flex-1 truncate font-mono text-[13px] text-zinc-100">{signal.value}</span>
        <span className="hidden font-mono text-[10px] uppercase tracking-wider text-zinc-500 sm:inline">{signal.category}</span>
        <span className={`rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider ${severityClasses(signal.severity)}`}>
          {signal.severity}
        </span>
        <ChevronDown className={`h-4 w-4 shrink-0 text-zinc-500 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <div className="pl-fade grid gap-5 border-t border-white/[0.06] bg-white/[0.012] px-4 py-5 sm:grid-cols-2">
          <div>
            <Label>Why this matters</Label>
            <p className="mt-1.5 text-[13px] leading-relaxed text-zinc-300">{signal.why}</p>
            <Label className="mt-4">Recommended action</Label>
            <span className="mt-1.5 inline-flex items-center gap-1.5 rounded-md border border-violet-400/30 bg-violet-500/10 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-violet-200">
              <ShieldCheck className="h-3 w-3" />
              {signal.recommended}
            </span>
          </div>
          <div>
            <Label>Potential exposure</Label>
            <ul className="mt-1.5 space-y-1.5">
              {signal.exposure.map((e) => (
                <li key={e} className="flex items-start gap-2 text-[13px] leading-relaxed text-zinc-400">
                  <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-rose-400/70" />
                  {e}
                </li>
              ))}
            </ul>
            <Label className="mt-4">Document context</Label>
            <p className="mt-1.5 rounded-md border border-white/[0.06] bg-black/40 px-3 py-2 font-mono text-[11px] leading-relaxed text-zinc-500">
              {signal.context}
            </p>
          </div>
        </div>
      )}
    </div>
  )
}

function Label({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <p className={`font-mono text-[9px] uppercase tracking-[0.16em] text-zinc-500 ${className}`}>{children}</p>
}

function MethodCard({
  active,
  onClick,
  title,
  desc,
  example,
}: {
  active: boolean
  onClick: () => void
  title: string
  desc: string
  example: string
}) {
  return (
    <button
      onClick={onClick}
      className={`relative rounded-xl border p-4 text-left transition-all ${
        active
          ? "border-violet-400/50 bg-violet-500/[0.05] ring-1 ring-violet-400/30"
          : "border-white/[0.1] bg-white/[0.012] hover:border-white/20"
      }`}
    >
      <div className="flex items-center justify-between">
        <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-zinc-400">{title}</span>
        <span
          className={`flex h-4 w-4 items-center justify-center rounded-full border ${
            active ? "border-violet-400 bg-violet-400 text-[#050505]" : "border-white/20"
          }`}
        >
          {active && <Check className="h-2.5 w-2.5" />}
        </span>
      </div>
      <p className="mt-2 text-[13px] leading-relaxed text-zinc-400">{desc}</p>
      <p className="mt-3 rounded-md border border-white/[0.06] bg-black/40 px-2.5 py-1.5 font-mono text-[12px] text-violet-200">
        {example}
      </p>
    </button>
  )
}

/* -------------------------------------------------------------------------- */
/*  PROTECTED (BEFORE / AFTER)                                                 */
/* -------------------------------------------------------------------------- */

function Protected({
  scan,
  mode,
  setMode,
  view,
  setView,
  protectedText,
  onDownload,
  onReset,
}: {
  scan: ScanResult
  mode: Mode
  setMode: (m: Mode) => void
  view: "document" | "ledger"
  setView: (v: "document" | "ledger") => void
  protectedText: string
  onDownload: () => void
  onReset: () => void
}) {
  return (
    <section className="pl-fade">
      {/* Success banner */}
      <div className="mt-4 flex items-start gap-3 rounded-xl border border-violet-400/25 bg-violet-500/[0.06] px-4 py-3.5">
        <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-violet-300" />
        <div>
          <p className="text-[14px] font-medium text-white">Your document is safer to share.</p>
          <p className="text-[13px] text-violet-200/80">Privacy protection complete.</p>
        </div>
        <span className="ml-auto hidden rounded-md border border-violet-400/25 bg-violet-500/10 px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider text-violet-200 sm:inline-flex">
          {scan.signals.length} signals neutralized
        </span>
      </div>

      {/* Controls */}
      <div className="mt-6 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-1 rounded-lg border border-white/[0.08] bg-white/[0.02] p-1">
          {(["document", "ledger"] as const).map((v) => (
            <button
              key={v}
              onClick={() => setView(v)}
              className={`rounded-md px-3 py-1.5 text-[12px] font-medium capitalize transition-colors ${
                view === v ? "bg-white/[0.08] text-white" : "text-zinc-500 hover:text-zinc-300"
              }`}
            >
              {v}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">Live mode</span>
          <div className="flex items-center gap-1 rounded-lg border border-white/[0.08] bg-white/[0.02] p-1">
            {(["REDACT", "MASK", "ANONYMIZE"] as const).map((m) => (
              <button
                key={m}
                onClick={() => setMode(m)}
                className={`rounded-md px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider transition-colors ${
                  mode === m ? "bg-violet-500 text-[#050505]" : "text-zinc-500 hover:text-zinc-300"
                }`}
              >
                {m}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Split view */}
      {view === "document" ? (
        <div className="mt-4 grid gap-3 lg:grid-cols-2">
          <DocPane label="Original" tone="unsafe" scan={scan} mode={mode} />
          <DocPane label="Protected" tone="safe" scan={scan} mode={mode} protectedText={protectedText} />
        </div>
      ) : (
        <LedgerTable scan={scan} mode={mode} />
      )}

      {/* Actions */}
      <div className="mt-8 flex flex-wrap items-center gap-3">
        <button
          onClick={onDownload}
            className="group inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-violet-500 to-fuchsia-500 px-5 py-2.5 text-[13px] font-semibold text-white shadow-[0_0_24px_-4px_rgba(139,92,246,0.7)] transition-transform hover:scale-[1.02] active:scale-95"
        >
          <Download className="h-4 w-4" />
          Download protected document
          <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
        </button>
        <button
          onClick={() => setView("document")}
          className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.02] px-4 py-2.5 text-[13px] font-medium text-zinc-200 transition-colors hover:border-white/20"
        >
          <Eye className="h-4 w-4" />
          View before / after
        </button>
        <button
          onClick={onReset}
          className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.02] px-4 py-2.5 text-[13px] font-medium text-zinc-200 transition-colors hover:border-white/20"
        >
          <RotateCcw className="h-4 w-4" />
          Scan another document
        </button>
      </div>
    </section>
  )
}

function DocPane({
  label,
  tone,
  scan,
  mode,
  protectedText,
}: {
  label: string
  tone: "safe" | "unsafe"
  scan: ScanResult
  mode: Mode
  protectedText?: string
}) {
  return (
    <div className={`overflow-hidden rounded-xl border ${tone === "safe" ? "border-violet-400/25" : "border-white/[0.1]"}`}>
      <div
        className={`flex items-center justify-between border-b px-4 py-2.5 ${
          tone === "safe" ? "border-violet-400/20 bg-violet-500/[0.05]" : "border-white/[0.08] bg-white/[0.02]"
        }`}
      >
        <span className={`font-mono text-[10px] uppercase tracking-[0.16em] ${tone === "safe" ? "text-violet-300" : "text-zinc-400"}`}>
          {label}
        </span>
        {tone === "safe" ? (
          <ShieldCheck className="h-3.5 w-3.5 text-violet-300" />
        ) : (
          <span className="font-mono text-[9px] uppercase tracking-wider text-rose-300/80">Unsafe</span>
        )}
      </div>
      <div className="bg-black/40 p-4">
        {tone === "unsafe" ? (
          <HighlightedOriginal scan={scan} />
        ) : (
          <pre className="whitespace-pre-wrap break-words font-mono text-[12px] leading-relaxed text-violet-100/90">
            {protectedText}
          </pre>
        )}
        <p className="mt-3 font-mono text-[9px] uppercase tracking-wider text-zinc-600">
          {tone === "safe" ? `Method · ${mode}` : "Contains sensitive values"}
        </p>
      </div>
    </div>
  )
}

function HighlightedOriginal({ scan }: { scan: ScanResult }) {
  // Split the original text and wrap each detected value with a highlight.
  const values = scan.signals.map((s) => s.value)
  const pattern = new RegExp(`(${values.map((v) => v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`, "g")
  const parts = scan.originalText.split(pattern)
  return (
    <pre className="whitespace-pre-wrap break-words font-mono text-[12px] leading-relaxed text-zinc-400">
      {parts.map((p, i) =>
        values.includes(p) ? (
          <mark key={i} className="rounded-sm bg-rose-500/20 px-0.5 text-rose-200">
            {p}
          </mark>
        ) : (
          <span key={i}>{p}</span>
        ),
      )}
    </pre>
  )
}

function LedgerTable({ scan, mode }: { scan: ScanResult; mode: Mode }) {
  return (
    <div className="mt-4 overflow-hidden rounded-xl border border-white/[0.08]">
      <div className="grid grid-cols-[auto_1fr_1fr] gap-px bg-white/[0.05] font-mono text-[9px] uppercase tracking-[0.14em] text-zinc-500">
        <div className="bg-[#070707] px-4 py-2.5">Type</div>
        <div className="bg-[#070707] px-4 py-2.5">Original</div>
        <div className="bg-[#070707] px-4 py-2.5">Protected · {mode}</div>
      </div>
      <div className="divide-y divide-white/[0.06]">
        {scan.signals.map((s) => (
          <div key={s.index} className="grid grid-cols-[auto_1fr_1fr]">
            <div className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-wider text-zinc-500">{s.type}</div>
            <div className="px-4 py-2.5 font-mono text-[12px] text-rose-200/90 line-through decoration-rose-400/40">{s.value}</div>
            <div className="px-4 py-2.5 font-mono text-[12px] text-violet-200">{s.transforms[mode]}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/*  MODAL                                                                      */
/* -------------------------------------------------------------------------- */

function Modal({ kind, onClose }: { kind: "how" | "privacy" | "about"; onClose: () => void }) {
  const content = {
    how: {
      title: "How it works",
      body: [
        "PrivacyLens analyzes a document in three stages: detection, scoring, and protection.",
        "Detection combines local pattern matching (emails, phones, IDs, cards) with contextual understanding of higher-risk signals like addresses and health data.",
        "Each signal is scored for severity and rolled up into a single 0–100 exposure score with plain-language reasoning.",
        "You then choose a protection method — redact, mask, or anonymize — and export a safer version of the file.",
      ],
    },
    privacy: {
      title: "Privacy",
      body: [
        "This demo runs entirely in your browser. No document contents are uploaded or stored by PrivacyLens.",
        "In production, analysis can run against a local-first engine or a self-hosted FastAPI backend you control.",
        "Detected values never leave your device unless you explicitly export the protected output.",
      ],
    },
    about: {
      title: "About",
      body: [
        "PrivacyLens Intelligence is a privacy-analysis MVP built for a hackathon.",
        "It demonstrates an end-to-end workflow: scan → understand → protect → export.",
        "The intelligence layer is mocked for the demo and is designed to swap cleanly to a real API via NEXT_PUBLIC_API_URL.",
      ],
    },
  }[kind]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true">
      <button aria-label="Close" onClick={onClose} className="absolute inset-0 bg-black/70 backdrop-blur-sm" />
      <div className="pl-fade relative w-full max-w-lg overflow-hidden rounded-2xl border border-white/[0.1] bg-[#0a0a0a] p-6">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-2.5">
            <LensMark />
            <h3 className="text-[15px] font-semibold tracking-tight text-white">{content.title}</h3>
          </div>
          <button onClick={onClose} className="rounded-md p-1 text-zinc-500 transition-colors hover:bg-white/[0.06] hover:text-white">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="mt-4 space-y-3">
          {content.body.map((p, i) => (
            <p key={i} className="text-[13px] leading-relaxed text-zinc-400">
              {p}
            </p>
          ))}
        </div>
      </div>
    </div>
  )
}
