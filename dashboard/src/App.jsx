import { useState } from 'react'
import { scanGitHubRepo, checkOnChainProgram, PATTERNS } from './scanner.js'
import { REPORT } from './reportData.js'

const SEVERITY_COLORS = {
  Critical: '#FF4444',
  High: '#FF6B35',
  Medium: '#FFA500',
  Low: '#00C853',
}

const SEVERITY_BG = {
  Critical: 'rgba(255,68,68,0.15)',
  High: 'rgba(255,107,53,0.15)',
  Medium: 'rgba(255,165,0,0.15)',
  Low: 'rgba(0,200,83,0.15)',
}

const STATUS_STYLES = {
  SIMULATED: { color: '#14F195', bg: 'rgba(20,241,149,0.15)', label: 'SIMULATED' },
  CONFIRMED: { color: '#14F195', bg: 'rgba(20,241,149,0.15)', label: 'CONFIRMED' },
  GENERATED: { color: '#FFA500', bg: 'rgba(255,165,0,0.15)', label: 'GENERATED' },
  FAILED: { color: '#FF4444', bg: 'rgba(255,68,68,0.15)', label: 'FAILED' },
}

function Header({ activeTab, setActiveTab }) {
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'semantic', label: 'Semantic Analysis' },
    { id: 'exploits', label: 'Exploits' },
    { id: 'static', label: 'Static Scanner' },
  ]

  return (
    <header className="border-b border-gray-800">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 py-4 flex items-center gap-3 flex-wrap">
        <div className="text-xl sm:text-2xl">
          <span className="font-bold" style={{ color: '#9945FF' }}>anchor</span>
          <span className="font-bold text-gray-300">-shield</span>
        </div>
        <span className="text-xs px-2 py-0.5 rounded" style={{ background: '#9945FF22', color: '#9945FF' }}>
          v0.3.0
        </span>
        <span className="text-xs px-2 py-0.5 rounded" style={{ background: '#14F19522', color: '#14F195' }}>
          Adversarial
        </span>
        <div className="ml-auto text-sm text-gray-500 hidden sm:block">
          Adversarial Security Agent for Solana
        </div>
      </div>
      <div className="max-w-6xl mx-auto px-4 sm:px-6 flex gap-1 overflow-x-auto">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className="px-3 sm:px-4 py-2.5 text-sm font-medium transition-all rounded-t-lg whitespace-nowrap"
            style={{
              color: activeTab === tab.id ? '#E0E0E0' : '#666',
              background: activeTab === tab.id ? '#1A1D2E' : 'transparent',
              borderBottom: activeTab === tab.id ? '2px solid #9945FF' : '2px solid transparent',
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>
    </header>
  )
}

/* ── Overview Tab ── */
function OverviewTab() {
  const s = REPORT.summary
  const findings = REPORT.semantic_analysis.findings

  return (
    <div className="space-y-6">
      {/* Hero comparison */}
      <div className="rounded-xl p-4 sm:p-6" style={{ background: 'linear-gradient(135deg, #1A1D2E 0%, #252836 100%)' }}>
        <h2 className="text-lg font-semibold mb-4 text-gray-300">Analysis Comparison</h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <ComparisonCard
            title="Regex Scanner"
            icon="1"
            color="#666"
            value={s.static_pattern_matches}
            subtitle="pattern matches"
            detail="0 logic bugs detected"
          />
          <ComparisonCard
            title="Semantic LLM"
            icon="2"
            color="#9945FF"
            value={s.logic_bugs_by_llm}
            subtitle="logic vulnerabilities"
            detail={`${findings.filter(f => f.severity === 'Critical').length} Critical, ${findings.filter(f => f.severity === 'High').length} High`}
          />
          <ComparisonCard
            title="Bankrun Exploits"
            icon="3"
            color="#14F195"
            value={`${s.bankrun_exploits_confirmed || 0}/${s.exploits_generated}`}
            subtitle="confirmed on SBF binary"
            detail="Real on-chain execution"
          />
        </div>
      </div>

      {/* Key insight */}
      <div className="rounded-xl p-5 border" style={{ background: '#1A1D2E', borderColor: '#9945FF44' }}>
        <div className="flex items-start gap-3">
          <div className="text-2xl mt-0.5" style={{ color: '#FFA500' }}>!</div>
          <div>
            <h3 className="font-semibold text-gray-200 mb-1">
              {s.logic_bugs_missed_by_regex} critical logic bugs invisible to regex
            </h3>
            <p className="text-sm text-gray-400">
              The static pattern scanner found zero of the four logic vulnerabilities in the lending pool.
              These bugs require understanding cross-instruction state relationships — something only
              semantic analysis can detect. Each vulnerability was independently confirmed by an
              automated exploit simulation.
            </p>
          </div>
        </div>
      </div>

      {/* Bug comparison table */}
      <div className="rounded-xl overflow-hidden" style={{ background: '#1A1D2E' }}>
        <div className="p-4 border-b border-gray-800">
          <h3 className="font-semibold text-gray-300">Vulnerability Detection Matrix</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500">
                <th className="text-left p-3 font-medium">#</th>
                <th className="text-left p-3 font-medium">Vulnerability</th>
                <th className="text-left p-3 font-medium">Severity</th>
                <th className="text-center p-3 font-medium">Regex</th>
                <th className="text-center p-3 font-medium">LLM</th>
                <th className="text-center p-3 font-medium">Exploit</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f, i) => {
                const bankrun = REPORT.bankrun_exploits.find(e => e.finding_id === f.id || e.finding_id?.includes(f.id))
                const python = REPORT.python_exploits.find(e => e.finding_id === f.id)
                return (
                  <tr key={f.id} className="border-b border-gray-800/50">
                    <td className="p-3 text-gray-500">{i + 1}</td>
                    <td className="p-3 text-gray-300">{f.title}</td>
                    <td className="p-3">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="p-3 text-center text-red-400">Missed</td>
                    <td className="p-3 text-center" style={{ color: '#14F195' }}>Found</td>
                    <td className="p-3 text-center">
                      {bankrun ? (
                        <span style={{ color: '#14F195' }}>Bankrun</span>
                      ) : python ? (
                        <span style={{ color: '#FFA500' }}>Simulated</span>
                      ) : (
                        <span className="text-gray-600">&mdash;</span>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pipeline flow */}
      <div className="rounded-xl p-5" style={{ background: '#1A1D2E' }}>
        <h3 className="font-semibold text-gray-300 mb-4">Analysis Pipeline</h3>
        <div className="flex flex-col sm:flex-row items-center gap-3 text-sm flex-wrap">
          <PipelineStep step="1" label="Source Code" detail="Anchor .rs files" />
          <PipelineArrow />
          <PipelineStep step="2" label="Static Scan" detail="Regex patterns" color="#666" />
          <PipelineArrow />
          <PipelineStep step="3" label="Semantic Analysis" detail="LLM reasoning" color="#9945FF" />
          <PipelineArrow />
          <PipelineStep step="4" label="Exploit Gen" detail="Auto PoC code" color="#FFA500" />
          <PipelineArrow />
          <PipelineStep step="5" label="Bankrun" detail="SBF binary exec" color="#14F195" />
          <PipelineArrow />
          <PipelineStep step="6" label="Python Sim" detail="Fallback verify" color="#00C853" />
        </div>
      </div>
    </div>
  )
}

function ComparisonCard({ title, icon, color, value, subtitle, detail }) {
  return (
    <div className="rounded-lg p-4 text-center" style={{ background: '#0F1117' }}>
      <div className="text-xs font-semibold mb-2 flex items-center justify-center gap-2">
        <span className="w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold"
          style={{ background: color + '33', color }}>
          {icon}
        </span>
        <span className="text-gray-400">{title}</span>
      </div>
      <div className="text-3xl font-bold mb-1" style={{ color }}>{value}</div>
      <div className="text-xs text-gray-500">{subtitle}</div>
      <div className="text-xs text-gray-600 mt-1">{detail}</div>
    </div>
  )
}

function PipelineStep({ step, label, detail, color = '#444' }) {
  return (
    <div className="flex items-center gap-2 px-3 py-2 rounded-lg" style={{ background: '#0F1117' }}>
      <span className="w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold"
        style={{ background: color + '33', color }}>
        {step}
      </span>
      <div>
        <div className="font-medium text-gray-300">{label}</div>
        <div className="text-xs text-gray-500">{detail}</div>
      </div>
    </div>
  )
}

function PipelineArrow() {
  return <div className="text-gray-600 hidden sm:block">&#10132;</div>
}

/* ── Semantic Analysis Tab ── */
function SemanticTab() {
  const findings = REPORT.semantic_analysis.findings

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-2 flex-wrap">
        <h2 className="text-lg font-semibold text-gray-300">Semantic Analysis Results</h2>
        <span className="text-xs px-2 py-0.5 rounded" style={{ background: '#9945FF22', color: '#9945FF' }}>
          {REPORT.semantic_analysis.model}
        </span>
        {REPORT.semantic_analysis.mode === 'pre-validated' && (
          <span className="text-xs px-2 py-0.5 rounded" style={{ background: '#FFA50022', color: '#FFA500' }}>
            Pre-validated
          </span>
        )}
      </div>
      <p className="text-sm text-gray-500 mb-4">
        The semantic analyzer uses LLM reasoning to detect logic vulnerabilities that regex patterns cannot find.
        Each finding includes a confidence score and step-by-step attack scenario.
      </p>
      {findings.map((f) => (
        <SemanticFindingCard key={f.id} finding={f} />
      ))}
    </div>
  )
}

function SemanticFindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div
      className="rounded-xl overflow-hidden transition-all cursor-pointer"
      style={{ background: '#1A1D2E', borderLeft: `4px solid ${SEVERITY_COLORS[finding.severity]}` }}
      onClick={() => setExpanded(!expanded)}
    >
      <div className="p-4">
        <div className="flex items-start gap-3">
          <SeverityBadge severity={finding.severity} />
          <div className="flex-1 min-w-0">
            <div className="font-semibold text-sm text-gray-200">
              <span className="text-gray-500 font-mono">{finding.id}</span>
              <span className="mx-2 text-gray-700">|</span>
              <span className="font-mono" style={{ color: '#9945FF' }}>{finding.function}()</span>
              <span className="mx-2 text-gray-700">|</span>
              <span className="break-words">{finding.title}</span>
            </div>
            <div className="text-sm text-gray-400 mt-2">{finding.description}</div>
            <div className="flex items-center gap-4 mt-2">
              <ConfidenceBar confidence={finding.confidence} />
              <span className="text-xs text-gray-600">
                {finding.source === 'validated' ? 'Pre-validated' : 'Live analysis'}
              </span>
            </div>
          </div>
          <span className="text-gray-600 text-sm shrink-0">{expanded ? '\u25B2' : '\u25BC'}</span>
        </div>
      </div>
      {expanded && (
        <div className="px-4 pb-4 pt-0">
          <div className="border-t border-gray-800 pt-4 space-y-3">
            <div>
              <div className="text-xs font-semibold mb-2" style={{ color: '#FF4444' }}>Attack Scenario</div>
              <pre className="text-xs p-3 rounded whitespace-pre-wrap overflow-x-auto"
                style={{ background: '#0F1117', color: '#ccc' }}>
                {finding.attack_scenario}
              </pre>
            </div>
            <div>
              <div className="text-xs font-semibold mb-1" style={{ color: '#FFA500' }}>Estimated Impact</div>
              <p className="text-xs text-gray-400">{finding.estimated_impact}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function ConfidenceBar({ confidence }) {
  const pct = Math.round(confidence * 100)
  const color = pct >= 90 ? '#14F195' : pct >= 70 ? '#FFA500' : '#FF4444'
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 rounded-full" style={{ background: '#333' }}>
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="text-xs font-mono" style={{ color }}>{pct}%</span>
    </div>
  )
}

/* ── Exploits Tab ── */
function ExploitsTab() {
  const bankrunExploits = REPORT.bankrun_exploits || []
  const pythonExploits = REPORT.python_exploits || []

  return (
    <div className="space-y-6">
      {/* Bankrun section */}
      <div>
        <div className="flex items-center gap-3 mb-2 flex-wrap">
          <h2 className="text-lg font-semibold text-gray-300">Bankrun Exploits</h2>
          <span className="text-xs px-2 py-0.5 rounded font-bold" style={{ background: '#14F19522', color: '#14F195' }}>
            On-Chain Execution
          </span>
        </div>
        <p className="text-sm text-gray-500 mb-4">
          Exploits executed against the compiled SBF binary via solana-bankrun (in-process Solana runtime).
          These run real BPF instructions — no simulation or mocking.
        </p>
        <div className="grid gap-4">
          {bankrunExploits.map((exploit) => (
            <BankrunExploitCard key={exploit.file} exploit={exploit} />
          ))}
        </div>
      </div>

      {/* Python simulation section */}
      <div>
        <div className="flex items-center gap-3 mb-2 flex-wrap">
          <h2 className="text-lg font-semibold text-gray-300">Python Simulations</h2>
          <span className="text-xs px-2 py-0.5 rounded" style={{ background: '#FFA50022', color: '#FFA500' }}>
            Fallback Verification
          </span>
        </div>
        <p className="text-sm text-gray-500 mb-4">
          Python-based exploit simulations that model on-chain state and reproduce each vulnerability step by step.
          Used as supplementary evidence alongside bankrun confirmation.
        </p>
        <div className="grid gap-4">
          {pythonExploits.map((exploit) => (
            <PythonExploitCard key={exploit.finding_id} exploit={exploit} />
          ))}
        </div>
      </div>
    </div>
  )
}

function BankrunExploitCard({ exploit }) {
  const [showCode, setShowCode] = useState(false)
  const finding = REPORT.semantic_analysis.findings.find(
    f => f.id === exploit.finding_id || exploit.finding_id?.includes(f.id)
  )

  return (
    <div className="rounded-xl overflow-hidden" style={{ background: '#1A1D2E', borderLeft: '4px solid #14F195' }}>
      <div className="p-4">
        <div className="flex items-center gap-3 mb-2 flex-wrap">
          <span className="text-xs px-2 py-0.5 rounded font-bold"
            style={{ background: '#14F19522', color: '#14F195' }}>
            CONFIRMED
          </span>
          <span className="font-mono text-xs text-gray-500">{exploit.finding_id}</span>
          <span className="text-sm font-medium text-gray-300">{exploit.title}</span>
        </div>
        <p className="text-sm text-gray-400 mb-3">{exploit.result}</p>
        {finding && (
          <p className="text-xs text-gray-500 mb-3">{finding.estimated_impact}</p>
        )}
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-xs px-2 py-0.5 rounded" style={{ background: '#252836', color: '#888' }}>
            TypeScript
          </span>
          <span className="text-xs px-2 py-0.5 rounded" style={{ background: '#252836', color: '#888' }}>
            solana-bankrun
          </span>
          <span className="text-xs text-gray-600 font-mono">{exploit.file}</span>
          <button
            onClick={(e) => { e.stopPropagation(); setShowCode(!showCode) }}
            className="ml-auto text-xs px-3 py-1 rounded transition-all"
            style={{ background: '#14F19522', color: '#14F195' }}
          >
            {showCode ? 'Hide Output' : 'View Output'}
          </button>
        </div>
      </div>
      {showCode && (
        <div className="border-t border-gray-800">
          <pre className="text-xs p-4 overflow-x-auto" style={{ background: '#0A0C12', color: '#aaa' }}>
            {getBankrunOutput(exploit.finding_id)}
          </pre>
        </div>
      )}
    </div>
  )
}

function PythonExploitCard({ exploit }) {
  const [showCode, setShowCode] = useState(false)
  const finding = REPORT.semantic_analysis.findings.find(f => f.id === exploit.finding_id)

  return (
    <div className="rounded-xl overflow-hidden" style={{ background: '#1A1D2E' }}>
      <div className="p-4">
        <div className="flex items-center gap-3 mb-2 flex-wrap">
          <span className="text-xs px-2 py-0.5 rounded font-bold"
            style={{ background: '#FFA50022', color: '#FFA500' }}>
            SIMULATED
          </span>
          <span className="font-mono text-xs text-gray-500">{exploit.finding_id}</span>
          <span className="text-sm font-medium text-gray-300">{exploit.title}</span>
        </div>
        {finding && (
          <p className="text-xs text-gray-500 mb-3">{finding.estimated_impact}</p>
        )}
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-xs px-2 py-0.5 rounded" style={{ background: '#252836', color: '#888' }}>
            {exploit.language}
          </span>
          <span className="text-xs text-gray-600 font-mono">{exploit.code_file}</span>
          <button
            onClick={(e) => { e.stopPropagation(); setShowCode(!showCode) }}
            className="ml-auto text-xs px-3 py-1 rounded transition-all"
            style={{ background: '#9945FF22', color: '#9945FF' }}
          >
            {showCode ? 'Hide Code' : 'View Code'}
          </button>
        </div>
      </div>
      {showCode && (
        <div className="border-t border-gray-800">
          <pre className="text-xs p-4 overflow-x-auto" style={{ background: '#0A0C12', color: '#aaa' }}>
            {getPythonExploitCode(exploit.finding_id)}
          </pre>
        </div>
      )}
    </div>
  )
}

function getBankrunOutput(findingId) {
  const outputs = {
    'SEM-001': `Bankrun Exploit: Collateral Check Bypass (SEM-001)
Binary: vuln_lending.so (compiled SBF)

[1] Genesis accounts loaded:
    Pool: deposited=600 SOL, borrows=0
    User: deposited=100 SOL, borrowed=0
    Vault: 600 SOL

[2] Borrowing 100 SOL repeatedly...
    (check is: deposited >= amount, ignores existing debt)

    Borrow #1: 100 SOL (cumulative debt: 100 SOL)
    Borrow #2: 100 SOL (cumulative debt: 200 SOL)
    Borrow #3: 100 SOL (cumulative debt: 300 SOL)
    Borrow #4: 100 SOL (cumulative debt: 400 SOL)
    Borrow #5: 100 SOL (cumulative debt: 500 SOL)

[3] Final state:
    Deposited: 100 SOL | Borrowed: 500 SOL | Debt ratio: 500%

>>> CONFIRMED: Borrowed 500 SOL with 100 SOL collateral <<<`,
    'SEM-002': `Bankrun Exploit: Withdraw Drain (SEM-002)
Binary: vuln_lending.so (compiled SBF)

[1] State: attacker deposited 100 SOL, borrowed 90 SOL
    Pool: deposits=600 SOL, borrows=90 SOL
    Vault: 510 SOL

[2] Withdrawing 100 SOL despite 90 SOL outstanding debt...
    Withdrawal SUCCEEDED (should have been blocked)

[3] Final state:
    Deposited: 0 SOL | Borrowed: 90 SOL | Collateral: 0
    Attacker gained: 100 SOL net (90 SOL stolen)

>>> CONFIRMED: Protocol has 90 SOL bad debt with 0 collateral <<<`,
    'SEM-003/004': `Bankrun Exploit: Overflow + Division by Zero (SEM-003/004)
Binary: vuln_lending.so (compiled SBF)

--- TEST A: Integer Overflow ---
[1] borrowed: 1,000,000,000 lamports
    interest_rate: 500, total_borrows: 36,893,488,147
    Honest interest: 18,446,744,073,500,000,000,000 (overflows u64)
    u64 wrapped:     18,446,743,864,157,935,616

--- TEST B: Division by Zero ---
[2] liquidate with zero-borrow user:
    health = 10,000,000,000 * 100 / (0 + 0) => DIVISION BY ZERO
    Program CRASHED: attempt to divide by zero

>>> CONFIRMED: Division by zero causes program panic <<<`,
  }
  return outputs[findingId] || 'Output not available in dashboard view'
}

function getPythonExploitCode(findingId) {
  const codes = {
    'SEM-001': `# Exploit: Collateral check ignores existing debt
# Demonstrates unlimited borrowing with fixed collateral

pool = Pool(total_deposits=1000)
attacker = UserAccount()

# Step 1: Deposit 100 SOL
deposit(pool, attacker, 100)

# Step 2: Borrow 100 SOL (passes: deposited 100 >= 100)
borrow(pool, attacker, 100)  # debt: 100

# Step 3: Borrow AGAIN (BUG: still passes, ignores existing debt)
borrow(pool, attacker, 100)  # debt: 200

# Step 4: And again...
borrow(pool, attacker, 100)  # debt: 300

# Result: 300 SOL borrowed with only 100 SOL collateral
# Debt ratio: 300% (should be capped at 75%)
assert attacker.borrowed > attacker.deposited
# >>> EXPLOIT CONFIRMED <<<`,
    'SEM-002': `# Exploit: Withdrawal with outstanding borrows
# Demonstrates collateral extraction leaving bad debt

pool = Pool(total_deposits=1000)
attacker = UserAccount()
wallet = 100  # Starting balance

# Step 1: Deposit 100 SOL
deposit(pool, attacker, 100); wallet -= 100

# Step 2: Borrow 90 SOL
borrow(pool, attacker, 90); wallet += 90

# Step 3: Withdraw ALL collateral (BUG: no borrow check)
withdraw(pool, attacker, 100); wallet += 100

# Result: Started with 100, now has 190
# Protocol left with 90 SOL bad debt
assert wallet == 190  # Attacker profited 90 SOL
assert attacker.deposited == 0  # All collateral gone
# >>> EXPLOIT CONFIRMED <<<`,
    'SEM-003': `# Exploit: Integer overflow in interest calculation
# Demonstrates u64 overflow corrupting health factor

U64_MAX = (1 << 64) - 1

pool = Pool(total_borrows=500_000_000_000_000, interest_rate=500)
user = UserAccount(deposited=50e9, borrowed=100e9)

# Correct calculation (Python arbitrary precision)
real_interest = user.borrowed * pool.interest_rate * pool.total_borrows
# = 25,000,000,000,000,000,000,000,000,000

# Vulnerable calculation (u64 wrapping)
wrapped = (int(user.borrowed) * pool.interest_rate
           * pool.total_borrows) & U64_MAX

# Value corruption: 100%
assert real_interest > U64_MAX  # Overflow occurred
assert wrapped != real_interest  # Value is wrong
# >>> EXPLOIT CONFIRMED <<<`,
  }
  return codes[findingId] || '# Exploit code not available in dashboard view\n# Run the pipeline to generate full exploit files'
}

/* ── Static Scanner Tab ── */
function StaticTab() {
  const [input, setInput] = useState('')
  const [mode, setMode] = useState('repo')
  const [results, setResults] = useState(null)
  const [programInfo, setProgramInfo] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleScan = async () => {
    if (!input.trim()) return
    setLoading(true)
    setError(null)
    setResults(null)
    setProgramInfo(null)
    try {
      if (mode === 'program') {
        const info = await checkOnChainProgram(input.trim())
        setProgramInfo(info)
      } else {
        const report = await scanGitHubRepo(input.trim())
        setResults(report)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="rounded-xl p-4 sm:p-6" style={{ background: '#1A1D2E' }}>
        <h2 className="text-lg font-semibold text-gray-300 mb-4">Static Pattern Scanner</h2>
        <p className="text-sm text-gray-500 mb-4">
          Scans GitHub repositories for known Anchor vulnerability patterns.
          Note: this scanner detects structural issues only — logic bugs require the semantic analyzer.
        </p>
        <div className="flex gap-2 mb-4">
          {['repo', 'program'].map((m) => (
            <button key={m} onClick={() => setMode(m)}
              className="px-4 py-1.5 rounded text-sm font-medium transition-all"
              style={{
                background: mode === m ? '#9945FF' : '#252836',
                color: mode === m ? '#fff' : '#666',
              }}>
              {m === 'repo' ? 'GitHub Repo' : 'On-Chain Program'}
            </button>
          ))}
        </div>
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleScan()}
            placeholder={mode === 'repo' ? 'https://github.com/owner/repo' : 'Program ID'}
            className="flex-1 px-4 py-3 rounded-lg text-sm font-mono outline-none"
            style={{ background: '#0F1117', border: '1px solid #333', color: '#E0E0E0' }}
            disabled={loading}
          />
          <button onClick={handleScan} disabled={loading || !input.trim()}
            className="px-6 py-3 rounded-lg font-semibold text-white text-sm disabled:opacity-50"
            style={{ background: 'linear-gradient(135deg, #9945FF, #14F195)' }}>
            {loading ? 'Scanning...' : 'Scan'}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg text-sm" style={{ background: '#FF444422', color: '#FF4444' }}>
          {error}
        </div>
      )}

      {loading && (
        <div className="text-center py-8">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-2 border-gray-600"
            style={{ borderTopColor: '#9945FF' }} />
          <p className="text-gray-500 mt-3 text-sm">Scanning repository...</p>
        </div>
      )}

      {programInfo && (
        <div className="rounded-xl p-5" style={{ background: '#1A1D2E' }}>
          <h3 className="text-sm font-semibold mb-3" style={{ color: '#9945FF' }}>On-Chain Info</h3>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <span className="text-gray-500">Program ID:</span>
              <span className="ml-2 font-mono text-xs">{programInfo.programId}</span>
            </div>
            <div>
              <span className="text-gray-500">Found:</span>
              <span className="ml-2" style={{ color: programInfo.found ? '#00C853' : '#FF4444' }}>
                {programInfo.found ? 'Yes' : 'No'}
              </span>
            </div>
          </div>
        </div>
      )}

      {results && (
        <div className="space-y-4">
          <div className="flex gap-6 items-center justify-center py-4 px-6 rounded-xl"
            style={{ background: '#1A1D2E' }}>
            {['Critical', 'High', 'Medium', 'Low'].map((sev) => (
              <div key={sev} className="text-center">
                <div className="text-2xl font-bold" style={{ color: SEVERITY_COLORS[sev] }}>
                  {results.summary[sev] || 0}
                </div>
                <div className="text-xs text-gray-500">{sev}</div>
              </div>
            ))}
            <div className="border-l border-gray-700 pl-6 text-center">
              <div className="text-2xl font-bold" style={{
                color: results.securityScore === 'A' ? '#00C853' : '#FFA500'
              }}>
                {results.securityScore}
              </div>
              <div className="text-xs text-gray-500">Score</div>
            </div>
          </div>
          {results.findings.length === 0 ? (
            <div className="text-center py-8 rounded-xl" style={{ background: '#1A1D2E' }}>
              <div className="text-2xl mb-2" style={{ color: '#00C853' }}>No pattern matches found</div>
              <p className="text-gray-500 text-sm">
                Scanned {results.filesScanned} files against {results.patternsChecked} patterns.
              </p>
            </div>
          ) : (
            results.findings.map((f, i) => (
              <StaticFindingCard key={i} finding={f} />
            ))
          )}
        </div>
      )}

      {!results && !programInfo && !loading && (
        <div className="rounded-xl overflow-hidden" style={{ background: '#1A1D2E' }}>
          <div className="p-4 border-b border-gray-800">
            <h3 className="text-sm font-semibold text-gray-300">Detection Patterns</h3>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800">
                <th className="text-left p-3 text-gray-500 font-medium">ID</th>
                <th className="text-left p-3 text-gray-500 font-medium">Pattern</th>
                <th className="text-left p-3 text-gray-500 font-medium">Severity</th>
              </tr>
            </thead>
            <tbody>
              {PATTERNS.map((p) => (
                <tr key={p.id} className="border-b border-gray-800/50">
                  <td className="p-3 font-mono text-xs" style={{ color: '#9945FF' }}>{p.id}</td>
                  <td className="p-3 text-gray-400">{p.name}</td>
                  <td className="p-3"><SeverityBadge severity={p.severity} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function StaticFindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <div className="rounded-xl p-4 transition-all cursor-pointer"
      style={{ background: '#1A1D2E', borderLeft: `4px solid ${SEVERITY_COLORS[finding.severity]}` }}
      onClick={() => setExpanded(!expanded)}>
      <div className="flex items-start gap-3">
        <SeverityBadge severity={finding.severity} />
        <div className="flex-1">
          <div className="font-semibold text-sm">
            <span className="text-gray-400">{finding.id}</span>
            <span className="mx-2 text-gray-600">-</span>
            {finding.name}
          </div>
          <div className="text-xs text-gray-500 mt-1 font-mono">{finding.file}:{finding.line}</div>
          <div className="text-sm text-gray-400 mt-2">{finding.description}</div>
        </div>
        <span className="text-gray-600 text-sm">{expanded ? '\u25B2' : '\u25BC'}</span>
      </div>
      {expanded && (
        <div className="mt-4 pt-4 border-t border-gray-800">
          <div className="text-xs font-semibold mb-1" style={{ color: '#14F195' }}>Fix</div>
          <pre className="text-xs p-3 rounded overflow-x-auto" style={{ background: '#0F1117', color: '#ccc' }}>{finding.fix}</pre>
        </div>
      )}
    </div>
  )
}

/* ── Shared Components ── */
function SeverityBadge({ severity }) {
  return (
    <span className="px-2 py-0.5 rounded text-xs font-bold shrink-0"
      style={{ background: SEVERITY_BG[severity], color: SEVERITY_COLORS[severity] }}>
      {severity}
    </span>
  )
}

/* ── Main App ── */
export default function App() {
  const [activeTab, setActiveTab] = useState('overview')

  const tabContent = {
    overview: <OverviewTab />,
    semantic: <SemanticTab />,
    exploits: <ExploitsTab />,
    static: <StaticTab />,
  }

  return (
    <div className="min-h-screen" style={{ background: '#0F1117' }}>
      <Header activeTab={activeTab} setActiveTab={setActiveTab} />
      <main className="max-w-6xl mx-auto px-4 sm:px-6 py-8">
        {tabContent[activeTab]}
      </main>
      <footer className="border-t border-gray-800 py-6 text-center text-sm text-gray-600">
        anchor-shield v0.3.0 | Adversarial Security Agent for Solana
      </footer>
    </div>
  )
}
