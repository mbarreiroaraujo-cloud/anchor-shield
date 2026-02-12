import { useState } from 'react'
import { scanGitHubRepo, checkOnChainProgram, PATTERNS } from './scanner.js'
import demoReport from './demoReport.json'

const SEVERITY_COLORS = {
  Critical: '#FF4444',
  CRITICAL: '#FF4444',
  High: '#FF4444',
  HIGH: '#FF4444',
  Medium: '#FFA500',
  MEDIUM: '#FFA500',
  Low: '#00C853',
  LOW: '#00C853',
}

const SEVERITY_BG = {
  Critical: 'rgba(255,68,68,0.15)',
  CRITICAL: 'rgba(255,68,68,0.15)',
  High: 'rgba(255,68,68,0.15)',
  HIGH: 'rgba(255,68,68,0.15)',
  Medium: 'rgba(255,165,0,0.15)',
  MEDIUM: 'rgba(255,165,0,0.15)',
  Low: 'rgba(0,200,83,0.15)',
  LOW: 'rgba(0,200,83,0.15)',
}

function Header({ activeView, onViewChange }) {
  return (
    <header className="border-b border-gray-800 px-6 py-4">
      <div className="max-w-5xl mx-auto flex items-center gap-3">
        <div className="text-2xl">
          <span className="font-bold" style={{ color: '#9945FF' }}>anchor</span>
          <span className="font-bold text-gray-300">-shield</span>
        </div>
        <span className="text-xs px-2 py-0.5 rounded" style={{ background: '#9945FF22', color: '#9945FF' }}>v2.0</span>
        <nav className="ml-8 flex gap-1">
          {[
            { id: 'scan', label: 'Static Scan' },
            { id: 'semantic', label: 'Semantic Analysis' },
            { id: 'exploits', label: 'Exploits' },
            { id: 'compare', label: 'Compare' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => onViewChange(tab.id)}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-all ${
                activeView === tab.id ? 'text-white' : 'text-gray-500 hover:text-gray-300'
              }`}
              style={activeView === tab.id ? { background: '#9945FF' } : {}}
            >
              {tab.label}
            </button>
          ))}
        </nav>
        <div className="ml-auto text-sm text-gray-500">
          Autonomous Security Agent for Solana Anchor Programs
        </div>
      </div>
    </header>
  )
}

function ScanInput({ onScan, loading }) {
  const [input, setInput] = useState('')
  const [mode, setMode] = useState('repo')

  const handleScan = () => {
    if (!input.trim()) return
    onScan(input.trim(), mode)
  }

  return (
    <div className="max-w-3xl mx-auto text-center py-12 px-6">
      <h1 className="text-4xl font-bold mb-2">
        <span style={{ color: '#9945FF' }}>Security Scanner</span>
        <span className="text-gray-400"> for Anchor Programs</span>
      </h1>
      <p className="text-gray-500 mb-8 text-lg">
        Three-layer analysis: static patterns + semantic LLM + adversarial exploits.
      </p>

      <div className="flex gap-2 justify-center mb-4">
        <button
          onClick={() => setMode('repo')}
          className={`px-4 py-1.5 rounded text-sm font-medium transition-all ${
            mode === 'repo'
              ? 'text-white'
              : 'text-gray-500 hover:text-gray-300'
          }`}
          style={mode === 'repo' ? { background: '#9945FF' } : { background: '#1A1D2E' }}
        >
          GitHub Repo
        </button>
        <button
          onClick={() => setMode('program')}
          className={`px-4 py-1.5 rounded text-sm font-medium transition-all ${
            mode === 'program'
              ? 'text-white'
              : 'text-gray-500 hover:text-gray-300'
          }`}
          style={mode === 'program' ? { background: '#9945FF' } : { background: '#1A1D2E' }}
        >
          On-Chain Program
        </button>
      </div>

      <div className="flex gap-2 max-w-2xl mx-auto">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleScan()}
          placeholder={mode === 'repo'
            ? 'https://github.com/owner/repo'
            : 'Program ID (e.g., 6LtL...3kRR)'}
          className="flex-1 px-4 py-3 rounded-lg text-sm font-mono outline-none transition-all"
          style={{
            background: '#1A1D2E',
            border: '1px solid #333',
            color: '#E0E0E0',
          }}
          disabled={loading}
        />
        <button
          onClick={handleScan}
          disabled={loading || !input.trim()}
          className="px-6 py-3 rounded-lg font-semibold text-white text-sm transition-all hover:opacity-90 disabled:opacity-50"
          style={{ background: 'linear-gradient(135deg, #9945FF, #14F195)' }}
        >
          {loading ? 'Scanning...' : 'Scan'}
        </button>
      </div>
    </div>
  )
}

function SummaryBar({ summary, score }) {
  return (
    <div className="flex gap-6 items-center justify-center py-4 px-6 rounded-lg mb-6"
      style={{ background: '#1A1D2E' }}>
      {['Critical', 'High', 'Medium', 'Low'].map((sev) => (
        <div key={sev} className="text-center">
          <div className="text-2xl font-bold" style={{ color: SEVERITY_COLORS[sev] }}>
            {summary[sev] || 0}
          </div>
          <div className="text-xs text-gray-500">{sev}</div>
        </div>
      ))}
      <div className="border-l border-gray-700 pl-6 text-center">
        <div className="text-2xl font-bold" style={{
          color: score === 'A' ? '#00C853' : score.startsWith('B') ? '#FFA500' : '#FF4444'
        }}>
          {score}
        </div>
        <div className="text-xs text-gray-500">Score</div>
      </div>
    </div>
  )
}

function FindingCard({ finding, index }) {
  const [expanded, setExpanded] = useState(false)
  const sev = finding.severity || 'Medium'
  return (
    <div
      className="rounded-lg p-4 mb-3 transition-all cursor-pointer"
      style={{
        background: '#1A1D2E',
        borderLeft: `4px solid ${SEVERITY_COLORS[sev] || '#FFA500'}`,
      }}
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex items-start gap-3">
        <span className="px-2 py-0.5 rounded text-xs font-bold shrink-0"
          style={{
            background: SEVERITY_BG[sev] || 'rgba(255,165,0,0.15)',
            color: SEVERITY_COLORS[sev] || '#FFA500',
          }}>
          {sev.toUpperCase()}
        </span>
        <div className="flex-1">
          <div className="font-semibold text-sm">
            <span className="text-gray-400">{finding.id}</span>
            <span className="mx-2 text-gray-600">—</span>
            {finding.name}
          </div>
          <div className="text-xs text-gray-500 mt-1 font-mono">
            {finding.file}:{finding.line}
          </div>
          <div className="text-sm text-gray-400 mt-2">{finding.description}</div>
        </div>
        <span className="text-gray-600 text-sm">{expanded ? '▲' : '▼'}</span>
      </div>

      {expanded && (
        <div className="mt-4 pt-4 border-t border-gray-800">
          <div className="mb-3">
            <div className="text-xs font-semibold mb-1" style={{ color: '#14F195' }}>Fix Recommendation</div>
            <pre className="text-xs p-3 rounded overflow-x-auto"
              style={{ background: '#0F1117', color: '#ccc' }}>
              {finding.fix || finding.fix_recommendation}
            </pre>
          </div>
          {finding.reference && (
            <div className="text-xs text-gray-500">
              Reference: <a href={finding.reference} target="_blank" rel="noreferrer"
                className="underline" style={{ color: '#9945FF' }}>{finding.reference}</a>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function ProgramInfo({ info }) {
  if (!info) return null
  return (
    <div className="rounded-lg p-5 mb-6" style={{ background: '#1A1D2E' }}>
      <h3 className="text-sm font-semibold mb-3" style={{ color: '#9945FF' }}>
        On-Chain Risk Assessment
      </h3>
      <div className="grid grid-cols-2 gap-3 text-sm">
        <div>
          <span className="text-gray-500">Program ID:</span>
          <span className="ml-2 font-mono text-xs">{info.programId}</span>
        </div>
        <div>
          <span className="text-gray-500">Network:</span>
          <span className="ml-2">{info.network}</span>
        </div>
        <div>
          <span className="text-gray-500">Found:</span>
          <span className="ml-2" style={{ color: info.found ? '#00C853' : '#FF4444' }}>
            {info.found ? 'Yes' : 'No'}
          </span>
        </div>
        {info.found && <>
          <div>
            <span className="text-gray-500">Executable:</span>
            <span className="ml-2">{info.executable ? 'Yes' : 'No'}</span>
          </div>
          <div>
            <span className="text-gray-500">Upgradeable:</span>
            <span className="ml-2" style={{ color: info.isUpgradeable ? '#FFA500' : '#00C853' }}>
              {info.isUpgradeable ? 'Yes' : 'No'}
            </span>
          </div>
          <div>
            <span className="text-gray-500">Owner:</span>
            <span className="ml-2 font-mono text-xs">{info.owner?.substring(0, 20)}...</span>
          </div>
        </>}
      </div>
    </div>
  )
}

function PatternTable() {
  return (
    <div className="max-w-3xl mx-auto px-6 pb-12">
      <h2 className="text-lg font-semibold mb-4 text-gray-300">Detection Patterns</h2>
      <div className="rounded-lg overflow-hidden" style={{ background: '#1A1D2E' }}>
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
                <td className="p-3">{p.name}</td>
                <td className="p-3">
                  <span className="px-2 py-0.5 rounded text-xs font-bold"
                    style={{ background: SEVERITY_BG[p.severity], color: SEVERITY_COLORS[p.severity] }}>
                    {p.severity}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ============================================================================
// NEW: Semantic Analysis View
// ============================================================================

function SemanticFindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false)
  const sev = finding.severity || 'MEDIUM'
  const confidence = finding.confidence != null ? Math.round(finding.confidence * 100) : null

  return (
    <div
      className="rounded-lg p-4 mb-3 transition-all cursor-pointer"
      style={{
        background: '#1A1D2E',
        borderLeft: `4px solid ${SEVERITY_COLORS[sev] || '#FFA500'}`,
      }}
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex items-start gap-3">
        <span className="px-2 py-0.5 rounded text-xs font-bold shrink-0"
          style={{
            background: SEVERITY_BG[sev] || 'rgba(255,165,0,0.15)',
            color: SEVERITY_COLORS[sev] || '#FFA500',
          }}>
          {sev.toUpperCase()}
        </span>
        <div className="flex-1">
          <div className="font-semibold text-sm text-gray-200">
            {finding.title}
          </div>
          <div className="text-xs text-gray-500 mt-1 font-mono">
            Function: {finding.function}
            {finding.line_hint && ` | Line ~${finding.line_hint}`}
          </div>
          {confidence != null && (
            <div className="mt-1">
              <span className="text-xs px-2 py-0.5 rounded"
                style={{
                  background: confidence > 90 ? 'rgba(0,200,83,0.15)' : 'rgba(255,165,0,0.15)',
                  color: confidence > 90 ? '#00C853' : '#FFA500',
                }}>
                {confidence}% confidence
              </span>
            </div>
          )}
          <div className="text-sm text-gray-400 mt-2">{finding.description}</div>
        </div>
        <span className="text-gray-600 text-sm">{expanded ? '▲' : '▼'}</span>
      </div>

      {expanded && finding.attack_scenario && (
        <div className="mt-4 pt-4 border-t border-gray-800">
          <div className="text-xs font-semibold mb-2" style={{ color: '#FF4444' }}>Attack Scenario</div>
          <pre className="text-xs p-3 rounded overflow-x-auto whitespace-pre-wrap"
            style={{ background: '#0F1117', color: '#ccc' }}>
            {finding.attack_scenario}
          </pre>
        </div>
      )}
    </div>
  )
}

function SemanticView({ report }) {
  const semantic = report?.semantic_analysis
  if (!semantic) return <div className="text-gray-500 text-center py-12">No semantic analysis data available.</div>

  return (
    <div className="max-w-3xl mx-auto px-6 pb-12">
      <h2 className="text-lg font-semibold mb-2 text-gray-300">
        Semantic Analysis — <span style={{ color: '#9945FF' }}>LLM-Powered</span>
      </h2>
      <p className="text-sm text-gray-500 mb-6">
        Logic vulnerabilities discovered by AI analysis. These bugs are invisible to regex pattern matching.
      </p>

      <div className="flex gap-4 mb-6">
        {[
          { label: 'Critical', count: semantic.critical, color: '#FF4444' },
          { label: 'High', count: semantic.high, color: '#FF4444' },
          { label: 'Medium', count: semantic.medium, color: '#FFA500' },
        ].map(({ label, count, color }) => (
          <div key={label} className="text-center px-4 py-3 rounded-lg" style={{ background: '#1A1D2E' }}>
            <div className="text-2xl font-bold" style={{ color }}>{count}</div>
            <div className="text-xs text-gray-500">{label}</div>
          </div>
        ))}
        <div className="text-center px-4 py-3 rounded-lg" style={{ background: '#1A1D2E' }}>
          <div className="text-2xl font-bold" style={{ color: '#9945FF' }}>{semantic.total_findings}</div>
          <div className="text-xs text-gray-500">Total</div>
        </div>
      </div>

      {semantic.findings.map((f, i) => (
        <SemanticFindingCard key={i} finding={f} />
      ))}
    </div>
  )
}

// ============================================================================
// NEW: Exploits View
// ============================================================================

function ExploitCard({ exploit }) {
  const [showCode, setShowCode] = useState(false)
  const sev = exploit.severity || 'HIGH'

  const statusColor = {
    CONFIRMED: '#00C853',
    GENERATED: '#FFA500',
    THEORETICAL: '#9945FF',
    FAILED: '#FF4444',
  }[exploit.status] || '#666'

  return (
    <div className="rounded-lg p-4 mb-3" style={{ background: '#1A1D2E' }}>
      <div className="flex items-center gap-3 mb-2">
        <span className="px-2 py-0.5 rounded text-xs font-bold"
          style={{
            background: SEVERITY_BG[sev] || 'rgba(255,165,0,0.15)',
            color: SEVERITY_COLORS[sev] || '#FFA500',
          }}>
          {sev.toUpperCase()}
        </span>
        <span className="text-sm font-semibold text-gray-200 flex-1">{exploit.finding_title}</span>
        <span className="px-2 py-0.5 rounded text-xs font-bold"
          style={{ background: `${statusColor}22`, color: statusColor }}>
          {exploit.status}
        </span>
      </div>
      <div className="text-xs text-gray-500 font-mono mb-3">{exploit.filename}</div>

      <button
        onClick={() => setShowCode(!showCode)}
        className="text-xs px-3 py-1 rounded transition-all"
        style={{ background: '#9945FF22', color: '#9945FF' }}
      >
        {showCode ? 'Hide Code' : 'Show Exploit Code'}
      </button>

      {showCode && (
        <pre className="mt-3 p-4 rounded text-xs overflow-x-auto"
          style={{ background: '#0A0C14', color: '#ccc', maxHeight: '400px' }}>
          {exploit.code}
        </pre>
      )}
    </div>
  )
}

function ExploitsView({ report }) {
  const adv = report?.adversarial_synthesis
  if (!adv) return <div className="text-gray-500 text-center py-12">No exploit data available.</div>

  return (
    <div className="max-w-3xl mx-auto px-6 pb-12">
      <h2 className="text-lg font-semibold mb-2 text-gray-300">
        Adversarial Exploits — <span style={{ color: '#FF4444' }}>Proof of Concept</span>
      </h2>
      <p className="text-sm text-gray-500 mb-6">
        Automatically generated TypeScript exploit tests that demonstrate each vulnerability.
      </p>

      <div className="flex gap-4 mb-6">
        <div className="text-center px-4 py-3 rounded-lg" style={{ background: '#1A1D2E' }}>
          <div className="text-2xl font-bold" style={{ color: '#9945FF' }}>{adv.exploits_generated}</div>
          <div className="text-xs text-gray-500">Generated</div>
        </div>
        <div className="text-center px-4 py-3 rounded-lg" style={{ background: '#1A1D2E' }}>
          <div className="text-2xl font-bold" style={{ color: '#00C853' }}>{adv.exploits_confirmed}</div>
          <div className="text-xs text-gray-500">Confirmed</div>
        </div>
        <div className="text-center px-4 py-3 rounded-lg" style={{ background: '#1A1D2E' }}>
          <div className="text-2xl font-bold" style={{ color: '#FFA500' }}>{adv.exploits_theoretical}</div>
          <div className="text-xs text-gray-500">Theoretical</div>
        </div>
      </div>

      {adv.exploits.map((e, i) => (
        <ExploitCard key={i} exploit={e} />
      ))}
    </div>
  )
}

// ============================================================================
// NEW: Comparison View
// ============================================================================

function CompareView({ report }) {
  if (!report) return <div className="text-gray-500 text-center py-12">No report data available.</div>

  const staticBugs = report.static_analysis?.logic_bugs_found ?? 0
  const semanticBugs = report.semantic_analysis?.total_findings ?? 0
  const critHigh = (report.semantic_analysis?.critical ?? 0) + (report.semantic_analysis?.high ?? 0)
  const exploitsGen = report.adversarial_synthesis?.exploits_generated ?? 0
  const exploitsConf = report.adversarial_synthesis?.exploits_confirmed ?? 0
  const exploitsTheo = report.adversarial_synthesis?.exploits_theoretical ?? 0

  const layers = [
    {
      name: 'Static Regex',
      description: 'Pattern matching against known vulnerability signatures',
      logicBugs: staticBugs,
      patternMatches: report.static_analysis?.pattern_matches ?? 0,
      exploits: null,
      color: '#666',
    },
    {
      name: 'Semantic LLM',
      description: 'AI-powered analysis of program logic and business rules',
      logicBugs: semanticBugs,
      patternMatches: null,
      exploits: null,
      color: '#9945FF',
    },
    {
      name: 'Adversarial',
      description: 'Automated exploit generation and execution',
      logicBugs: null,
      patternMatches: null,
      exploits: `${exploitsConf > 0 ? exploitsConf + ' confirmed' : ''}${exploitsTheo > 0 ? (exploitsConf > 0 ? ', ' : '') + exploitsTheo + ' theoretical' : ''}`,
      color: '#FF4444',
    },
  ]

  return (
    <div className="max-w-3xl mx-auto px-6 pb-12">
      <h2 className="text-lg font-semibold mb-2 text-gray-300">
        Layer Comparison — <span style={{ color: '#14F195' }}>Why Three Layers Matter</span>
      </h2>
      <p className="text-sm text-gray-500 mb-8">
        Each layer catches what the previous one misses. Logic bugs are invisible to regex.
      </p>

      {/* Comparison Table */}
      <div className="rounded-lg overflow-hidden mb-8" style={{ background: '#1A1D2E' }}>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800">
              <th className="text-left p-4 text-gray-500 font-medium">Layer</th>
              <th className="text-center p-4 text-gray-500 font-medium">Logic Bugs Found</th>
              <th className="text-center p-4 text-gray-500 font-medium">Exploits</th>
            </tr>
          </thead>
          <tbody>
            {layers.map((layer) => (
              <tr key={layer.name} className="border-b border-gray-800/50">
                <td className="p-4">
                  <div className="font-semibold" style={{ color: layer.color }}>{layer.name}</div>
                  <div className="text-xs text-gray-600 mt-0.5">{layer.description}</div>
                </td>
                <td className="p-4 text-center">
                  {layer.logicBugs != null ? (
                    <span className="text-xl font-bold" style={{
                      color: layer.logicBugs > 0 ? '#FF4444' : '#666'
                    }}>
                      {layer.logicBugs}
                    </span>
                  ) : (
                    <span className="text-gray-600">—</span>
                  )}
                </td>
                <td className="p-4 text-center">
                  {layer.exploits ? (
                    <span className="text-sm" style={{ color: '#14F195' }}>{layer.exploits}</span>
                  ) : (
                    <span className="text-gray-600">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Visual Bar Comparison */}
      <div className="rounded-lg p-6" style={{ background: '#1A1D2E' }}>
        <h3 className="text-sm font-semibold mb-4 text-gray-400">Logic Bug Detection Rate</h3>
        <div className="space-y-3">
          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-gray-500">Static Regex</span>
              <span className="text-gray-400">{staticBugs} / {critHigh} bugs</span>
            </div>
            <div className="h-3 rounded-full overflow-hidden" style={{ background: '#0F1117' }}>
              <div className="h-full rounded-full transition-all"
                style={{
                  width: critHigh > 0 ? `${(staticBugs / critHigh) * 100}%` : '0%',
                  background: '#666',
                  minWidth: staticBugs > 0 ? '8px' : '0',
                }} />
            </div>
          </div>
          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-gray-500">Semantic LLM</span>
              <span className="text-gray-400">{critHigh} / {critHigh} bugs</span>
            </div>
            <div className="h-3 rounded-full overflow-hidden" style={{ background: '#0F1117' }}>
              <div className="h-full rounded-full transition-all"
                style={{
                  width: '100%',
                  background: 'linear-gradient(90deg, #9945FF, #14F195)',
                }} />
            </div>
          </div>
          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-gray-500">Adversarial Exploits</span>
              <span className="text-gray-400">{exploitsGen} / {critHigh} exploits</span>
            </div>
            <div className="h-3 rounded-full overflow-hidden" style={{ background: '#0F1117' }}>
              <div className="h-full rounded-full transition-all"
                style={{
                  width: critHigh > 0 ? `${(exploitsGen / critHigh) * 100}%` : '0%',
                  background: '#FF4444',
                }} />
            </div>
          </div>
        </div>
      </div>

      {/* Key Insight */}
      <div className="mt-6 p-4 rounded-lg" style={{ background: 'rgba(153,69,255,0.1)', border: '1px solid #9945FF44' }}>
        <div className="text-sm font-semibold mb-1" style={{ color: '#9945FF' }}>Key Insight</div>
        <div className="text-sm text-gray-400">
          Regex found <strong className="text-white">{report.static_analysis?.pattern_matches ?? 0} pattern matches</strong> but{' '}
          <strong style={{ color: '#FF4444' }}>0 logic bugs</strong>. The LLM found{' '}
          <strong style={{ color: '#14F195' }}>{critHigh} critical logic vulnerabilities</strong> that
          no regex can detect, and generated <strong style={{ color: '#FF4444' }}>{exploitsGen} exploit PoCs</strong>.
        </div>
      </div>
    </div>
  )
}

// ============================================================================
// Main App
// ============================================================================

export default function App() {
  const [activeView, setActiveView] = useState('scan')
  const [results, setResults] = useState(null)
  const [programInfo, setProgramInfo] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleScan = async (input, mode) => {
    setLoading(true)
    setError(null)
    setResults(null)
    setProgramInfo(null)

    try {
      if (mode === 'program') {
        const info = await checkOnChainProgram(input)
        setProgramInfo(info)
      } else {
        const report = await scanGitHubRepo(input)
        setResults(report)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen" style={{ background: '#0F1117' }}>
      <Header activeView={activeView} onViewChange={setActiveView} />

      {activeView === 'scan' && (
        <>
          <ScanInput onScan={handleScan} loading={loading} />

          {error && (
            <div className="max-w-3xl mx-auto px-6">
              <div className="p-4 rounded-lg text-sm" style={{ background: '#FF444422', color: '#FF4444' }}>
                {error}
              </div>
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
            <div className="max-w-3xl mx-auto px-6">
              <ProgramInfo info={programInfo} />
            </div>
          )}

          {results && (
            <div className="max-w-3xl mx-auto px-6 pb-12">
              <div className="flex items-center gap-3 mb-4">
                <h2 className="text-lg font-semibold text-gray-300">
                  Scan Results: <span className="font-mono text-sm" style={{ color: '#14F195' }}>
                    {results.target}
                  </span>
                </h2>
              </div>
              <div className="text-xs text-gray-500 mb-4">
                {results.filesScanned} files scanned | {results.patternsChecked} patterns checked
              </div>

              <SummaryBar summary={results.summary} score={results.securityScore} />

              {results.findings.length === 0 ? (
                <div className="text-center py-8 rounded-lg" style={{ background: '#1A1D2E' }}>
                  <div className="text-3xl mb-2" style={{ color: '#00C853' }}>No vulnerabilities found</div>
                  <p className="text-gray-500 text-sm">
                    Scanned {results.filesScanned} files against {results.patternsChecked} detection patterns.
                  </p>
                </div>
              ) : (
                results.findings.map((f, i) => <FindingCard key={i} finding={f} index={i} />)
              )}
            </div>
          )}

          {!results && !programInfo && !loading && !error && <PatternTable />}
        </>
      )}

      {activeView === 'semantic' && <SemanticView report={demoReport} />}
      {activeView === 'exploits' && <ExploitsView report={demoReport} />}
      {activeView === 'compare' && <CompareView report={demoReport} />}

      <footer className="border-t border-gray-800 py-6 text-center text-sm text-gray-600">
        anchor-shield v2.0 | Static + Semantic + Adversarial |{' '}
        <a href="https://github.com/mbarreiroaraujo-cloud/anchor-shield" target="_blank" rel="noreferrer"
          style={{ color: '#9945FF' }}>GitHub</a>
      </footer>
    </div>
  )
}
