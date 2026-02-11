import { useState } from 'react'
import { scanGitHubRepo, checkOnChainProgram, PATTERNS } from './scanner.js'

const SEVERITY_COLORS = {
  Critical: '#FF4444',
  High: '#FF4444',
  Medium: '#FFA500',
  Low: '#00C853',
}

const SEVERITY_BG = {
  Critical: 'rgba(255,68,68,0.15)',
  High: 'rgba(255,68,68,0.15)',
  Medium: 'rgba(255,165,0,0.15)',
  Low: 'rgba(0,200,83,0.15)',
}

function Header() {
  return (
    <header className="border-b border-gray-800 px-6 py-4">
      <div className="max-w-5xl mx-auto flex items-center gap-3">
        <div className="text-2xl">
          <span className="font-bold" style={{ color: '#9945FF' }}>anchor</span>
          <span className="font-bold text-gray-300">-shield</span>
        </div>
        <span className="text-xs px-2 py-0.5 rounded" style={{ background: '#9945FF22', color: '#9945FF' }}>v0.1.0</span>
        <div className="ml-auto text-sm text-gray-500">
          Automated Security Scanner for Solana Anchor Programs
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
        Detect known vulnerability patterns in Solana Anchor programs.
        Powered by original research from{' '}
        <a href="https://github.com/coral-xyz/anchor/pull/4229" target="_blank" rel="noreferrer"
          className="underline" style={{ color: '#14F195' }}>PR #4229</a>.
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
  return (
    <div
      className="rounded-lg p-4 mb-3 transition-all cursor-pointer"
      style={{
        background: '#1A1D2E',
        borderLeft: `4px solid ${SEVERITY_COLORS[finding.severity]}`,
      }}
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex items-start gap-3">
        <span className="px-2 py-0.5 rounded text-xs font-bold shrink-0"
          style={{
            background: SEVERITY_BG[finding.severity],
            color: SEVERITY_COLORS[finding.severity],
          }}>
          {finding.severity.toUpperCase()}
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
              {finding.fix}
            </pre>
          </div>
          <div className="text-xs text-gray-500">
            Reference: <a href={finding.reference} target="_blank" rel="noreferrer"
              className="underline" style={{ color: '#9945FF' }}>{finding.reference}</a>
          </div>
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

export default function App() {
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
      <Header />
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

      <footer className="border-t border-gray-800 py-6 text-center text-sm text-gray-600">
        anchor-shield v0.1.0 | Built on original security research |{' '}
        <a href="https://github.com/mbarreiroaraujo-cloud/anchor-shield" target="_blank" rel="noreferrer"
          style={{ color: '#9945FF' }}>GitHub</a>
      </footer>
    </div>
  )
}
