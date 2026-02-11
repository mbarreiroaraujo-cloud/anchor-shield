/**
 * In-browser scanner engine for anchor-shield dashboard.
 * Fetches Rust source files from GitHub API and runs pattern detection.
 */

const PATTERNS = [
  {
    id: 'ANCHOR-001',
    name: 'init_if_needed Incomplete Field Validation',
    severity: 'High',
    detect: (content, filename) => {
      const findings = [];
      const regex = /#\[account\(([\s\S]*?)\)\]/g;
      let match;
      while ((match = regex.exec(content)) !== null) {
        const attrs = match[1];
        if (!attrs.includes('init_if_needed')) continue;
        if (!attrs.match(/token\s*::|associated_token\s*::/)) continue;

        // Check for safe patterns
        const line = content.substring(0, match.index).split('\n').length;
        const context = content.split('\n').slice(Math.max(0, line - 15), line + 15).join('\n');
        if (context.match(/constraint\s*=\s*[^,]*\.delegate\.is_none/)) continue;
        if (context.match(/constraint\s*=\s*[^,]*\.close_authority\.is_none/)) continue;

        findings.push({
          id: 'ANCHOR-001', name: 'init_if_needed Incomplete Field Validation',
          severity: 'High', file: filename, line,
          description: 'Token account accepted via init_if_needed without delegate/close_authority validation.',
          fix: 'Add constraint = account.delegate.is_none() and constraint = account.close_authority.is_none()',
          reference: 'https://github.com/solana-foundation/anchor/pull/4229',
        });
      }
      return findings;
    },
  },
  {
    id: 'ANCHOR-002',
    name: 'Duplicate Mutable Account Bypass',
    severity: 'Medium',
    detect: (content, filename) => {
      const findings = [];
      // Check for init_if_needed + mut on same-type accounts in same struct
      const structRegex = /#\[derive\(Accounts\)\][\s\S]*?pub\s+struct\s+(\w+)/g;
      let sm;
      while ((sm = structRegex.exec(content)) !== null) {
        const braceStart = content.indexOf('{', sm.index + sm[0].length);
        if (braceStart === -1) continue;
        let depth = 1, i = braceStart + 1;
        while (i < content.length && depth > 0) {
          if (content[i] === '{') depth++;
          if (content[i] === '}') depth--;
          i++;
        }
        const body = content.substring(braceStart, i);
        const hasInitIfNeeded = body.match(/init_if_needed[\s\S]*?Account\s*<\s*'\w+\s*,\s*(\w+)/);
        const hasMut = body.match(/#\[account\([^)]*\bmut\b[^)]*\)\][\s\S]*?Account\s*<\s*'\w+\s*,\s*(\w+)/);
        if (hasInitIfNeeded && hasMut && hasInitIfNeeded[1] === hasMut[1]) {
          findings.push({
            id: 'ANCHOR-002', name: 'Duplicate Mutable Account Bypass',
            severity: 'Medium', file: filename,
            line: content.substring(0, sm.index).split('\n').length,
            description: `init_if_needed field coexists with mutable field of type ${hasInitIfNeeded[1]} — excluded from duplicate check.`,
            fix: 'Add explicit duplicate check: require!(a.key() != b.key())',
            reference: 'https://github.com/solana-foundation/anchor/pull/4229',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'ANCHOR-003',
    name: 'Realloc Payer Missing Signer Verification',
    severity: 'Medium',
    detect: (content, filename) => {
      const findings = [];
      const payerMatch = content.match(/realloc\s*::\s*payer\s*=\s*(\w+)/g);
      if (!payerMatch) return findings;
      for (const pm of payerMatch) {
        const payerName = pm.match(/=\s*(\w+)/)[1];
        const fieldRegex = new RegExp(`pub\\s+${payerName}\\s*:\\s*(\\S+)`);
        const fieldMatch = content.match(fieldRegex);
        if (fieldMatch && !fieldMatch[1].includes('Signer')) {
          const line = content.substring(0, content.indexOf(pm)).split('\n').length;
          findings.push({
            id: 'ANCHOR-003', name: 'Realloc Payer Missing Signer Verification',
            severity: 'Medium', file: filename, line,
            description: `Realloc payer '${payerName}' typed as ${fieldMatch[1]} instead of Signer.`,
            fix: 'Change payer field type to Signer<\'info\'>',
            reference: 'https://github.com/solana-foundation/anchor/pull/4229',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'ANCHOR-004',
    name: 'Account Type Cosplay — Missing Discriminator',
    severity: 'Medium',
    detect: (content, filename) => {
      const findings = [];
      const safeNames = new Set(['system_program', 'token_program', 'rent', 'clock',
        'associated_token_program', 'authority', 'payer', 'owner', 'signer']);
      const regex = /pub\s+(\w+)\s*:\s*AccountInfo\s*</g;
      let m;
      while ((m = regex.exec(content)) !== null) {
        const name = m[1];
        if (safeNames.has(name) || name.endsWith('_program')) continue;
        const line = content.substring(0, m.index).split('\n').length;
        const context = content.split('\n').slice(Math.max(0, line - 10), line + 1).join('\n');
        if (context.includes('/// CHECK:') || context.includes('owner =') || context.includes('signer')) continue;
        findings.push({
          id: 'ANCHOR-004', name: 'Account Type Cosplay — Missing Discriminator',
          severity: 'Medium', file: filename, line,
          description: `Field '${name}' uses raw AccountInfo without owner/discriminator verification.`,
          fix: 'Replace AccountInfo with Account<\'info, T>',
          reference: 'https://github.com/solana-foundation/anchor/pull/4229',
        });
      }
      return findings;
    },
  },
  {
    id: 'ANCHOR-005',
    name: 'Close + Reinit Lifecycle Attack',
    severity: 'Medium',
    detect: (content, filename) => {
      const findings = [];
      const hasClose = content.match(/close\s*=/);
      const hasInitIfNeeded = content.match(/init_if_needed/);
      if (hasClose && hasInitIfNeeded) {
        // Extract account types for both
        const closeTypes = new Set();
        const initTypes = new Set();
        const typeRegex = /Account\s*<\s*'\w+\s*,\s*(\w+)\s*>/g;
        let tm;
        // Find types near close and init_if_needed
        const closeIdx = content.indexOf('close');
        const initIdx = content.indexOf('init_if_needed');
        const closeContext = content.substring(Math.max(0, closeIdx - 200), closeIdx + 200);
        const initContext = content.substring(Math.max(0, initIdx - 200), initIdx + 200);
        while ((tm = typeRegex.exec(closeContext)) !== null) closeTypes.add(tm[1]);
        typeRegex.lastIndex = 0;
        while ((tm = typeRegex.exec(initContext)) !== null) initTypes.add(tm[1]);
        for (const t of closeTypes) {
          if (initTypes.has(t)) {
            findings.push({
              id: 'ANCHOR-005', name: 'Close + Reinit Lifecycle Attack',
              severity: 'Medium', file: filename,
              line: content.substring(0, initIdx).split('\n').length,
              description: `Account type '${t}' used with both close and init_if_needed.`,
              fix: 'Use plain init instead of init_if_needed for closeable accounts',
              reference: 'https://github.com/solana-foundation/anchor/pull/4229',
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'ANCHOR-006',
    name: 'Missing Owner Validation',
    severity: 'High',
    detect: (content, filename) => {
      const findings = [];
      const safeNames = new Set(['system_program', 'token_program', 'rent', 'clock',
        'associated_token_program', 'sysvar_rent', 'sysvar_clock']);
      const regex = /pub\s+(\w+)\s*:\s*(?:AccountInfo|UncheckedAccount)\s*</g;
      let m;
      while ((m = regex.exec(content)) !== null) {
        const name = m[1];
        if (safeNames.has(name) || name.endsWith('_program')) continue;
        const line = content.substring(0, m.index).split('\n').length;
        const context = content.split('\n').slice(Math.max(0, line - 10), line + 1).join('\n');
        if (context.includes('/// CHECK:') || context.includes('owner =') || context.includes('signer')) continue;
        findings.push({
          id: 'ANCHOR-006', name: 'Missing Owner Validation',
          severity: 'High', file: filename, line,
          description: `Field '${name}' uses raw AccountInfo/UncheckedAccount without owner check.`,
          fix: 'Use Account<\'info, T> or add #[account(owner = program::ID)]',
          reference: 'https://github.com/solana-foundation/anchor/pull/4229',
        });
      }
      return findings;
    },
  },
];

export async function scanGitHubRepo(repoUrl) {
  const match = repoUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
  if (!match) throw new Error('Invalid GitHub URL');
  const [, owner, repo] = match;
  const cleanRepo = repo.replace('.git', '');

  // Fetch repo metadata
  const repoResp = await fetch(`https://api.github.com/repos/${owner}/${cleanRepo}`);
  if (!repoResp.ok) throw new Error(`Repository not found: ${owner}/${cleanRepo}`);
  const repoData = await repoResp.json();
  const branch = repoData.default_branch || 'main';

  // Fetch file tree
  const treeResp = await fetch(`https://api.github.com/repos/${owner}/${cleanRepo}/git/trees/${branch}?recursive=1`);
  if (!treeResp.ok) throw new Error('Could not fetch repository tree');
  const treeData = await treeResp.json();

  // Filter .rs files
  const rsFiles = treeData.tree
    .filter(f => f.type === 'blob' && f.path.endsWith('.rs'))
    .filter(f => !f.path.includes('target/') && !f.path.includes('node_modules/'))
    .slice(0, 50);

  const allFindings = [];
  let filesScanned = 0;

  for (const file of rsFiles) {
    try {
      const contentResp = await fetch(
        `https://api.github.com/repos/${owner}/${cleanRepo}/contents/${file.path}?ref=${branch}`,
        { headers: { Accept: 'application/vnd.github.v3.raw' } }
      );
      if (!contentResp.ok) continue;
      const content = await contentResp.text();
      filesScanned++;

      for (const pattern of PATTERNS) {
        try {
          const findings = pattern.detect(content, file.path);
          allFindings.push(...findings);
        } catch (e) { /* skip pattern errors */ }
      }
    } catch (e) { /* skip file errors */ }
  }

  // Compute summary
  const summary = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const f of allFindings) {
    summary[f.severity] = (summary[f.severity] || 0) + 1;
  }

  let score = 'A';
  const total = summary.Critical * 10 + summary.High * 5 + summary.Medium * 2 + summary.Low;
  if (total >= 20) score = 'F';
  else if (total >= 15) score = 'D';
  else if (total >= 10) score = 'C';
  else if (total >= 5) score = 'B';
  else if (total > 0) score = 'B+';

  return {
    target: `${owner}/${cleanRepo}`,
    filesScanned,
    patternsChecked: PATTERNS.length,
    findings: allFindings,
    summary,
    securityScore: score,
  };
}

export async function checkOnChainProgram(programId, network = 'mainnet-beta') {
  const rpcUrl = {
    'mainnet-beta': 'https://api.mainnet-beta.solana.com',
    devnet: 'https://api.devnet.solana.com',
    testnet: 'https://api.testnet.solana.com',
  }[network] || 'https://api.mainnet-beta.solana.com';

  const resp = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0', id: 1,
      method: 'getAccountInfo',
      params: [programId, { encoding: 'base64', commitment: 'confirmed' }],
    }),
  });

  const data = await resp.json();
  const value = data?.result?.value;

  if (!value) return { programId, found: false, network };

  return {
    programId,
    found: true,
    executable: value.executable,
    owner: value.owner,
    isUpgradeable: value.owner === 'BPFLoaderUpgradeab1e11111111111111111111111',
    dataSize: value.data?.[0]?.length || 0,
    network,
  };
}

export { PATTERNS };
