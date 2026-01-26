import './PRCard.css';

function PRCard({ pr }) {
  const getVerdictColor = (verdict) => {
    switch (verdict) {
      case 'AUTO_APPROVE': return 'green';
      case 'BLOCK': return 'red';
      case 'MANUAL_REVIEW': return 'orange';
      default: return 'gray';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed': return '✅';
      case 'pending': return '⏳';
      case 'failed': return '❌';
      default: return '⚪';
    }
  };

  const getRiskLevel = (score) => {
    if (!score) return 'unknown';
    if (score >= 0.8) return 'high';
    if (score >= 0.5) return 'medium';
    return 'low';
  };

  return (
    <div className={`pr-card ${getVerdictColor(pr.verdict)}`}>
      <div className="pr-header">
        <span className="status-icon">{getStatusIcon(pr.status)}</span>
        <h3>{pr.repo_name}</h3>
        <span className="pr-number">#{pr.pr_number}</span>
      </div>

      <div className="pr-details">
        {pr.risk_score !== null && (
          <div className={`risk-score ${getRiskLevel(pr.risk_score)}`}>
            <span className="label">Risk Score:</span>
            <span className="value">{(pr.risk_score * 100).toFixed(0)}%</span>
          </div>
        )}

        {pr.verdict && (
          <div className={`verdict ${getVerdictColor(pr.verdict)}`}>
            <span className="label">Verdict:</span>
            <span className="value">{pr.verdict.replace('_', ' ')}</span>
          </div>
        )}

        <div className="scan-results">
          {pr.scan_results && pr.scan_results.length > 0 ? (
            <>
              <span className="label">Scans:</span>
              <div className="tools">
                {pr.scan_results.map((scan, idx) => (
                  <span key={idx} className={`tool-badge ${scan.severity}`}>
                    {scan.tool}
                  </span>
                ))}
              </div>
            </>
          ) : (
            <span className="no-scans">No scans yet</span>
          )}
        </div>
      </div>

      <div className="pr-footer">
        <a href={pr.pr_url} target="_blank" rel="noopener noreferrer" className="view-pr-btn">
          View PR →
        </a>
        <span className="timestamp">
          {new Date(pr.created_at).toLocaleDateString()}
        </span>
      </div>
    </div>
  );
}

export default PRCard;
