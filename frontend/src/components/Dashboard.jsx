import { useState, useEffect } from 'react';
import { getAllResults } from '../api/client';
import PRCard from './PRCard';
import './Dashboard.css';

function Dashboard() {
  const [prs, setPrs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchResults();
  }, []);

  const fetchResults = async () => {
    try {
      setLoading(true);
      const data = await getAllResults(0, 20);
      setPrs(data);
      setError(null);
    } catch (err) {
      setError('Failed to fetch results: ' + err.message);
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="dashboard loading">
        <div className="spinner"></div>
        <p>Loading PR analyses...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="dashboard error">
        <p>❌ {error}</p>
        <button onClick={fetchResults}>Retry</button>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <h1>🛡️ Security Gate Dashboard</h1>
        <p>AI-Driven PR Analysis System</p>
      </header>

      <div className="stats">
        <div className="stat-card">
          <h3>{prs.length}</h3>
          <p>Total Analyses</p>
        </div>
        <div className="stat-card">
          <h3>{prs.filter(pr => pr.verdict === 'AUTO_APPROVE').length}</h3>
          <p>Approved</p>
        </div>
        <div className="stat-card">
          <h3>{prs.filter(pr => pr.verdict === 'BLOCK').length}</h3>
          <p>Blocked</p>
        </div>
        <div className="stat-card">
          <h3>{prs.filter(pr => pr.verdict === 'MANUAL_REVIEW').length}</h3>
          <p>Needs Review</p>
        </div>
      </div>

      <div className="pr-list">
        <h2>Recent PR Analyses</h2>
        {prs.length === 0 ? (
          <div className="empty-state">
            <p>No PR analyses yet. Analyze your first PR!</p>
          </div>
        ) : (
          <div className="pr-grid">
            {prs.map(pr => (
              <PRCard key={pr.id} pr={pr} />
            ))}
          </div>
        )}
      </div>

      <button className="refresh-btn" onClick={fetchResults}>
        🔄 Refresh
      </button>
    </div>
  );
}

export default Dashboard;
