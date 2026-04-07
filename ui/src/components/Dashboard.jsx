import React, { useState, useEffect } from 'react';
import StatCard from './StatCard';

export default function Dashboard() {
  const [stats, setStats] = useState({ 
    total_attacks: 0, 
    vulnerabilities: 0, 
    success_rate: 0, 
    duration_seconds: 0 
  });
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statRes, findRes] = await Promise.all([
          fetch('/api/stats'),
          fetch('/api/findings')
        ]);
        
        if (!statRes.ok || !findRes.ok) {
          throw new Error('Failed to fetch stats or findings');
        }
        
        const statData = await statRes.json();
        const findData = await findRes.json();
        
        setStats(statData);
        setFindings(findData);
        setError(false);
      } catch (e) {
        console.error("Failed to load backend telemetry", e);
        setError(true);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  return (
    <div className="container" style={{ marginTop: '90px', paddingBottom: '50px' }}>
      {/* Error Banner */}
      <div className="row g-4" aria-live="polite">
        {error && (
          <div className="col-12 mt-3 animate-up">
            <div className="alert alert-danger" role="alert">
              <strong>Connection Error:</strong> Failed to load telemetry data. Please ensure the backend is running.
            </div>
          </div>
        )}
      </div>

      {loading ? (
        <div className="row g-4 mt-3" aria-live="polite">
          <div className="col-12 text-center p-5 text-muted animate-up">
            Loading PromptFuzz intelligence...
          </div>
        </div>
      ) : (
        <>
          <div className="row g-4 mt-1 animate-up" aria-live="polite">
            <div className="col-12 col-md-3">
              <StatCard 
                title="Total Attacks" 
                value={stats.total_attacks} 
                colorClass="text-primary" 
              />
            </div>
            <div className="col-12 col-md-3">
              <StatCard 
                title="Vulnerabilities" 
                value={stats.vulnerabilities} 
                colorClass="text-danger" 
              />
            </div>
            <div className="col-12 col-md-3">
              <StatCard 
                title="Success Rate" 
                value={`${stats.success_rate.toFixed(1)}%`} 
                colorClass="text-warning" 
              />
            </div>
            <div className="col-12 col-md-3">
              <StatCard 
                title="Duration" 
                value={`${stats.duration_seconds.toFixed(1)}s`} 
                colorClass="text-info" 
              />
            </div>
          </div>

          <div className="row mt-5 animate-up" style={{ animationDelay: '100ms' }}>
            <div className="col-12">
              <div className="card-glass p-4">
                <h4 className="fw-semibold text-white mb-4">Finding Details</h4>
                {findings.length > 0 ? (
                  <div className="table-responsive">
                    <table className="table table-dark table-striped table-hover align-middle">
                      <thead>
                        <tr>
                          <th>Target</th>
                          <th>Attack Name</th>
                          <th>Severity</th>
                          <th>Prompt Preview</th>
                        </tr>
                      </thead>
                      <tbody>
                        {findings.map((finding) => (
                          <tr key={finding.id || Math.random()}>
                            <td><span className="badge bg-secondary">{finding.target}</span></td>
                            <td><span className="text-info">{finding.attack_name}</span></td>
                            <td>
                              <span className={`badge ${finding.severity === 'critical' ? 'bg-danger' : finding.severity === 'high' ? 'bg-warning' : finding.severity === 'medium' ? 'bg-primary' : 'bg-secondary'}`}>
                                {finding.severity}
                              </span>
                            </td>
                            <td>
                              <div className="text-truncate text-muted d-inline-block" style={{ maxWidth: '400px' }} title={finding.prompt}>
                                {finding.prompt?.substring(0, 80)}{finding.prompt?.length > 80 ? '...' : ''}
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="text-center p-5 text-muted">
                    <p>No findings to display.</p>
                    <p className="small">Launch campaigns to populate live charts and embedding analysis.</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
