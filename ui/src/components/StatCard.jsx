import React from 'react';

export default function StatCard({ title, value, colorClass }) {
  return (
    <div className="card-glass p-4 text-center">
      <div 
        className="text-muted mb-2 text-uppercase fw-semibold" 
        style={{ letterSpacing: '1px' }}
      >
        {title}
      </div>
      <div className={`stat-number ${colorClass}`}>
        {value}
      </div>
    </div>
  );
}
