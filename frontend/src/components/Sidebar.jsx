import { useState } from 'react';
import FindingCard from './FindingCard';
import LeadCard from './LeadCard';
import ReportModal from './ReportModal';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export default function Sidebar({ findings, leads, sessionId, isOpen, onClose }) {
  const [showReport, setShowReport] = useState(false);
  const [expandedItem, setExpandedItem] = useState(null);
  const [activeTab, setActiveTab] = useState('findings');

  const sortedFindings = [...findings].sort((a, b) => {
    const aIdx = SEVERITY_ORDER.indexOf(a.severity?.toLowerCase() || 'info');
    const bIdx = SEVERITY_ORDER.indexOf(b.severity?.toLowerCase() || 'info');
    return aIdx - bIdx;
  });

  const activeLeads = (leads || []).filter((l) => l.status !== 'dismissed');

  return (
    <>
      {isOpen && (
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-30 lg:hidden"
          onClick={onClose}
        />
      )}

      <aside
        className={`
          fixed top-0 left-0 h-full w-72 bg-gray-900/95 backdrop-blur-md border-r border-gray-800/60 z-40
          transform transition-transform duration-300 ease-in-out
          lg:relative lg:translate-x-0 lg:z-0
          ${isOpen ? 'translate-x-0' : '-translate-x-full'}
          flex flex-col overflow-hidden
        `}
      >
        {/* Header with tabs */}
        <div className="border-b border-gray-800/60">
          <div className="flex items-center justify-between px-1 pt-3 pb-0">
            <div className="flex gap-0">
              <button
                onClick={() => setActiveTab('findings')}
                className={`px-3 py-2 text-[10px] font-bold uppercase tracking-wider border-b-2 transition-colors ${
                  activeTab === 'findings'
                    ? 'text-cyan-400 border-cyan-400'
                    : 'text-gray-600 border-transparent hover:text-gray-400'
                }`}
              >
                Findings
                {findings.length > 0 && (
                  <span className={`ml-1.5 inline-flex items-center justify-center min-w-[1.25rem] h-4.5 px-1.5 text-[10px] font-bold rounded-full ${
                    activeTab === 'findings'
                      ? 'bg-cyan-400/10 text-cyan-400 border border-cyan-400/20'
                      : 'bg-gray-800 text-gray-500'
                  }`}>
                    {findings.length}
                  </span>
                )}
              </button>
              <button
                onClick={() => setActiveTab('leads')}
                className={`px-3 py-2 text-[10px] font-bold uppercase tracking-wider border-b-2 transition-colors ${
                  activeTab === 'leads'
                    ? 'text-purple-400 border-purple-400'
                    : 'text-gray-600 border-transparent hover:text-gray-400'
                }`}
              >
                Leads
                {activeLeads.length > 0 && (
                  <span className={`ml-1.5 inline-flex items-center justify-center min-w-[1.25rem] h-4.5 px-1.5 text-[10px] font-bold rounded-full ${
                    activeTab === 'leads'
                      ? 'bg-purple-400/10 text-purple-400 border border-purple-400/20'
                      : 'bg-gray-800 text-gray-500'
                  }`}>
                    {activeLeads.length}
                  </span>
                )}
              </button>
            </div>
            <button
              onClick={onClose}
              className="lg:hidden text-gray-500 hover:text-gray-300 transition-colors p-1 mr-2"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-3 flex-1 overflow-y-auto">
          {activeTab === 'findings' && (
            <>
              {sortedFindings.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-center">
                  <svg className="w-8 h-8 text-gray-700 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  <p className="text-xs text-gray-600">No findings yet</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {sortedFindings.map((f) => (
                    <FindingCard
                      key={f.id}
                      finding={f}
                      isExpanded={expandedItem === f.id}
                      onToggle={() =>
                        setExpandedItem(expandedItem === f.id ? null : f.id)
                      }
                    />
                  ))}
                </div>
              )}
            </>
          )}

          {activeTab === 'leads' && (
            <>
              {activeLeads.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-center">
                  <svg className="w-8 h-8 text-gray-700 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                  <p className="text-xs text-gray-600">No leads yet</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {activeLeads.map((l) => (
                    <LeadCard
                      key={l.id}
                      lead={l}
                      isExpanded={expandedItem === l.id}
                      onToggle={() =>
                        setExpandedItem(expandedItem === l.id ? null : l.id)
                      }
                    />
                  ))}
                </div>
              )}
            </>
          )}
        </div>

        {/* Report Button */}
        <div className="p-3 border-t border-gray-800/60">
          <button
            onClick={() => setShowReport(true)}
            className="w-full px-4 py-2.5 bg-cyan-500/10 text-cyan-400 border border-cyan-500/20
                       rounded-xl text-xs font-semibold uppercase tracking-wider
                       hover:bg-cyan-500/20 hover:border-cyan-500/30 hover:shadow-cyan-glow
                       transition-all duration-300 flex items-center justify-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Generate Report
          </button>
        </div>
      </aside>

      {showReport && (
        <ReportModal sessionId={sessionId} onClose={() => setShowReport(false)} />
      )}
    </>
  );
}
