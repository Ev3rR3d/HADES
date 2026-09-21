const CATEGORY_CONFIG = {
  route: { color: 'text-purple-400', bg: 'bg-purple-400/10', border: 'border-purple-400/30', icon: '/' },
  technology: { color: 'text-sky-400', bg: 'bg-sky-400/10', border: 'border-sky-400/30', icon: '#' },
  config: { color: 'text-amber-400', bg: 'bg-amber-400/10', border: 'border-amber-400/30', icon: '*' },
  credential: { color: 'text-red-400', bg: 'bg-red-400/10', border: 'border-red-400/30', icon: '@' },
  exposure: { color: 'text-orange-400', bg: 'bg-orange-400/10', border: 'border-orange-400/30', icon: '!' },
  other: { color: 'text-gray-400', bg: 'bg-gray-400/10', border: 'border-gray-400/30', icon: '?' },
};

const STATUS_LABELS = {
  open: { label: 'Open', style: 'text-yellow-400' },
  investigating: { label: 'Investigating', style: 'text-blue-400' },
  escalated: { label: 'Escalated', style: 'text-red-400' },
  dismissed: { label: 'Dismissed', style: 'text-gray-500 line-through' },
};

export default function LeadCard({ lead, isExpanded, onToggle }) {
  const category = lead.category?.toLowerCase() || 'other';
  const config = CATEGORY_CONFIG[category] || CATEGORY_CONFIG.other;
  const status = STATUS_LABELS[lead.status] || STATUS_LABELS.open;

  return (
    <div
      className={`rounded-lg border ${config.border} ${config.bg} transition-all duration-200 cursor-pointer`}
      onClick={onToggle}
    >
      <div className="flex items-center gap-2 px-3 py-2">
        <span className={`w-5 h-5 flex items-center justify-center rounded text-xs font-bold flex-shrink-0 ${config.color} bg-black/20`}>
          {config.icon}
        </span>
        <span className={`text-xs font-semibold uppercase ${config.color}`}>
          {category}
        </span>
        <span className={`text-sm truncate flex-1 ${lead.status === 'dismissed' ? 'text-gray-500 line-through' : 'text-gray-200'}`}>
          {lead.title}
        </span>
        <svg
          className={`w-4 h-4 text-gray-400 transition-transform duration-200 flex-shrink-0 ${
            isExpanded ? 'rotate-180' : ''
          }`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </div>

      {isExpanded && (
        <div className="px-3 pb-3 space-y-2 border-t border-gray-700/50 mt-1 pt-2">
          {lead.description && (
            <p className="text-sm text-gray-300">{lead.description}</p>
          )}
          <div className="flex items-center gap-2 pt-1">
            <span className={`text-xs font-medium ${status.style}`}>
              {status.label}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
