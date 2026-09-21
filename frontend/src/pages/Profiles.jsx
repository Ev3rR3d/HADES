import { useState, useEffect, useMemo } from 'react';
import {
  getTools, getProfiles, createProfile, updateProfile, deleteProfile,
  getCustomTools, createCustomTool, updateCustomTool, deleteCustomTool,
} from '../api';

const CATEGORY_LABELS = {
  recon: 'Recon',
  scanning: 'Scanning',
  enumeration: 'Enumeration',
  exploitation: 'Exploitation',
};

const CATEGORY_COLORS = {
  recon: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  scanning: 'text-amber-400 bg-amber-400/10 border-amber-400/30',
  enumeration: 'text-purple-400 bg-purple-400/10 border-purple-400/30',
  exploitation: 'text-red-400 bg-red-400/10 border-red-400/30',
};

const RISK_COLORS = {
  low: 'text-emerald-400',
  medium: 'text-amber-400',
  high: 'text-red-400',
};

const CATEGORY_OPTIONS = ['recon', 'scanning', 'enumeration', 'exploitation'];
const RISK_OPTIONS = ['low', 'medium', 'high'];

// ── Tool Card ───────────────────────────────────────────────────────────────

function ToolCard({ tool, selected, onToggle }) {
  const catColor = CATEGORY_COLORS[tool.category] || 'text-gray-400 bg-gray-400/10 border-gray-400/30';
  const riskColor = RISK_COLORS[tool.risk] || 'text-gray-400';

  return (
    <button
      onClick={onToggle}
      className={`
        group relative text-left p-3 rounded-xl border transition-all duration-200
        ${selected
          ? 'bg-cyan-400/[0.08] border-cyan-400/40 ring-1 ring-cyan-400/20'
          : 'bg-gray-900/50 border-gray-800/50 hover:border-gray-700 hover:bg-gray-800/30'
        }
      `}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={`font-mono text-sm font-semibold ${selected ? 'text-cyan-400' : 'text-gray-200'}`}>
              {tool.name}
            </span>
            {tool.is_custom && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-400/10 text-purple-400 border border-purple-400/20">
                custom
              </span>
            )}
            {!tool.installed && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-400/10 text-red-400 border border-red-400/20">
                N/A
              </span>
            )}
          </div>
          <p className="text-xs text-gray-500 line-clamp-2 leading-relaxed">{tool.description}</p>
        </div>
        <div className={`
          w-5 h-5 rounded-md border-2 flex-shrink-0 flex items-center justify-center transition-all
          ${selected
            ? 'bg-cyan-400 border-cyan-400'
            : 'border-gray-700 group-hover:border-gray-500'
          }
        `}>
          {selected && (
            <svg className="w-3 h-3 text-gray-950" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={3}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          )}
        </div>
      </div>
      <div className="flex items-center gap-2 mt-2">
        <span className={`text-[10px] px-1.5 py-0.5 rounded-md border ${catColor}`}>
          {CATEGORY_LABELS[tool.category] || tool.category}
        </span>
        <span className={`text-[10px] ${riskColor}`}>
          {tool.risk}
        </span>
      </div>
    </button>
  );
}

// ── Profile Card ────────────────────────────────────────────────────────────

function ProfileCard({ profile, isActive, onSelect, onDelete }) {
  const [confirmDelete, setConfirmDelete] = useState(false);
  const toolCount = profile.tools?.length || 0;

  return (
    <div
      onClick={onSelect}
      className={`
        cursor-pointer p-4 rounded-xl border transition-all duration-200
        ${isActive
          ? 'bg-cyan-400/[0.08] border-cyan-400/40 ring-1 ring-cyan-400/20'
          : 'bg-gray-900/50 border-gray-800/50 hover:border-gray-700 hover:bg-gray-800/30'
        }
      `}
    >
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h3 className={`font-semibold text-sm ${isActive ? 'text-cyan-400' : 'text-gray-200'}`}>
              {profile.name}
            </h3>
            {profile.is_default && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-500 border border-gray-700">
                default
              </span>
            )}
          </div>
          <p className="text-xs text-gray-500 mt-1">{profile.description}</p>
          <p className="text-[11px] text-gray-600 mt-2 font-mono">{toolCount} tools</p>
        </div>
        {!profile.is_default && (
          <div onClick={(e) => e.stopPropagation()}>
            {confirmDelete ? (
              <div className="flex gap-1">
                <button
                  onClick={() => onDelete(profile.id)}
                  className="text-[10px] px-2 py-1 rounded bg-red-500/20 text-red-400 hover:bg-red-500/30"
                >
                  Confirm
                </button>
                <button
                  onClick={() => setConfirmDelete(false)}
                  className="text-[10px] px-2 py-1 rounded bg-gray-800 text-gray-400 hover:bg-gray-700"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <button
                onClick={() => setConfirmDelete(true)}
                className="p-1 text-gray-600 hover:text-red-400 transition-colors"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
                </svg>
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Custom Tool Card ────────────────────────────────────────────────────────

function CustomToolCard({ tool, onEdit, onDelete }) {
  const [confirmDelete, setConfirmDelete] = useState(false);
  const catColor = CATEGORY_COLORS[tool.category] || 'text-gray-400 bg-gray-400/10 border-gray-400/30';
  const riskColor = RISK_COLORS[tool.risk] || 'text-gray-400';

  return (
    <div className="bg-gray-900/50 border border-gray-800/50 rounded-xl p-4 hover:border-gray-700 transition-all">
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-mono text-sm font-semibold text-gray-200">{tool.name}</span>
            {tool.display_name && tool.display_name !== tool.name && (
              <span className="text-xs text-gray-500">{tool.display_name}</span>
            )}
            <span className={`text-[10px] px-1.5 py-0.5 rounded-md border ${catColor}`}>
              {CATEGORY_LABELS[tool.category] || tool.category}
            </span>
            <span className={`text-[10px] ${riskColor}`}>{tool.risk}</span>
          </div>
          {tool.description && (
            <p className="text-xs text-gray-500 mt-1">{tool.description}</p>
          )}
          <div className="flex items-center gap-4 mt-2.5">
            <div className="flex items-center gap-1.5">
              <span className="text-[10px] text-gray-600 uppercase tracking-wider">Path</span>
              <code className="text-[11px] text-cyan-400/80 bg-gray-800/80 px-1.5 py-0.5 rounded font-mono">
                {tool.binary_path}
              </code>
            </div>
            {tool.args_template && (
              <div className="flex items-center gap-1.5">
                <span className="text-[10px] text-gray-600 uppercase tracking-wider">Args</span>
                <code className="text-[11px] text-gray-400 bg-gray-800/80 px-1.5 py-0.5 rounded font-mono truncate max-w-[300px]">
                  {tool.args_template}
                </code>
              </div>
            )}
            <div className="flex items-center gap-1.5">
              <span className="text-[10px] text-gray-600 uppercase tracking-wider">Timeout</span>
              <span className="text-[11px] text-gray-400 font-mono">{tool.timeout}s</span>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-1 flex-shrink-0 ml-3">
          <button
            onClick={() => onEdit(tool)}
            className="p-1.5 text-gray-600 hover:text-cyan-400 transition-colors rounded-lg hover:bg-gray-800"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
            </svg>
          </button>
          {confirmDelete ? (
            <div className="flex gap-1">
              <button
                onClick={() => onDelete(tool.id)}
                className="text-[10px] px-2 py-1 rounded bg-red-500/20 text-red-400 hover:bg-red-500/30"
              >
                Confirm
              </button>
              <button
                onClick={() => setConfirmDelete(false)}
                className="text-[10px] px-2 py-1 rounded bg-gray-800 text-gray-400 hover:bg-gray-700"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              onClick={() => setConfirmDelete(true)}
              className="p-1.5 text-gray-600 hover:text-red-400 transition-colors rounded-lg hover:bg-gray-800"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
              </svg>
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Custom Tool Form ────────────────────────────────────────────────────────

const EMPTY_FORM = {
  name: '', display_name: '', description: '', category: 'recon',
  binary_path: '', args_template: '', risk: 'low', timeout: 120,
};

function CustomToolForm({ initial, onSave, onCancel, saving }) {
  const [form, setForm] = useState(initial || EMPTY_FORM);
  const [error, setError] = useState('');

  const set = (key, val) => setForm(prev => ({ ...prev, [key]: val }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!form.name.trim()) return setError('Nome obrigatório');
    if (!form.binary_path.trim()) return setError('Caminho do binário obrigatório');
    if (/\s/.test(form.name)) return setError('Nome não pode conter espaços (use slug: my-tool)');
    try {
      await onSave(form);
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="bg-gray-900/50 border border-cyan-400/20 rounded-xl p-5 space-y-4">
      <h3 className="text-sm font-semibold text-cyan-400">
        {initial ? 'Editar Tool' : 'Nova Custom Tool'}
      </h3>

      {error && (
        <div className="text-xs text-red-400 bg-red-400/10 border border-red-400/20 rounded-lg px-3 py-2">
          {error}
        </div>
      )}

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-[11px] text-gray-500 mb-1 uppercase tracking-wider">Nome (slug)</label>
          <input
            type="text"
            value={form.name}
            onChange={(e) => set('name', e.target.value.toLowerCase().replace(/\s+/g, '-'))}
            placeholder="httpx-custom"
            className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-100
                       placeholder-gray-600 focus:outline-none focus:border-cyan-400/50 font-mono"
          />
        </div>
        <div>
          <label className="block text-[11px] text-gray-500 mb-1 uppercase tracking-wider">Display Name</label>
          <input
            type="text"
            value={form.display_name}
            onChange={(e) => set('display_name', e.target.value)}
            placeholder="HTTPx Custom"
            className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-100
                       placeholder-gray-600 focus:outline-none focus:border-cyan-400/50"
          />
        </div>
      </div>

      <div>
        <label className="block text-[11px] text-gray-500 mb-1 uppercase tracking-wider">Descrição</label>
        <input
          type="text"
          value={form.description}
          onChange={(e) => set('description', e.target.value)}
          placeholder="O que essa tool faz..."
          className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-100
                     placeholder-gray-600 focus:outline-none focus:border-cyan-400/50"
        />
      </div>

      <div>
        <label className="block text-[11px] text-gray-500 mb-1 uppercase tracking-wider">Caminho do Binário</label>
        <input
          type="text"
          value={form.binary_path}
          onChange={(e) => set('binary_path', e.target.value)}
          placeholder="/usr/local/bin/httpx  ou  httpx"
          className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-100
                     placeholder-gray-600 focus:outline-none focus:border-cyan-400/50 font-mono"
        />
        <p className="text-[10px] text-gray-600 mt-1">Path completo ou nome do binário se estiver no PATH</p>
      </div>

      <div>
        <label className="block text-[11px] text-gray-500 mb-1 uppercase tracking-wider">Argumentos (Template)</label>
        <input
          type="text"
          value={form.args_template}
          onChange={(e) => set('args_template', e.target.value)}
          placeholder="-u {target} -silent -json"
          className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-100
                     placeholder-gray-600 focus:outline-none focus:border-cyan-400/50 font-mono"
        />
        <p className="text-[10px] text-gray-600 mt-1">
          Use <code className="text-cyan-400/60">{'{target}'}</code> como placeholder pro alvo. Ex: <code className="text-gray-500">-u {'{target}'} -silent -json</code>
        </p>
      </div>

      <div className="grid grid-cols-3 gap-3">
        <div>
          <label className="block text-[11px] text-gray-500 mb-1 uppercase tracking-wider">Categoria</label>
          <select
            value={form.category}
            onChange={(e) => set('category', e.target.value)}
            className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-100
                       focus:outline-none focus:border-cyan-400/50"
          >
            {CATEGORY_OPTIONS.map(c => (
              <option key={c} value={c}>{CATEGORY_LABELS[c]}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-[11px] text-gray-500 mb-1 uppercase tracking-wider">Risco</label>
          <select
            value={form.risk}
            onChange={(e) => set('risk', e.target.value)}
            className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-100
                       focus:outline-none focus:border-cyan-400/50"
          >
            {RISK_OPTIONS.map(r => (
              <option key={r} value={r}>{r}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-[11px] text-gray-500 mb-1 uppercase tracking-wider">Timeout (s)</label>
          <input
            type="number"
            min={10}
            max={600}
            value={form.timeout}
            onChange={(e) => set('timeout', parseInt(e.target.value) || 120)}
            className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-100
                       focus:outline-none focus:border-cyan-400/50 font-mono"
          />
        </div>
      </div>

      <div className="flex items-center justify-end gap-2 pt-1">
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2 text-xs text-gray-400 bg-gray-800 border border-gray-700 rounded-lg hover:bg-gray-700"
        >
          Cancelar
        </button>
        <button
          type="submit"
          disabled={saving}
          className="px-5 py-2 text-xs text-cyan-400 bg-cyan-400/10 border border-cyan-400/30
                     rounded-lg hover:bg-cyan-400/20 disabled:opacity-50 font-medium"
        >
          {saving ? 'Salvando...' : initial ? 'Salvar' : 'Criar Tool'}
        </button>
      </div>
    </form>
  );
}

// ── Main Page ───────────────────────────────────────────────────────────────

export default function Profiles() {
  const [tab, setTab] = useState('profiles');
  const [tools, setTools] = useState([]);
  const [profiles, setProfiles] = useState([]);
  const [customTools, setCustomTools] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeProfile, setActiveProfile] = useState(null);
  const [selectedTools, setSelectedTools] = useState(new Set());
  const [filterCategory, setFilterCategory] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [editMode, setEditMode] = useState(false);
  const [profileName, setProfileName] = useState('');
  const [profileDesc, setProfileDesc] = useState('');
  const [saving, setSaving] = useState(false);
  const [showToolForm, setShowToolForm] = useState(false);
  const [editingTool, setEditingTool] = useState(null);

  const loadAll = async () => {
    try {
      const [toolsData, profilesData, customData] = await Promise.all([
        getTools(), getProfiles(), getCustomTools(),
      ]);
      setTools(toolsData.tools || []);
      setProfiles(profilesData);
      setCustomTools(customData);
      if (profilesData.length > 0 && !activeProfile) {
        setActiveProfile(profilesData[0]);
        setSelectedTools(new Set(profilesData[0].tools || []));
      }
    } catch (err) {
      console.error('Failed to load:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadAll(); }, []);

  // ── Profile helpers ──────────────────────────────────────────

  const toolsByCategory = useMemo(() => {
    const grouped = {};
    for (const t of tools) {
      const cat = t.category || 'other';
      if (!grouped[cat]) grouped[cat] = [];
      grouped[cat].push(t);
    }
    return grouped;
  }, [tools]);

  const filteredTools = useMemo(() => {
    let list = tools;
    if (filterCategory !== 'all') {
      list = list.filter(t => t.category === filterCategory);
    }
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      list = list.filter(t =>
        t.name.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q)
      );
    }
    return list;
  }, [tools, filterCategory, searchTerm]);

  const categories = useMemo(() => {
    const cats = new Set(tools.map(t => t.category));
    return ['all', ...Array.from(cats).sort()];
  }, [tools]);

  const handleToggleTool = (toolName) => {
    if (!editMode) return;
    setSelectedTools(prev => {
      const next = new Set(prev);
      if (next.has(toolName)) next.delete(toolName);
      else next.add(toolName);
      return next;
    });
  };

  const handleSelectProfile = (profile) => {
    setActiveProfile(profile);
    setSelectedTools(new Set(profile.tools || []));
    setEditMode(false);
    setProfileName(profile.name);
    setProfileDesc(profile.description);
  };

  const handleNewProfile = () => {
    setActiveProfile(null);
    setSelectedTools(new Set());
    setEditMode(true);
    setProfileName('');
    setProfileDesc('');
  };

  const handleEditProfile = () => {
    if (!activeProfile || activeProfile.is_default) return;
    setEditMode(true);
    setProfileName(activeProfile.name);
    setProfileDesc(activeProfile.description);
  };

  const handleSave = async () => {
    if (!profileName.trim()) return;
    setSaving(true);
    try {
      const toolList = Array.from(selectedTools);
      if (activeProfile && !activeProfile.is_default) {
        await updateProfile(activeProfile.id, { name: profileName, description: profileDesc, tools: toolList });
      } else {
        await createProfile(profileName, profileDesc, toolList);
      }
      const updated = await getProfiles();
      setProfiles(updated);
      const match = updated.find(p => p.name === profileName);
      if (match) { setActiveProfile(match); setSelectedTools(new Set(match.tools || [])); }
      setEditMode(false);
    } catch (err) {
      console.error('Save failed:', err);
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteProfile = async (id) => {
    try {
      await deleteProfile(id);
      const updated = await getProfiles();
      setProfiles(updated);
      if (activeProfile?.id === id) {
        setActiveProfile(updated[0] || null);
        setSelectedTools(new Set(updated[0]?.tools || []));
      }
    } catch (err) {
      console.error('Delete failed:', err);
    }
  };

  const handleSelectAll = () => {
    const visible = filteredTools.map(t => t.name);
    setSelectedTools(prev => { const next = new Set(prev); visible.forEach(n => next.add(n)); return next; });
  };

  const handleDeselectAll = () => {
    const visible = new Set(filteredTools.map(t => t.name));
    setSelectedTools(prev => { const next = new Set(prev); visible.forEach(n => next.delete(n)); return next; });
  };

  // ── Custom Tool helpers ──────────────────────────────────────

  const handleSaveCustomTool = async (form) => {
    setSaving(true);
    try {
      if (editingTool) {
        await updateCustomTool(editingTool.id, form);
      } else {
        await createCustomTool(form);
      }
      await loadAll();
      setShowToolForm(false);
      setEditingTool(null);
    } finally {
      setSaving(false);
    }
  };

  const handleEditCustomTool = (tool) => {
    setEditingTool(tool);
    setShowToolForm(true);
  };

  const handleDeleteCustomTool = async (id) => {
    try {
      await deleteCustomTool(id);
      await loadAll();
    } catch (err) {
      console.error('Delete custom tool failed:', err);
    }
  };

  // ── Render ───────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[80vh]">
        <div className="w-6 h-6 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="max-w-[1400px] mx-auto px-6 py-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Scan Profiles & Tools</h1>
          <p className="text-sm text-gray-500 mt-1">
            {tools.length} tools &middot; {profiles.length} profiles &middot; {customTools.length} custom
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 mb-6 border-b border-gray-800/50 pb-px">
        <button
          onClick={() => setTab('profiles')}
          className={`px-4 py-2.5 text-sm font-medium transition-all border-b-2 -mb-px ${
            tab === 'profiles'
              ? 'text-cyan-400 border-cyan-400'
              : 'text-gray-500 border-transparent hover:text-gray-300'
          }`}
        >
          Scan Profiles
        </button>
        <button
          onClick={() => setTab('custom')}
          className={`px-4 py-2.5 text-sm font-medium transition-all border-b-2 -mb-px ${
            tab === 'custom'
              ? 'text-cyan-400 border-cyan-400'
              : 'text-gray-500 border-transparent hover:text-gray-300'
          }`}
        >
          Custom Tools
          {customTools.length > 0 && (
            <span className="ml-2 text-[10px] bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded-full">
              {customTools.length}
            </span>
          )}
        </button>
      </div>

      {/* ── Tab: Scan Profiles ── */}
      {tab === 'profiles' && (
        <>
          <div className="flex justify-end mb-4">
            <button
              onClick={handleNewProfile}
              className="flex items-center gap-2 px-4 py-2.5 bg-cyan-400/10 text-cyan-400 border border-cyan-400/30
                         rounded-xl text-sm font-medium hover:bg-cyan-400/20 transition-all"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
              </svg>
              Novo Profile
            </button>
          </div>

          <div className="grid grid-cols-12 gap-6">
            {/* Left — Profile list */}
            <div className="col-span-3 space-y-3">
              <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider px-1">Profiles</h2>
              {profiles.map(p => (
                <ProfileCard
                  key={p.id}
                  profile={p}
                  isActive={activeProfile?.id === p.id}
                  onSelect={() => handleSelectProfile(p)}
                  onDelete={handleDeleteProfile}
                />
              ))}
            </div>

            {/* Right — Tool catalog */}
            <div className="col-span-9">
              {/* Profile header / edit form */}
              <div className="bg-gray-900/50 border border-gray-800/50 rounded-xl p-4 mb-4">
                {editMode ? (
                  <div className="space-y-3">
                    <div className="grid grid-cols-2 gap-3">
                      <input
                        type="text"
                        value={profileName}
                        onChange={(e) => setProfileName(e.target.value)}
                        placeholder="Nome do profile"
                        className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-100
                                   placeholder-gray-500 focus:outline-none focus:border-cyan-400/50"
                      />
                      <input
                        type="text"
                        value={profileDesc}
                        onChange={(e) => setProfileDesc(e.target.value)}
                        placeholder="Descrição"
                        className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-100
                                   placeholder-gray-500 focus:outline-none focus:border-cyan-400/50"
                      />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-gray-500">
                        {selectedTools.size} tools selecionadas
                      </span>
                      <div className="flex gap-2">
                        <button
                          onClick={() => { setEditMode(false); if (activeProfile) handleSelectProfile(activeProfile); }}
                          className="px-3 py-1.5 text-xs text-gray-400 bg-gray-800 border border-gray-700 rounded-lg hover:bg-gray-700"
                        >
                          Cancelar
                        </button>
                        <button
                          onClick={handleSave}
                          disabled={saving || !profileName.trim()}
                          className="px-4 py-1.5 text-xs text-cyan-400 bg-cyan-400/10 border border-cyan-400/30
                                     rounded-lg hover:bg-cyan-400/20 disabled:opacity-50"
                        >
                          {saving ? 'Salvando...' : 'Salvar'}
                        </button>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-lg font-semibold text-gray-100">
                        {activeProfile?.name || 'Nenhum profile selecionado'}
                      </h2>
                      <p className="text-xs text-gray-500 mt-0.5">{activeProfile?.description}</p>
                    </div>
                    <div className="flex gap-2">
                      <span className="text-sm font-mono text-cyan-400 bg-cyan-400/10 px-3 py-1.5 rounded-lg">
                        {selectedTools.size} tools
                      </span>
                      {activeProfile && !activeProfile.is_default && (
                        <button
                          onClick={handleEditProfile}
                          className="px-3 py-1.5 text-xs text-gray-400 bg-gray-800 border border-gray-700
                                     rounded-lg hover:bg-gray-700 hover:text-gray-200"
                        >
                          Editar
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Filters */}
              <div className="flex items-center gap-3 mb-4">
                <div className="flex gap-1.5">
                  {categories.map(cat => (
                    <button
                      key={cat}
                      onClick={() => setFilterCategory(cat)}
                      className={`
                        px-3 py-1.5 rounded-lg text-xs font-medium transition-all
                        ${filterCategory === cat
                          ? 'bg-cyan-400/10 text-cyan-400 border border-cyan-400/30'
                          : 'bg-gray-800/50 text-gray-500 border border-gray-800 hover:text-gray-300'
                        }
                      `}
                    >
                      {cat === 'all' ? 'Todas' : CATEGORY_LABELS[cat] || cat}
                      {cat !== 'all' && (
                        <span className="ml-1 text-gray-600">
                          {toolsByCategory[cat]?.length || 0}
                        </span>
                      )}
                    </button>
                  ))}
                </div>
                <div className="flex-1" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Buscar tool..."
                  className="px-3 py-1.5 bg-gray-800/50 border border-gray-800 rounded-lg text-xs text-gray-300
                             placeholder-gray-600 focus:outline-none focus:border-gray-600 w-48"
                />
                {editMode && (
                  <div className="flex gap-1.5">
                    <button
                      onClick={handleSelectAll}
                      className="px-2 py-1.5 text-[10px] text-gray-400 bg-gray-800 border border-gray-700 rounded-lg hover:text-gray-200"
                    >
                      Todas
                    </button>
                    <button
                      onClick={handleDeselectAll}
                      className="px-2 py-1.5 text-[10px] text-gray-400 bg-gray-800 border border-gray-700 rounded-lg hover:text-gray-200"
                    >
                      Nenhuma
                    </button>
                  </div>
                )}
              </div>

              {/* Tool grid */}
              <div className="grid grid-cols-3 gap-2.5">
                {filteredTools.map(tool => (
                  <ToolCard
                    key={tool.name}
                    tool={tool}
                    selected={selectedTools.has(tool.name)}
                    onToggle={() => handleToggleTool(tool.name)}
                  />
                ))}
              </div>

              {filteredTools.length === 0 && (
                <div className="text-center py-12 text-gray-600 text-sm">
                  Nenhuma tool encontrada
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {/* ── Tab: Custom Tools ── */}
      {tab === 'custom' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-gray-500">
              Adicione tools CLI customizadas. Elas ficam disponíveis nos profiles e no scan.
            </p>
            {!showToolForm && (
              <button
                onClick={() => { setEditingTool(null); setShowToolForm(true); }}
                className="flex items-center gap-2 px-4 py-2.5 bg-cyan-400/10 text-cyan-400 border border-cyan-400/30
                           rounded-xl text-sm font-medium hover:bg-cyan-400/20 transition-all"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
                </svg>
                Nova Tool
              </button>
            )}
          </div>

          {showToolForm && (
            <CustomToolForm
              initial={editingTool ? {
                name: editingTool.name,
                display_name: editingTool.display_name || '',
                description: editingTool.description || '',
                category: editingTool.category || 'recon',
                binary_path: editingTool.binary_path || '',
                args_template: editingTool.args_template || '',
                risk: editingTool.risk || 'low',
                timeout: editingTool.timeout || 120,
              } : null}
              onSave={handleSaveCustomTool}
              onCancel={() => { setShowToolForm(false); setEditingTool(null); }}
              saving={saving}
            />
          )}

          {customTools.length === 0 && !showToolForm && (
            <div className="text-center py-16">
              <div className="w-12 h-12 rounded-xl bg-gray-800/50 border border-gray-700 flex items-center justify-center mx-auto mb-4">
                <svg className="w-6 h-6 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M11.42 15.17L17.25 21A2.652 2.652 0 0021 17.25l-5.877-5.877M11.42 15.17l2.496-3.03c.317-.384.74-.626 1.208-.766M11.42 15.17l-4.655 5.653a2.548 2.548 0 11-3.586-3.586l6.837-5.63m5.108-.233c.55-.164 1.163-.188 1.743-.14a4.5 4.5 0 004.486-6.336l-3.276 3.277a3.004 3.004 0 01-2.25-2.25l3.276-3.276a4.5 4.5 0 00-6.336 4.486c.091 1.076-.071 2.264-.904 2.95l-.102.085" />
                </svg>
              </div>
              <p className="text-gray-500 text-sm">Nenhuma custom tool ainda</p>
              <p className="text-gray-600 text-xs mt-1">
                Adicione ferramentas como httpx, nuclei, subfinder, etc.
              </p>
            </div>
          )}

          {customTools.length > 0 && (
            <div className="space-y-3">
              {customTools.map(tool => (
                <CustomToolCard
                  key={tool.id}
                  tool={tool}
                  onEdit={handleEditCustomTool}
                  onDelete={handleDeleteCustomTool}
                />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
