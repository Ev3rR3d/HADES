import { useRef, useState } from 'react';

export default function MessageInput({ onSend, disabled, showContinue, onContinue }) {
  const [value, setValue] = useState('');
  const textareaRef = useRef(null);

  const handleSubmit = () => {
    const trimmed = value.trim();
    if (!trimmed || disabled) return;
    onSend(trimmed);
    setValue('');
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  const handleInput = (e) => {
    setValue(e.target.value);
    const el = e.target;
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 160) + 'px';
  };

  return (
    <div className="p-3 border-t border-gray-800/60 bg-gray-900/60">
      {showContinue && (
        <div className="flex items-center gap-2 mb-3">
          <button
            onClick={onContinue}
            className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-500/10 text-cyan-400
                       border border-cyan-500/20 rounded-xl text-sm font-semibold
                       hover:bg-cyan-500/20 hover:border-cyan-500/30 hover:shadow-cyan-glow
                       transition-all duration-300 active:scale-95"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Continue
          </button>
          <span className="text-[11px] text-gray-600">or type a message below</span>
        </div>
      )}

      <div className="flex items-end gap-2">
        <div className="flex-1 relative">
          <textarea
            ref={textareaRef}
            value={value}
            onChange={handleInput}
            onKeyDown={handleKeyDown}
            disabled={disabled}
            placeholder={disabled ? 'AI is working...' : 'Type a message...'}
            rows={1}
            className="w-full px-4 py-2.5 bg-gray-800/50 border border-gray-700/50 rounded-xl text-gray-100
                       placeholder-gray-600 text-sm resize-none focus:outline-none focus:border-cyan-500/40
                       focus:ring-1 focus:ring-cyan-500/15 focus:bg-gray-800 transition-all duration-200
                       disabled:opacity-40 disabled:cursor-not-allowed"
          />
        </div>
        <button
          onClick={handleSubmit}
          disabled={!value.trim() || disabled}
          className="flex-shrink-0 p-2.5 bg-cyan-500/15 text-cyan-400 border border-cyan-500/20
                     rounded-xl hover:bg-cyan-500/25 hover:border-cyan-500/30 transition-all duration-200
                     disabled:opacity-20 disabled:cursor-not-allowed active:scale-95"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
          </svg>
        </button>
      </div>

      {disabled && (
        <div className="typing-indicator flex items-center gap-1 mt-2 ml-2">
          <span />
          <span />
          <span />
          <span className="text-[11px] text-gray-600 ml-2 font-mono">processing...</span>
        </div>
      )}
    </div>
  );
}
