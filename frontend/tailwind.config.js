/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      colors: {
        hades: {
          bg: '#030712',
          surface: '#0a0f1c',
          panel: '#111827',
          border: '#1e293b',
          accent: '#22d3ee',
        },
      },
      boxShadow: {
        'cyan-glow': '0 0 15px rgba(34, 211, 238, 0.15), 0 0 3px rgba(34, 211, 238, 0.1)',
        'cyan-glow-lg': '0 0 30px rgba(34, 211, 238, 0.2), 0 0 60px rgba(34, 211, 238, 0.1)',
        'red-glow': '0 0 15px rgba(239, 68, 68, 0.15)',
        'orange-glow': '0 0 15px rgba(249, 115, 22, 0.15)',
        'inner-light': 'inset 0 1px 0 rgba(255, 255, 255, 0.03)',
      },
      keyframes: {
        'bounce-dot': {
          '0%, 80%, 100%': { transform: 'scale(0)' },
          '40%': { transform: 'scale(1)' },
        },
        'pulse-glow': {
          '0%, 100%': { opacity: '1', boxShadow: '0 0 5px rgba(34, 211, 238, 0.3)' },
          '50%': { opacity: '0.6', boxShadow: '0 0 15px rgba(34, 211, 238, 0.5)' },
        },
        'fade-in': {
          from: { opacity: '0', transform: 'translateY(6px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        'slide-in-left': {
          from: { opacity: '0', transform: 'translateX(-12px)' },
          to: { opacity: '1', transform: 'translateX(0)' },
        },
      },
      animation: {
        'bounce-dot': 'bounce-dot 1.4s infinite ease-in-out both',
        'pulse-glow': 'pulse-glow 2s infinite',
        'fade-in': 'fade-in 0.3s ease-out',
        'slide-in': 'slide-in-left 0.3s ease-out',
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(ellipse at top, var(--tw-gradient-stops))',
      },
    },
  },
  plugins: [],
}
