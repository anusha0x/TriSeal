/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        console: {
          bg: '#080c14',
          surface: '#0f172a',
          card: '#131e36',
          border: '#1e293b',
          muted: '#64748b',
          text: '#f8fafc',
        },
        chamber: {
          red: '#ef4444',
          blue: '#3b82f6',
          llm: '#a855f7',
          arbiter: '#f59e0b',
        },
        sec: {
          pass: '#10b981',
          fail: '#f43f5e',
          warn: '#f59e0b',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Menlo', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
