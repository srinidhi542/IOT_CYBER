/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class', // Default is dark class
  theme: {
    extend: {
      colors: {
        background: {
          dark: '#030712',  // Gray 950
          card: '#0b0f19',  // Custom very dark blue-grey
          border: '#1e293b' // Slate 800
        },
        cyber: {
          primary: '#06b6d4', // Cyan 500
          secondary: '#6366f1', // Indigo 500
          accent: '#10b981', // Emerald 500
          warning: '#f59e0b', // Amber 500
          critical: '#f43f5e', // Rose 500
          muted: '#64748b' // Slate 500
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['Fira Code', 'Courier New', 'monospace']
      }
    },
  },
  plugins: [],
}
