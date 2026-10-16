/** Tailwind configuration for VibeShield AI frontend. */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        severity: {
          critical: '#a21caf',
          high: '#dc2626',
          medium: '#d97706',
          low: '#2563eb',
          info: '#6b7280',
        },
      },
    },
  },
  plugins: [],
}
