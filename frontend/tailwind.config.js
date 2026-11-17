/**
 * Tailwind configuration for VibeShield AI frontend.
 *
 * Design language: editorial interface on matte black — the Preymaker
 * (DashDigital) typographic system inverted. Two colours carry almost
 * everything — matte black #0F0F0E and warm white #F6F5F0 — with hairline
 * rules instead of cards, shadows or gradients. The ramps below are
 * inversion-compatible with the class names already used across the app, so
 * `text-slate-100` resolves to warm white and `bg-slate-950` to the raised
 * matte surface.
 */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          '"Instrument Sans"',
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          '"Segoe UI"',
          'sans-serif',
        ],
      },
      colors: {
        slate: {
          50: '#171716', // raised matte surface
          100: '#f6f5f0', // primary white (headings)
          200: '#eae9e3',
          300: '#cfcec7', // body copy
          400: '#a5a49c', // muted
          500: '#8b8a83',
          600: '#7a7973', // faint / captions
          700: '#3a3a36', // hairline (as a solid)
          800: '#2a2a27',
          900: '#1f1f1d', // raised block, used at low opacity for rules
          950: '#121211', // matte surface (chips, code blocks)
        },
        /* Interaction accent: warm white itself, so links and focus read as type. */
        cyan: {
          50: '#171716',
          100: '#1f1f1d',
          200: '#2a2a27',
          300: '#6a6963',
          400: '#8b8a83',
          500: '#a5a49c',
          600: '#cfcec7',
          700: '#edece6',
          800: '#f6f5f0',
          900: '#fbfaf6',
          950: '#ffffff',
        },
        sky: {
          50: '#171716',
          100: '#1f1f1d',
          200: '#2a2a27',
          300: '#6a6963',
          400: '#8b8a83',
          500: '#a5a49c',
          600: '#cfcec7',
          700: '#edece6',
          800: '#f6f5f0',
          900: '#fbfaf6',
          950: '#ffffff',
        },
        /* Machine-written text (AI explanations) gets one warm stone accent so it
           can never be mistaken for scanner evidence. Lightened for dark ground. */
        violet: {
          100: '#2a2418',
          200: '#3c3322',
          300: '#c9b795',
          400: '#ad9a75',
          500: '#8f7c56',
          600: '#7a6844',
          700: '#d9c49b',
          800: '#e8d9ba',
          900: '#f2e8d4',
          950: '#fbf6ec',
        },
        /* Success keeps a quiet green: status is meaning, not decoration. */
        emerald: {
          100: '#12241a',
          200: '#193327',
          300: '#8ad4ab',
          400: '#6fbf93',
          500: '#58a97d',
          600: '#4fa57b',
          700: '#8ad4ab',
          800: '#b2e6c8',
          900: '#d6f3e2',
          950: '#ecfaf1',
        },
        /*
         * Severity keeps distinct hues: a risky finding must never read as the
         * white editorial accent. Values are lifted to stay legible on black.
         */
        severity: {
          critical: '#e879f9',
          high: '#f87171',
          medium: '#f0a64b',
          low: '#7eb6f2',
          info: '#8b8a83',
        },
      },
    },
  },
  plugins: [],
}
