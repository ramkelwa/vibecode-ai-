/** Tailwind configuration for VibeShield AI frontend. */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        /*
         * Forest palette taken from the supplied swatch stack:
         *   #0B1F1D  #0E2D28  #1F4A3F  #2D6A56  #6A9F8C  #EAFFE8
         *
         * The neutral ramp is anchored to those six steps, so every surface and
         * text tone already built on `slate` inherits them: 950 page (#EAFFE8),
         * 900 card surface (white), 800 borders (#C9DFD0), 600 muted
         * (#5C8F79), 400 secondary text (#2D6A56), 300 labels (#1F4A3F),
         * 200/100 body and main text (#14302A / #0B1F1D).
         */
        slate: {
          50: '#081613',
          100: '#0b1f1d',
          200: '#14302a',
          300: '#1f4a3f',
          400: '#2d6a56',
          500: '#42735d',
          600: '#5c8f79',
          700: '#9dc1ab',
          800: '#c9dfd0',
          900: '#ffffff',
          950: '#eaffe8',
        },
        /* Interaction accent: light steps for tints, deep steps for text/fills. */
        cyan: {
          50: '#effbee',
          100: '#ddf6d9',
          200: '#c2ebc3',
          300: '#a6d9b4',
          400: '#6a9f8c',
          500: '#4a8871',
          600: '#2d6a56',
          700: '#1f4a3f',
          800: '#163a31',
          900: '#0e2d28',
          950: '#0b1f1d',
        },
        /* Supporting accents, kept inside the same green family. */
        sky: {
          50: '#f0fbf3',
          100: '#ddf3e4',
          200: '#c0e5cf',
          300: '#9ccbb6',
          400: '#7ab39c',
          500: '#4f8d73',
          600: '#3a7660',
          700: '#2d6a56',
          800: '#1f4a3f',
          900: '#163a31',
          950: '#0b1f1d',
        },
        violet: {
          100: '#e2f2e8',
          200: '#c7e4d5',
          300: '#a3cdbb',
          400: '#7fb7a1',
          500: '#55947a',
          600: '#3d7a62',
          700: '#2f6a55',
          800: '#245544',
          900: '#1b4437',
          950: '#0d241d',
        },
        /* Success shares the accent so the UI stays monochrome-green. */
        emerald: {
          100: '#ddf6d9',
          200: '#c2ebc3',
          300: '#a6d9b4',
          400: '#6a9f8c',
          500: '#4a8871',
          600: '#2d6a56',
          700: '#1f4a3f',
          800: '#163a31',
          900: '#0e2d28',
          950: '#0b1f1d',
        },
        /*
         * Severity keeps distinct hues: a risky finding must not read as the
         * green accent. Only `info` follows the palette's secondary tone.
         */
        severity: {
          critical: '#a21caf',
          high: '#dc2626',
          medium: '#d97706',
          low: '#2563eb',
          info: '#3f7357',
        },
      },
    },
  },
  plugins: [],
}
