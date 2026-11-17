import { useEffect, useRef } from 'react'

/**
 * Editorial cursor highlight — the interaction from the reference site.
 *
 * An ink disc follows the pointer and expands with a label over anything
 * clickable. Purely decorative: it never replaces the native cursor, it is
 * skipped on touch devices and for reduced-motion users, and assistive
 * technology never sees it.
 */
export default function Cursor() {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const el = ref.current
    if (!el || typeof window === 'undefined' || !window.matchMedia) return
    const fine = window.matchMedia('(pointer: fine)')
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)')
    if (!fine.matches || reduce.matches) return

    const root = document.documentElement
    root.classList.add('vin-cursor-on')

    let frame = 0
    let x = 0
    let y = 0

    const draw = () => {
      frame = 0
      el.style.transform = `translate3d(${x}px, ${y}px, 0)`
    }

    const onMove = (event: PointerEvent) => {
      x = event.clientX
      y = event.clientY
      if (!frame) frame = window.requestAnimationFrame(draw)
    }

    const onOver = (event: Event) => {
      const target = event.target
      if (!(target instanceof Element)) return
      const hit = target.closest(
        'button, a[href], [role="tab"], select, input, .vin-row, .vin-row-hover, .vin-nav-link',
      )
      if (!hit) {
        el.dataset.active = 'false'
        el.dataset.label = ''
        return
      }
      el.dataset.active = 'true'
      el.dataset.label = hit.matches('.vin-row, .vin-row-hover') ? 'OPEN' : 'SELECT'
    }

    const onLeave = () => {
      el.dataset.active = 'false'
      el.dataset.label = ''
    }

    window.addEventListener('pointermove', onMove, { passive: true })
    document.addEventListener('pointerover', onOver, true)
    document.addEventListener('pointerleave', onLeave)

    return () => {
      window.removeEventListener('pointermove', onMove)
      document.removeEventListener('pointerover', onOver, true)
      document.removeEventListener('pointerleave', onLeave)
      root.classList.remove('vin-cursor-on')
      if (frame) window.cancelAnimationFrame(frame)
    }
  }, [])

  return <div ref={ref} className="vin-cursor" aria-hidden="true" data-active="false" />
}
