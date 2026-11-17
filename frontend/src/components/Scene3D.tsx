/**
 * Purely decorative backdrop. The editorial theme replaces the 3D scene with a
 * printed grid and paper grain — CSS-only, no WebGL, no pointer capture.
 */
export default function Scene3D() {
  return (
    <div className="scene" aria-hidden="true">
      <div className="scene-grid" />
      <div className="scene-noise" />
    </div>
  )
}
