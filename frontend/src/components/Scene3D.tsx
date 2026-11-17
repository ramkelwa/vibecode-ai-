/**
 * Purely decorative 3D backdrop: perspective grid floor, drifting light orbs,
 * a rotating wireframe horizon and a slow scan sweep. CSS-only, no WebGL.
 */
export default function Scene3D() {
  return (
    <div className="scene" aria-hidden="true">
      <div className="scene-orb scene-orb-a" />
      <div className="scene-orb scene-orb-b" />
      <div className="scene-orb scene-orb-c" />
      <div className="scene-rings" />
      <div className="scene-grid" />
      <div className="scene-sweep" />
      <div className="scene-noise" />
      <div className="scene-vignette" />
    </div>
  )
}
