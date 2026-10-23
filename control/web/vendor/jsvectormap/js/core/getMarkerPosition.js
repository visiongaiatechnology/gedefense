import maps from '../maps.js'

export default function getMarkerPosition({ coords }) {
  if (maps[this.params.map].projection) {
    return this.coordsToPoint(...coords)
  }

  return {
    x: coords[0] * this.scale + this.transX * this.scale,
    y: coords[1] * this.scale + this.transY * this.scale
  }
}