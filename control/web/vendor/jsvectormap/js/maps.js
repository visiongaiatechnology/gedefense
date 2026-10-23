/**
 * jsVectorMap registry bridge.
 *
 * The map class and the core mixins used to import each other, which is a
 * circular dependency. Native ES modules evaluate `map.js` before the core
 * module has initialized its default export, producing
 * "Cannot access 'core' before initialization". The registry is a leaf module
 * with no imports, so both sides can share it without a cycle.
 */
const maps = Object.create(null)

export default maps
