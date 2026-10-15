// Run the actual shared display module in the same synthetic VM test pattern as
// the panels. No formatter or preference behavior is stubbed.
const { load: loadModule } = require("./load-module.cjs");
const load = (globals = {}) => loadModule("@/components/display-timezone.tsx", { globals });
module.exports = { ...load(), load };
