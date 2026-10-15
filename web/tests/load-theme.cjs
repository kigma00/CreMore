// Load the real theme preference module (and its inline-script constants) in the
// same synthetic VM pattern as the other shared modules. Both are returned
// together because a test reads the script constants next to the component.
const { load: loadModule } = require("./load-module.cjs");
const load = (globals = {}) => ({
  ...loadModule("@/lib/theme-script.ts", { globals }),
  ...loadModule("@/components/theme.tsx", { globals }),
});
module.exports = { ...load(), load };
