// Runs inline in <head> before the first paint, so a saved theme never flashes
// the wrong palette. Kept free of imports: a Server Component (the root layout)
// reads this string, and it must not be a client reference. The script is a
// fixed literal (nothing is interpolated into it); a test keeps the storage key
// below and the key inside the script in step.
export const themeStorageKey = "cremore.theme.v1";

export const themeInitScript =
  '(function(){try{var t=localStorage.getItem("cremore.theme.v1");if(t==="dark"||t==="light")document.documentElement.setAttribute("data-theme",t);}catch(e){}})();';
