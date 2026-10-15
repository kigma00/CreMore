// Literal bucket prefixes through the real narrowing controls. No server or provider calls.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { bundle } = require("./bundle-module.cjs");
const { ORIGIN, inBounds } = require("./console-proof.cjs");
const fs = require("node:fs");
const path = require("node:path");
const app = bundle({ React: "react", client: "react-dom/client", targets: "@/console/views/integrations/targets.tsx",
  model: "@/console/views/integrations/targets-model.ts", locale: "@/components/locale.tsx" },
{ extraExports: { "@/console/views/integrations/targets.tsx": "\nexport { Narrowing };" } });
const css = fs.readFileSync(path.join(__dirname, "../app/(console)/console.css"), "utf8");

async function main() {
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  try {
    for (const [width, language, theme] of [[390, "ko", "light"], [1280, "en", "dark"]]) {
      const context = await browser.newContext({ viewport: { width, height: 900 } });
      const errors = [];
      await context.addInitScript(data => { window.__fixture = data; }, app.data);
      const html = `<html data-theme="${theme}" lang="${language}"><head><meta name="viewport" content="width=device-width,initial-scale=1"><style>${css}</style></head>
        <body><div id="root"></div><script>${app.preamble}
        const item={id:'bucket',resource_type:'S3_BUCKET'};
        function Harness(){const [root,setRoot]=React.useState(model.defaultRoot(item));
          window.currentRoot=root;
          return React.createElement(locale.LocaleContext.Provider,{value:'${language}'},
            React.createElement('div', {style:{padding:16}},
              React.createElement(targets.Narrowing,{item,root,onRoot:setRoot,target:{kind:'aws',id:'account',sourceType:'s3',name:'test'}}),
              React.createElement('button',{disabled:!!model.rootProblem(root,'S3_BUCKET'),onClick(){
                window.saved=model.profileBody({roots:[root],snapshot:'snap',schedule:0,reason:'test',name:'scope'});
              }},'Save')));}
        client.createRoot(document.getElementById('root')).render(React.createElement(Harness));</script></body></html>`;
      await context.route("**/*", async route => {
        if (route.request().isNavigationRequest() && new URL(route.request().url()).origin === ORIGIN) {
          return route.fulfill({ contentType: "text/html", body: html });
        }
        errors.push(`unexpected request: ${route.request().url()}`);
        return route.abort();
      });
      const page = await context.newPage();
      page.on("pageerror", error => errors.push(error.message));
      try {
        await page.goto(ORIGIN);
        await page.getByRole("button", { name: language === "ko" ? "접두어로 지정" : "By prefix", exact: true }).click();
        const prefixes = page.getByLabel(language === "ko" ? "읽을 접두어" : "Prefixes to read", { exact: true });
        const exclusions = page.getByLabel(language === "ko" ? "제외할 접두어" : "Prefixes to skip", { exact: true });
        await prefixes.fill("approved/ \n \ncomma,name/");
        await exclusions.fill(" private/\nignore,exact/");
        await page.getByRole("button", { name: "Save", exact: true }).click();
        const root = (await page.evaluate(() => window.saved)).selected_roots[0];
        assert.deepEqual(root.prefixes, ["approved/ ", " ", "comma,name/"]);
        assert.deepEqual(root.excluded_prefixes, [" private/", "ignore,exact/"]);
        assert.equal(root.all_current_objects, false);
        await prefixes.fill("");
        assert.equal(await page.getByRole("button", { name: "Save", exact: true }).isDisabled(), true);
        assert.equal(await page.evaluate(() => window.currentRoot.all_current_objects), false);
        await prefixes.fill(" ");
        await page.getByRole("button", { name: "Save", exact: true }).click();
        assert.deepEqual(await page.evaluate(() => window.saved.selected_roots[0].prefixes), [" "]);
        await inBounds(page, `${width}/${language}/${theme}`);
        assert.deepEqual(errors, []);
      } finally { await context.close(); }
    }
    console.log("PASS literal S3 scope: spaces/commas preserved for inclusions and exclusions, whitespace-only restriction preserved, empty restriction never grants whole bucket; mobile/light/Korean and desktop/dark/English.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
