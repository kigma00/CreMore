# 커밋 ID 대응표 — 2026-09-27

2026-09-27 `integration/saas-structure`의 커밋 메시지에서 공동 작성자 표기를 지우면서, `main`과 갈라진 뒤의
커밋 130개의 ID가 바뀌었다. 커밋마다 파일 내용(트리)·작성자·날짜는 같다. 저장소 문서의 커밋 ID는 새 ID로
고쳤다. GitHub Actions 실행 기록·이전 대화·외부 메모에 남은 이전 ID는 아래 표에서 찾는다.

| 이전 ID | 새 ID | 제목 |
|---|---|---|
| `908ec70` | `9d5dc84` | chore: ignore Playwright MCP output directory |
| `01b2036` | `daab6b6` | refactor: unify ownership and harden collection state |
| `ebb8931` | `a1c7c9f` | refactor: consolidate ownership and verify contracts |
| `3bf355b` | `9e78d43` | fix: support current FastAPI validation metadata |
| `115993e` | `7dd0b3e` | test: install complete schema contract dependencies |
| `e4b9277` | `d96bb8d` | docs: finalize refactor evidence and developer setup |
| `161d8dc` | `9f79b20` | feat: add durable SIEM output integrations |
| `f88b4cf` | `08b50fe` | test: verify eventual claims under PostgreSQL contention |
| `0d1f603` | `7df7d45` | docs: document SIEM integrations and team ownership |
| `dd6d34b` | `a23ff08` | refactor: modularize source provider ownership |
| `d736cbf` | `ddb8b73` | docs: record provider module ownership and verification |
| `7c5480b` | `04e89d1` | docs: add shared team agent instructions |
| `8a56abc` | `df7aaa2` | Refine dashboard UI and interaction coverage |
| `9fb1e9c` | `470cc10` | fix: align dashboard layouts across viewports |
| `592bcea` | `844ad00` | chore: remove unused standalone GCP container recipe |
| `00795ea` | `91d3d16` | refactor: organize provider libraries at repository root |
| `6a7eb59` | `b13758d` | refactor(gcp): share connector library with provider |
| `c022238` | `c13b5b7` | fix: resolve provider import cycles and review findings |
| `82821b5` | `296cf33` | fix: resolve final review regressions |
| `4fcee7f` | `5096062` | docs: record Docker validation results |
| `c19f137` | `1551f19` | docs: sync team guidance with verified layout |
| `91632c7` | `2243dfb` | feat: expand provider inventory and vault evidence |
| `692d5fa` | `8501637` | docs: align team guide with provider contracts |
| `1f28b30` | `f55eb36` | fix(coverage): let a disabled vault leave the comparison scope |
| `ca6004d` | `ab320f3` | fix(coverage): judge GCP service-account keys absent by key ID |
| `5067f04` | `126935a` | feat(coverage): count issued credentials by vault verdict |
| `99c8482` | `08fe61a` | fix(scanning): refresh exposures a delta listing shows unchanged |
| `7a12dc5` | `86f11b8` | feat(detection): detect Microsoft Entra client secrets |
| `9e9651a` | `e17f7a7` | docs: record the coverage verdict fixes and their verification |
| `f0fb506` | `0e5488f` | fix(detection): accept a leading dash in Entra client secrets |
| `5f49e0c` | `a8c5a7c` | fix(verify): keep GitLab tokens of unconfirmed issuers off GitLab.com |
| `b4362af` | `af42ea0` | feat(detection): detect Azure SAS tokens and link them to storage accounts |
| `dbb9d3a` | `5272825` | feat(coverage): rank issued tokens by the owner verification reported |
| `ed1d64b` | `d7fc95c` | feat(coverage): report Entra certificates missing from confirmed vault reads |
| `67d1df9` | `2e35a32` | feat(detection): catch older Entra secrets beside Azure config names |
| `11e8b35` | `84bd2c4` | docs: record the no-raw-transmission fixes and GitHub hash wording |
| `0f3f4ee` | `959f419` | feat(verify): identify GitLab.com tokens exactly and fix owner ranking |
| `fbe9e6f` | `d8146e0` | feat(coverage): link exposed GitHub tokens to their audit-log activity |
| `7285afa` | `51c2a0b` | feat(coverage): confirm which storage key signed an exposed Azure SAS |
| `16d25e1` | `77627df` | feat(coverage): let the worker collect AWS Secrets Manager and SSM on opt-in |
| `aa11c93` | `d415e93` | feat(coverage): collect the installation's own Vault/OpenBao on the server |
| `2cc52d8` | `aaab297` | docs(gcp): say when to use each Secret Manager comparison path |
| `7f2f9da` | `8714a7c` | feat(azure): scan Azure Blob Storage containers as a content source |
| `f42f986` | `1c06fff` | feat(azure): scan Azure DevOps Repos as a content source |
| `194edca` | `81121bd` | docs: record the remaining no-raw-transmission items and their checks |
| `fec12cc` | `7a92471` | feat(detection): detect Azure DevOps personal access tokens |
| `c27fd59` | `7ced8e5` | feat(coverage): schedule server collection of the installation's Vault |
| `73b9d36` | `5c14977` | feat(github): add token-authenticated Git events to audit token activity |
| `3d4f73e` | `1da4105` | feat(azure): confirm the signing key of Table and older service SAS |
| `aa1efb5` | `6e50de3` | feat(azure): scan Azure DevOps Server collections and a chosen branch |
| `1ccb32e` | `fb989d3` | feat(azure): scan a project's TFVC tree in the Azure DevOps source |
| `96d7b0e` | `dd1765b` | feat(azure): collect the Azure DevOps personal access token inventory |
| `059114d` | `b426425` | test(detection): keep the Azure DevOps PAT URL sample out of repository scans |
| `759595f` | `1d645b8` | docs: record the follow-up green and blue items and their checks |
| `6757746` | `bd8b440` | fix(web): say GitHub token activity now includes recent Git events |
| `440cf72` | `e1ee0ea` | fix(web): name the Azure Blob Storage and Azure DevOps providers |
| `de241c9` | `729173c` | fix(evidence): say Azure sources have no original link, not missing coordinates |
| `e2d74a6` | `53161bb` | fix(web): name the Azure credential types, detector provider and Blob identity |
| `57aadd4` | `45497d2` | fix(web): let Azure Blob and Azure DevOps connections record a declaration |
| `a988aa5` | `bc06ef0` | docs: bring the README up to date with the current sources and coverage |
| `651ffb2` | `6616dae` | feat(evidence): open Azure DevOps Git findings at the detected commit |
| `c381934` | `064c15d` | chore: stop tracking local AI-tooling session state |
| `1d14cd7` | `16ea6b0` | feat(gcp): add dashboard OAuth onboarding and worker authentication |
| `190f892` | `143c4e0` | docs(gcp): record validation against latest refactoring |
| `997d879` | `311c626` | fix(gcp): list discovery with the OAuth user's token, never the worker ADC |
| `20500f3` | `089f856` | refactor(coverage): let provider libraries import contracts without the DB layer |
| `167794a` | `aec56f9` | test: guard provider library boundaries the way refactor/saas-libraries did |
| `74e4237` | `12061a3` | fix(api): keep the collector's OpenAPI schema names after the GCP OAuth merge |
| `6c00f83` | `a9b34ce` | refactor: derive platform source lists from the content-source registry |
| `3fe7af9` | `826da28` | refactor(coverage): declare the machine-record guard in the adapter registry |
| `6b1956b` | `be8652c` | ci: check the installed wheel outside the checkout |
| `e02fe23` | `5de815e` | chore(scripts): add import and collector benchmarks for refactor comparisons |
| `76890d9` | `9f950a3` | test: tighten the boundary and source-list parity checks after review |
| `211a895` | `ed5467c` | fix(scripts): make the installed-wheel check mirror hatchling |
| `1100417` | `7f8c943` | refactor(api): prefix every GCP OAuth request model with GcpOAuth |
| `c565f47` | `2e4db59` | docs(code): explain the moved imports and INSTANCE_SCOPED where they live |
| `8d90401` | `8e92cfe` | docs: record the SaaS-structure integration with evidence and a hand-off prompt |
| `87f39b5` | `39aacff` | fix(gcp): check service-account key identifiers without a key-shaped literal |
| `8b08c28` | `5c88cc5` | feat(gitlab): verify self-managed tokens on the registered instance they were found in |
| `6de6568` | `570d0e7` | fix(gcp): wait and resume when Google's token service asks to retry |
| `c11d51a` | `52e05da` | test: guard against optional-SDK imports in the registry path and cross-provider imports |
| `96f5cd0` | `de7c6a9` | fix(scripts): compare every bench sample, resume state and request order |
| `e31bd06` | `c595e94` | test(gcp): run the OAuth API tests on PostgreSQL and race one session's completion |
| `6319895` | `af6f4c7` | test(coverage): port the schema-2 PostgreSQL publication and resume tests |
| `e348089` | `3d59233` | test(worker): port the content contract tests and cover both Azure collectors |
| `a152fcf` | `ffd80c3` | ci: check the wheel as the image installs it, run its tests, and gate PRs on boundaries |
| `52d3e58` | `b72e76e` | docs+test: name the platform flows in the AWS folder and pin its import-time DB module |
| `f881262` | `c9f3f45` | refactor(github): resolve the secret-scanning credential in the worker |
| `ad7504c` | `482c514` | perf(coverage): rank finding candidates from one lean read, detail only the shown page |
| `0731bb4` | `823a1c3` | perf(coverage): read Azure SAS candidates in three queries instead of three per finding |
| `2079160` | `e4f01ce` | fix(azure): list a DevOps tree past the response cap folder by folder |
| `ea0f97c` | `fac0b7f` | docs: propose the operating policy for options that read secret values |
| `3655e6c` | `5b7ec41` | docs(integration): record the review follow-ups, final checks and the base-structure proposal |
| `86168d1` | `8478baf` | docs(integration): record the full CI run of the reviewed branch |
| `e7cbe11` | `f4ab0a9` | fix(github): follow the audit log's two-cursor next link |
| `df6ce5b` | `f8bee25` | fix(github): key inventory credentials by credential id or SSH fingerprint |
| `4519cc4` | `5e2a8bf` | feat(github): choose the Actions run period, the audit logs to read and an Enterprise-only read |
| `976f08d` | `52fa140` | feat(github): read the Enterprise audit log with a sealed classic PAT only |
| `3466449` | `01df17a` | feat(github): link audit entries to the credentials they name, exactly or not at all |
| `9ab6439` | `e462c55` | feat(github): take the App ID or its Client ID and confirm the App with GET /app |
| `e537cb5` | `fe74768` | feat(github): name each read's App permission and judge every organization's installation by it |
| `a56b5c5` | `9eb2705` | feat(github): re-check one organization's installation or refresh the App's installation list without collecting |
| `7ec77bb` | `896d874` | feat(github): bound a collection run's wall-clock time |
| `8c5e575` | `70933b5` | fix(github): declare the installation-check planner's coverage.errors import |
| `4509a20` | `041becb` | feat(coverage): pause, resume or stop a metadata collection |
| `ceb4f2e` | `95ae835` | fix(web): show the GitHub organization options the adapter actually reads |
| `15923df` | `876b595` | feat(github): collect outside the product with its own adapter, and submit the run |
| `0d7e1a3` | `d70d43a` | feat(github): read audit entries against their credentials, filtered by relation |
| `c4f38a8` | `2d2cc67` | docs(integration): record the develop_github port, its shared-file changes and checks |
| `96ece65` | `2028d27` | fix(github): keep the App label out of the connection check's workspace |
| `0a0a740` | `8061349` | fix(coverage): read stored contracts through today's model when an option was added |
| `05b3592` | `6b444ea` | fix(github): find the collection behind any number of checks, and trust a listing only for what it planned |
| `7932b7a` | `5f0549e` | fix(coverage): keep a pause and the time limit inside a run's lifetime |
| `364d0c2` | `d2bb88e` | fix(github): bound the audit-link view and stop re-reading a finished run |
| `93ff916` | `ed46b12` | Revert "fix(web): show the GitHub organization options the adapter actually reads" |
| `f027059` | `760d9b0` | chore(github): remove what the port added without use |
| `97adf29` | `7bd5958` | docs(integration): record the review follow-ups of the develop_github port |
| `0f3ef43` | `eb8f28e` | fix(github): fail the run when the App cannot be confirmed or its key cannot sign |
| `853bd0e` | `5a2348c` | fix(github): leave the connection as it is when removing an audit token that is not set |
| `c108407` | `97ee021` | fix(coverage): leave out an optional secret role the worker cannot resolve |
| `0e23d49` | `3b73f93` | fix(coverage): end a collection paused before its run opened, and read a pause with the check |
| `37a56f5` | `8c67c9b` | fix(github): judge an unread organization by every read the connection would make |
| `02a29ea` | `c11d228` | fix(github): keep the App's lookup of its own installation apart from the listed installation |
| `ace4f53` | `f02a3b3` | docs(integration): record the LOW review fixes of the develop_github port |
| `e1d696f` | `057aa9a` | perf(aws): read only this account's CloudTrail logs for its regions and window |
| `a9f83e8` | `7d7654f` | fix(web): say when a GitHub run has more audit entries than the link view joins |
| `fd58c93` | `fbb891f` | feat(web): download a run's native export, read reason codes in words, mark optional roles |
| `70fabab` | `25c9f98` | chore: remove the standalone GCP and GitLab command-line tools |
| `78b6f87` | `f4fbb5d` | fix(atlassian): port the verified Preview OAuth contracts from main |
| `3120aee` | `2065332` | docs: bring the README and the integration record up to date |
