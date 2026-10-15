# 공통 문서 스캔

`cremore/scanning/service.py`는 수집기가 전달한 파일 바이트를 공통 추출기에 넘긴 뒤 기존 탐지기를
실행한다. 공급자 승인·수집 범위·다운로드 크기 제한은 그대로 적용된다. 공급자가 먼저 파일을
제외하거나 파일 바이트를 제공하지 않으면 이 기능만으로 수집 범위가 확대되지 않는다.

## 지원 범위

| 형식 | 추출 내용과 제한 |
| --- | --- |
| TXT·일반 텍스트 | UTF-8과 BOM이 있는 UTF-16/UTF-32. UTF-8이 아닌 텍스트(NUL 없이 제어 바이트가 1/16 이하)는 CP949(EUC-KR 포함)로 엄격하게 읽고, ASCII 바이트가 하나라도 사라지면(확장 음절, 뒤 문자를 삼킨 cp1252 바이트) latin-1 읽기를 뒤에 덧붙여 두 가지를 모두 검사. CP949로 안 읽히면 latin-1로 끝까지 읽어 완료로 처리. 제어 문자(터미널 색 코드, NUL, DOS Ctrl-Z)는 줄바꿈으로 바꿔 전체를 읽고, UTF-8이면 그 안의 UTF-16LE 연속열도 덧붙임. 구형 인코딩 텍스트 안에 압축·PDF·암호화 표지가 있으면 불완전. 디코딩되지 않고 NUL이나 제어 바이트가 많으면 아래 바이너리 문자열 검사 |
| 바이너리 | ELF·PE·Mach-O 실행 파일, Java class, SQLite DB와 디코딩되지 않고 NUL이나 제어 바이트가 많은 그 밖의 미지원 바이트. 인쇄 가능한 문자열만 검사(형식 `binary`). 압축·PDF·암호화 표지가 보이면 불완전 |
| PDF | `pypdf`의 페이지 텍스트·주석·폼 위젯 값·URI 문자열. 처음 1024바이트 안의 `%PDF-` 앞에 BOM·공백·줄바꿈·NUL만 있으면 그것을 떼고 PDF로 읽음(다른 내용이 앞에 있으면 PDF로 보지 않아 그 내용을 버리지 않음). 암호화, 텍스트 없는 페이지, 미처리 그래픽·첨부는 불완전 |
| DOCX·PPTX·XLSX 및 같은 구조의 매크로 문서 | ZIP 안 XML의 본문·머리말·주석·문자열·셀·슬라이드와 링크 문자열. 매크로·미처리 바이너리·이미지는 불완전 |
| DOC | Word 97–2003 호환 FIB/Clx/PlcPcd의 Unicode/압축 텍스트와 보조 문서 영역. 오래된 Word 형식·암호화·미처리 삽입 개체는 불완전 |
| XLS·PPT 등 그 밖의 OLE 파일 | 스트림마다 섹터 순서대로 이어 붙인 내용의 바이너리 문자열 검사(형식 `ole-strings`). 파일 바이트를 그대로 읽지 않는 것은 스트림의 섹터가 파일 안에서 떨어져 있을 수 있어 경계에 걸친 값이 둘로 끊기기 때문이다. XLS(BIFF8)의 공유 문자열 표(SST)는 8224바이트를 넘으면 CONTINUE 레코드로 이어지고 그 경계에서 잘린 문자열 사이에 레코드 머리와 문자 폭 표지 바이트가 끼므로, 표를 해석해 잘린 문자열을 이어 붙이고(서식·발음 정보가 경계를 넘어도 이어 읽음) 그 영역은 원래 바이트의 문자열 검사에서 뺀다. 이어 붙인 문자열도 다른 스트림처럼 8자 이상의 인쇄 가능한 연속열만 검사하도록 8비트 문자열과 UTF-16 문자 문자열을 따로 모아 같은 문자열 검사에 넘기므로, 한글이나 짧은 셀이 많아도 텍스트 한도를 더 쓰지 않는다. 선언한 문자열 수 뒤에 남은 표 바이트는 원래 바이트로 읽는다. 표를 해석하지 못하면 그 영역도 원래 바이트로 읽고 `MALFORMED_DOCUMENT`로 불완전. 스트림 크기의 합이 파일보다 큰(섹터 체인이 서로 겹친) 디렉터리나 읽히지 않는 스트림이 있으면 파일 바이트 전체의 문자열을 읽고 `MALFORMED_DOCUMENT`로 불완전. 스트림은 압축을 풀지 않고 저장된 그대로 읽으며, 크기 합을 파일 크기와 먼저 비교하므로 멤버 크기 한도 대신 입력 한도로 제한된다. 메모·텍스트 상자(TxO)의 글과 수식 문자열 결과(String)도 같은 방식으로 CONTINUE 레코드마다 문자 폭 표지 뒤에 이어지므로, 레코드를 해석해 이어 붙이고 그 바이트는 원래 바이트의 문자열 검사에서 뺀다. 선언한 글자 수만큼 이어지지 않는 글은 원래 바이트로 읽고 `MALFORMED_DOCUMENT`로 불완전. 완료는 `Workbook`/`Book` 스트림이 있는 XLS와, `PowerPoint Document` 스트림에 압축된 삽입 개체·VBA 레코드(ExOleObjStg, 0x1011)가 없는 PPT뿐이다(컨테이너 레코드 안까지 확인). 암호화 XLS(FilePass)·PPT(CurrentUser 암호 표지)는 `ENCRYPTED_DOCUMENT`, 매크로(`_VBA_PROJECT_CUR`·`_VBA_PROJECT`·`Macros`·`VBA`)·삽입 개체(`ObjectPool`·`MBD…`)·메일 첨부(`__attach_version1.0_…`) 저장소가 있거나 그 밖의 OLE 파일(MSI 설치 파일, Visio, Outlook `.msg` 등 압축 스트림을 쓰는 형식)이면 문자열은 그대로 쓰되 `EMBEDDED_CONTENT`(문자열이 없으면 `UNSUPPORTED_OLE_FORMAT`)로 불완전 |
| HWP | HWP 5.0의 OLE `DocInfo`와 `BodyText/SectionN`, 비압축/DEFLATE 문단 텍스트·중첩 문단. 다른 주 버전·암호/배포/DRM 문서는 제외 |
| HWP 3 | `HWP Document File`과 고정 꼬리(`\x1a\x01\x02\x03\x04\x05`)로 판별해 파일 전체를 바이너리 문자열 검사(형식 `hwp3-strings`). 16비트로 저장된 영문·숫자 문자열을 읽음. 문서 정보의 암호 표지(파일 오프셋 126)는 `ENCRYPTED_DOCUMENT`, 압축 표지(오프셋 154)는 본문을 풀지 않으므로 `EMBEDDED_CONTENT`로 불완전 |
| HWPX | ZIP `Contents`의 XML 텍스트. 이미지·미처리 삽입 개체는 불완전 |
| ODT·ODS·ODP | ODF ZIP의 XML 텍스트. 암호화·미처리 이미지/개체는 불완전 |
| RTF | `striprtf`의 본문 및 머리말·꼬리말·각주·주석. 확장 destination·이미지·삽입 개체는 불완전 |
| ZIP·TAR·gzip·bzip2·xz | RAM에서 읽은 일반 파일을 재귀 검사. 멤버도 같은 형식 판별을 거쳐 바이너리 멤버는 문자열 검사. 암호화·특수 파일·미지원 멤버·한도·손상은 불완전. 연결된 압축 스트림은 첫 스트림만 검사하고 불완전 표시 |
| 이미지·오디오·영상·글꼴·PSD | PNG·JPEG·GIF·TIFF·ICO·WebP·엄격한 BMP 헤더, MP4·MOV·3GP·M4A·HEIC·AVIF(ISO BMFF `ftyp`), MP3·WAV·AVI·MKV/WebM·Ogg·FLAC·MIDI, 글꼴 종류까지 확인한 WOFF/WOFF2·OpenType, PSD/PSB. 텍스트로 읽지 않고 `MEDIA_FORMAT`으로 건너뜀 |
| 7z·RAR·zstd·LZ4·Unix compress(.Z)·LZMA-alone | 압축을 풀지 않고 `UNSUPPORTED_FORMAT`으로 건너뜀 |

OCR과 이미지·오디오·영상 안 텍스트, 7z/RAR/zstd/LZ4/.Z/LZMA-alone 압축 해제, 암호화 문서는 지원하지 않는다.
썸네일·미리보기는 중복 표현으로 제외하며 본문 이미지가 있으면 불완전 상태를 유지한다.
문서 레이아웃을 렌더링하거나 외부 링크·템플릿·프로그램·매크로를 실행하지 않는다.
파일명·MIME 대신 바이트로 형식을 판별하므로 같은 Git blob을 다른 이름으로 옮겨도 추출 의미가 같다.
짧은 ASCII 서명은 다음 구조 바이트까지 확인한다. 예를 들어 `BMW config`로 시작하는 텍스트는 BMP가
아니고, `ID3 `·`OTTO `·`wOFF `·`Rar! `·`MZ`로 시작하는 일반 텍스트도 텍스트로 읽는다(PE는 `MZ` 헤더가
가리키는 `PE\0\0`까지, RAR는 `Rar!\x1a\x07`까지 확인). `%PDF-`를 언급하는 텍스트는 끝에 `%%EOF`가
있어도 텍스트로 읽고, 저장된 HTTP 헤더처럼 PDF 앞에 내용이 있는 파일은 그 내용을 버리지 않는다.
오프셋 0에서 시작하는 다른 컨테이너(ZIP 안에 저장된 PDF 등)가 먼저다.

## 바이너리 문자열 검사

`strings(1)`과 같은 방식으로 길이 8자 이상인 인쇄 가능한 ASCII 연속열(탭 포함)과 UTF-16LE
연속열(상위 바이트 0인 같은 문자 범위, 8자 이상)을 찾아 ASCII, UTF-16LE 순으로 줄바꿈으로 이어
탐지기에 넘긴다. 결과는 추출 텍스트 한도(기본 16 MiB) 안에서 만들고 넘치면 잘라 `TEXT_LIMIT`
불완전으로 표시한다. 바이트 분류표 하나로 연속열을 찾으므로 정규식보다 몇 배 빠르다.
바이너리 안의 압축·암호화·다른 인코딩 영역, 8자보다 짧은 조각, 인쇄할 수 없는 바이트로 끊긴 값과
한글 등 비ASCII 문자열은 찾지 못한다. 그래서 바이트 어디에든 컨테이너 표지(`PK\x03\x04`, `%PDF-`,
예약 플래그·XFL·OS 바이트까지 맞는 gzip 머리 10바이트, 7z, `Rar!\x1a\x07`, bzip2 `BZh?1AY&SY`, xz,
zstd)가 있으면 `EMBEDDED_CONTENT`,
암호화 표지(OpenSSL `Salted__`, git-crypt `\x00GITCRYPT\x00`)가 있으면 `ENCRYPTED_DOCUMENT`로 불완전
표시한다(자체 압축 해제 실행 파일, 암호화된 blob 등). 읽은 문자열의 양성 탐지는 그대로 쓴다.
완료는 이런 표지가 없는 바이트를 끝까지 문자열 검사했다는 뜻이다.
최상위 텍스트·바이너리·HWP 3는 파서 프로세스 없이 스캔 프로세스 안에서, 압축 파일·문서 안의 멤버와
OLE 파일은 파서 프로세스 안에서 같은 함수로 검사한다. 스캔 프로세스 안의 이 경로는 시간 제한 없이
선형으로 돈다. 50 MiB 합성 입력(무작위 바이트, 짧은 연속열 반복, CP949·latin-1·UTF-8 텍스트) 측정은
Windows 개발 PC에서 입력당 0.1–1.0초, 추가 메모리 100–200 MiB(입력의 2–4배)였다.

## 예산과 원문 비보관

`ExtractionLimits` 기본값은 입력 50 MiB, 누적 확장 64 MiB, 멤버 16 MiB, 추출 텍스트 16 MiB,
멤버 512개, PDF 500쪽, 중첩 3회, 파일당 파싱 15초, 파서 메모리 512 MiB다.
중첩 문서도 한 누적 예산을 공유한다. PDF 이외 문서의 시각적 페이지 수는 계산하지 않으며
바이트·멤버·시간·메모리 한도로 제한한다. 상한을 맞추기 위해 잘린 내용은 완료로 처리하지 않는다.

일반 텍스트와 바이너리 문자열은 직접 검사하고 문서 파서는 별도 Python 프로세스에서 실행한다.
입력과 추출 결과는 익명 파이프와 RAM으로만 전달한다. 원문·압축 멤버·추출 결과·파서 오류를
파일·DB·로그에 저장하지 않는다. 파서의 로그·경고·stderr도 억제한다.

### 파서 서버(POSIX)

`os.fork`가 있는 POSIX(Linux·macOS)에서는 스캔 프로세스마다 파서 서버 하나를 첫 문서에서 띄운다.
서버는 `worker.py`와 같은 방식으로 시작한다. 고정된 형제 스크립트(`extraction/server.py`)를
`-B -E -s`로, 상속 핸들 없이 별도 프로세스 그룹에서 실행한다. 스캔 프로세스의 환경변수(수집
자격증명·프록시·클라우드 신원·DB 주소)는 하나도 넘기지 않고 glibc 할당기 설정
`MALLOC_MMAP_THRESHOLD_=131072`만 준다. 서버는 파서 라이브러리를 한 번만 읽어 둔 단일 스레드
프로세스이고 요청을 한 번에 하나씩 처리한다(스캔 프로세스 쪽은 잠금으로 직렬화). 서버 하나는
스캔 프로세스(작업 실행기)마다 약 40 MB(Linux 측정 VmSize)를 더 쓴다.

- 문서마다 서버를 fork한 새 자식이 파싱한다. 자식이 바꾼 것은 다음 문서로 이어지지 않는다. 자식은 서버의
  프로토콜 파이프를 쓰지 않는다.
- 서버는 요청 머리줄을 1바이트씩 읽어 문서 바이트를 버퍼에 남기지 않고, 문서와 자식의 출력을 자기가
  할당한 버퍼에만 받는다. 응답을 보낸 뒤 그 버퍼를 0으로 덮고 놓으므로 다음 자식은 이전 문서의 입력·추출
  텍스트를 해제된 메모리에서도 물려받지 않는다. 큰 블록은 고정 mmap 임계값으로 해제 즉시 운영체제에
  돌아가 이전 응답 크기가 다음 자식의 메모리 한도에 영향을 주지 않는다.
- 자식은 `RLIMIT_AS`(파서 메모리 한도)와 `RLIMIT_CORE=0`을 걸고, 서버가 먼저 죽어도 남지 않도록 CPU 시간
  한도를 보조로 둔다. 문서 바이트를 받는 서버 자신도 core dump를 금지한다.
- 서버는 `limits.seconds`가 지나면 자식을 SIGKILL로 끝내고 `PARSE_TIMEOUT`을 돌려준다. 자식이 0이 아닌
  상태로 끝나거나(SIGSEGV 등 신호 포함) 출력이 한도를 넘으면 `PARSER_RESOURCE_LIMIT`, 출력 형식이 깨지거나
  형식·사유가 고정 어휘 밖이면 `PARSER_FAILURE`로 문서마다 프로세스를 띄우는 경로와 같은 규칙을 쓴다.
  서버가 보내지 않은 SIGKILL(OOM killer 등)로 죽은 자식은 문서 탓이 아니므로 재시도 사유
  `PARSER_UNAVAILABLE`이다. 자식이 신호로 죽으면 다음 문서는 새 서버가 읽는다(같은 메모리 배치에서 충돌을
  반복하지 않음).
- 서버가 프로토콜을 어기거나 파이프를 닫거나 `limits.seconds`+30초 안에 답하지 않으면 그 서버를 버리고
  다음 문서에서 새로 띄운다. 그 문서는 재시도 사유(`PARSER_UNAVAILABLE`, 무응답은 `PARSE_TIMEOUT`)로 남는다.
  비정상 종료한 서버의 프로세스 그룹은 SIGKILL로 정리해 파싱 중이던 자식이 남지 않는다.
  서버는 문서 500개마다 새 프로세스로 바꾼다.
- 기다리는 동안(다른 스레드의 요청을 기다리는 시간 포함) 최소 0.2초마다 진행 확인을 호출한다. 취소·리스 검사
  예외가 나면 서버를 닫아 실행 중인 자식을 종료·수거하게 한 뒤 예외를 그대로 전달한다.
  스캔 프로세스가 fork되면 자식 쪽은 부모의 서버를 쓰지 않고 자기 서버를 띄운다.
- 자식의 주소 공간에는 미리 읽은 파서 라이브러리가 들어 있어 같은 메모리 한도에서 새 인터프리터보다
  문서에 쓸 수 있는 메모리가 그만큼(약 40 MB) 적다. 합성 측정에서 문서마다 프로세스는 80 MiB 한도로
  끝낸 문서가 서버 경로에서는 120 MiB 한도를 요구했다. 기본 512 MiB 한도에서는 이 차이만큼 여유가 줄어든다.

Windows에는 `os.fork`가 없어 문서마다 `worker.py` 프로세스를 새로 띄우는 기존 경로를 그대로 쓴다.
POSIX는 `RLIMIT_AS`와 core dump 금지, Windows는 Job Object의 프로세스 메모리 한도를 적용한다.
한도를 설정하지 못하거나 자식이 종료되면 불완전 결과를 반환한다. 이는 운영체제 보안 sandbox가
아니며, 문서 라이브러리 자체의 결함을 모두 격리한다고 주장하지 않는다.
호스트 swap·운영체제 crash dump 보존 정책은 설치 운영자의 별도 책임이다.

공급자 읽기·추출·탐지는 fenced DB 쓰기 트랜잭션 밖에서 수행한다.

## 완료·캐시·근거

추출이 일부 성공하면 얻은 텍스트의 양성 탐지는 저장한다. 암호화·손상·이미지·누락된 내부
참조·상한·시간 초과는 이전 노출이 제거되었다는 근거가 되지 않으며, 불완전 결과는 해당 리소스의
부재 판정을 실행하지 않는다. 다시 읽어 결과가 달라질 수 있는 사유는 `RETRYABLE_REASONS`
(`PARSE_TIMEOUT`, `PARSER_UNAVAILABLE`)뿐이다. 그 밖의 사유는 같은 바이트와 추출 캐시 digest에서
항상 같으므로 다시 읽어도 더 검사할 수 없다. 원래 공급자의 리소스·위치·revision은 유지한다.
탐지의 행 번호는 추출된 논리 텍스트 기준이며 원본 문서의 시각적 쪽/행 번호가 아니다.

`cache_digest(engine_digest, limits=...)`는 탐지기 digest에 추출기 epoch·예산·설치된 파서 버전을
결합한다. 스캔 실행부의 루트 정책도 같은 함수를 사용해야 하며 공급자의 선행 파일 필터와
캐시 소비자도 같은 digest를 사용한다. 기존 탐지기 digest만 쓴 캐시를 완료 결과로 재사용하지 않는다.
바이너리·인코딩·미디어 판별이 바뀐 2026-10-09 변경에서 `EXTRACTOR_EPOCH`를 2로, OLE 스트림을 섹터
순서대로 읽고 Excel 공유 문자열 표를 이어 붙이게 된 2026-10-10 변경에서 3으로, Excel 메모·텍스트 상자·수식
문자열 결과를 이어 붙이게 된 2026-10-11 변경에서 4로 올려 이전 추출 결과를 무효화했다. epoch는 `detection_policy_digest`에도 들어가므로 배포 뒤에는 이전에 검사한
모든 승인 루트가 다른 digest를 갖게 되고 `poll_policy_sweeps`가 루트마다 룰 변경 재검사(`POLICY_SWEEP`,
전체 재검사)를 넣는다. 다만 업그레이드 전에 승인된 범위 중 전체 검사 주기가 있는 범위는 업그레이드 뒤 처음 접수되는 전체 검사(기본 다음 날
02:00~06:00 KST의 범위별 시각)가 끝날 때까지 재검사를 넣지 않고, 그 전체 검사가 새 epoch로 먼저 다시 읽는다([업그레이드 주의](SCANNING_IMPLEMENTATION.md#전체변경분-검사-주기와-설치-기본값-2026-10-10)).
그 시간대에 다운로드·추출 부하가 생긴다. 그 사이의 변경분 실행은 이 이유로 전체 읽기가 되지 않는다. 전체 검사가 꺼진 범위는 배포 직후 재검사를 받는다. 예전 결과의 `BINARY_CONTENT`·
`UNSUPPORTED_ENCODING` 사유는 새 추출에서 더 나오지 않는다. `UNSUPPORTED_OLE_FORMAT`은 인쇄 가능한
문자열이 하나도 없는, 통합 문서·프레젠테이션이 아닌 OLE 파일에만 나온다.
`ScanSummary.extraction_reasons`는 고정 상태 코드별 건수이고 리소스의 `document_format`과
`document_extraction_status`도 고정 값만 가진다. worker는 task checkpoint와 최종 coverage에
사유별 수를 누적하며 API의 `extraction_reasons`와 수집·탐지 현황 상세의 문서 읽기 제한에 표시한다.
중지·예산 소진 결과에도 이미 확인한 사유를 보존한다. 공개 응답은 bounded 코드·정수만 허용한다.

S3·GCS·Blob, GitHub·GitLab·Bitbucket·Azure Repos, Confluence 첨부에서 내려받은 바이트가
같은 경로를 사용한다. 웹사이트도 명시적으로 승인한 시작 URL의 PDF/Office/HWP를 이 경로로
보낸다. 웹사이트는 링크된 임의 문서를 자동 탐색하지 않으며 기존 확인 도메인·주소 고정·경로
검증을 거친다. Notion은 API가 반환한 페이지 본문을 읽으며 외부 파일 URL을 임의 다운로드하지 않는다.

## 근거와 검사

- [pypdf 추출 문서](https://pypdf.readthedocs.io/en/stable/user/extract-text.html): 텍스트 추출과 OCR의 차이, 페이지 스트림 메모리 비용.
- [MS-DOC](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/ccd7b486-7881-484c-a137-51170af7cc22): Fib, FibRgLw97, Clx, PlcPcd, FcCompressed.
- [Hancom HWP 5.0 공개 명세](https://cdn.hancom.com/link/docs/%ED%95%9C%EA%B8%80%EB%AC%B8%EC%84%9C%ED%8C%8C%EC%9D%BC%ED%98%95%EC%8B%9D_5.0_revision1.3.pdf): FileHeader, DocInfo, BodyText, 제어 문자 표 6과 문단 레코드.
- [olefile 사용법](https://olefile.readthedocs.io/en/latest/Howto.html): 메모리 파일 객체와 OLE 결함 처리.
- [ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/): OOXML과 OPC 내부 관계.
- [ODF 1.3](https://docs.oasis-open.org/office/OpenDocument/v1.3/os/): XML 문서/패키지 형식.
- [striprtf](https://github.com/joshy/striprtf): RTF 제어어·코드페이지/Unicode 추출.
- [defusedxml](https://github.com/tiran/defusedxml): DTD·entity·외부 XML 참조 차단.
- MS-XLS FilePass 레코드, MS-PPT CurrentUserAtom `headerToken`: 구형 XLS/PPT의 암호화 표지.
- LibreOffice `hwpfilter`의 `HWPInfo::Read`: HWP 3 서명 뒤 문서 정보 블록의 암호(오프셋 126)·압축(오프셋 154) 표지.

필수 파서 의존성은 `pypdf>=6.19.0,<7`, `olefile>=0.47,<0.48`,
`defusedxml>=0.7.1,<0.8`, `striprtf>=0.0.33,<0.1`이다. 플랫폼 배포 의존성과 잠금 파일에
포함했다. `cremore/scanning/document_scan_test.py`는 디스크 문서나 실계정 없이 합성
PDF·OOXML·OLE DOC/HWP·XLS/PPT·HWP 3·RTF·실행 파일·CP949/latin-1 텍스트·압축 바이트와
미디어 서명으로 탐지, 원문 비보관, 예산, 취소, 노출 보존과 형식 판별을 검사한다. cp1252 바이트 뒤의
토큰은 실제 탐지 엔진으로 찾는지 확인하고, 바이너리 안의 컨테이너·암호화 표지(gzip 머리 모양 포함),
매크로·첨부가 있는 OLE와 MSI·Visio·MSG·삽입 개체가 있는 PPT, PDF 앞의 텍스트와 줄바꿈 뒤의 텍스트 PDF,
확장 음절이 있는 CP949, Ctrl-Z가 붙은 구형 텍스트, HWP 3 암호·압축 표지, 제어 문자가 섞인 텍스트,
고정 어휘 밖의 파서 출력도 검사한다.
`cremore/scanning/extraction_server_test.py`는 POSIX에서 파서 서버와 문서별 프로세스 경로의 결과
동일성, 시간 초과·외부 SIGKILL·SIGSEGV·프로토콜 오류·무응답 서버·유휴 중 종료·500개 교체, 서버가
죽어도 파싱 자식이 남지 않음, 이전 문서의 입력·추출 텍스트가 서버와 다음 자식 메모리에 없음, 큰 응답 뒤
서버 주소 공간이 커지지 않음, 여러 스레드의 동시 호출, 환경변수·핸들 비상속, fork된 스캔 프로세스의 서버
분리, 진행 확인·취소를 검사한다(Windows에서는 건너뛴다). 실행 중인 자식을 관찰하는 검사는 수 초 걸리는
합성 PDF와 2초 시간 제한을 써서 기계 속도와 관계없이 자식이 제한 시각까지 살아 있게 한다.
`scripts/bench_extraction.py --min-speedup 5`는 작은 합성 DOCX·ZIP·gzip 60개로 두 경로의 문서당
시간과 결과를 비교한다(서버 시작 시간은 따로 표시하고 문서당 시간에서 뺀다). 2026-10-09 측정 조건은
Windows 11 개발 PC의 Docker Desktop Linux 컨테이너(Python 3.14, 저장소를 읽기 전용 bind mount)이고
다른 작업이 동시에 돌던 상태였다. 여섯 번 실행한 범위는 서버 5.2–8.6 ms/문서, 문서마다 프로세스
335.8–426.2 ms/문서(39.0–82.3배), 서버 시작 0.43–1.05초였다. 같은 환경에서 서버 첫 시작이 부하에 따라
최대 약 6초까지 걸린 적이 있다. 실제 배포 이미지·호스트에서의 값은 따로 재야 한다.
기존 캐시·reconcile·worker 회귀 검사와 설치본/POSIX 검사는 통합 시 함께 확인한다.
합성 다운로드/파싱 호출 수 측정은 실공급자의 속도 개선 실측을 대신하지 않는다.
