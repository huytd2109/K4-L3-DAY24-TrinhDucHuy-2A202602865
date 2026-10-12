# CP4 — token giả trong lịch sử Git

Thực nghiệm ngày 12/10/2026 trên Windows/PowerShell. Token trong bài là synthetic, vô hiệu; không dùng để gọi dịch vụ và không chép giá trị token vào báo cáo.

## Scanner và finding

- Scanner: **Gitleaks 8.30.1**, binary có sẵn ở `D:\gitleaks\gitleaks.exe`; `gitleaks version` trả `8.30.1`.
- Commit: **`1bdd849922156c868a5ee9293d68f5b72e242d2c`** (viết ngắn `1bdd849`).
- File/dòng: **`lab-fake-secret.txt:1`** trong commit cũ; file không còn ở checkout hiện tại.
- Rule: **`lab24-synthetic-token`**; Gitleaks hiển thị Finding/Secret là `REDACTED`.
- Fingerprint: `1bdd849922156c868a5ee9293d68f5b72e242d2c:lab-fake-secret.txt:lab24-synthetic-token:1`.

## Quét lịch sử so với file hiện tại

```powershell
gitleaks version
# 8.30.1
gitleaks git --config .gitleaks.toml --redact --verbose .
# 8 commits scanned; leaks found: 1; exit 1
gitleaks dir --config .gitleaks.toml --redact .
# no leaks found; exit 0
```

Mã `1` của lượt quét lịch sử thành công ở trên là kết quả mong đợi vì tìm thấy token giả. Quét directory kiểm các file hiện tại, không chứng minh lịch sử sạch. Lượt quét đầy đủ không có finding ở `.venv/`, nên **không thêm allowlist** và không đổi `.gitleaks.toml` hay tắt rule.

Lần chạy đầu trong sandbox không phải bằng chứng phát hiện: Gitleaks báo `could not create Git log cmd ... git ... executable file not found in %PATH%`; mã `1` khi đó là lỗi setup. Quét directory ban đầu báo bỏ qua `.pytest_cache`/`.pytest_tmp` vì permission denied, nên đã chạy lại với quyền bổ sung. Việc chạy lịch sử với quyền bổ sung vẫn cần chỉnh PATH cho tiến trình con:

```powershell
$env:PATH = 'D:\Git\cmd;D:\gitleaks;' + $env:PATH
if (-not $env:PATHEXT) { $env:PATHEXT = '.COM;.EXE;.BAT;.CMD' }
```

Sau chỉnh PATH, Git 2.55.0.windows.3 chạy được; quét lịch sử và directory cho kết quả hợp lệ như trên, không còn cảnh báo bỏ qua thư mục. Chỉ chỉnh môi trường phiên chạy, không đổi PATH hệ thống.

## Hook và dependency lock

- `.pre-commit-config.yaml` dùng repo `https://github.com/gitleaks/gitleaks`, pin `rev: v8.30.1`, hook `gitleaks-system`, `pass_filenames: false`, thêm `--config .gitleaks.toml`. Hook system dùng binary đã cài; định nghĩa chính thức gọi `gitleaks git --pre-commit --redact --staged --verbose` ([source v8.30.1](https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/.pre-commit-hooks.yaml)). Không dùng hook quét staged để thay cho quét toàn lịch sử hoặc directory.
- `python -m pre_commit install`: thành công, cài `.git/hooks/pre-commit`; `python -m pre_commit run --all-files`: `Detect hardcoded secrets ... Passed`, exit `0`.
- Venv hiện có `pre-commit 4.6.2`, `pip-tools 7.6.2`. Đọc phiên bản pip-tools bằng `importlib.metadata.version('pip-tools')`; CLI `python -m piptools --version` không hỗ trợ tùy chọn đó.
- `requirements.lock` được sinh bằng `piptools compile --generate-hashes`, gồm **11 package**, mọi package pin `==` và có SHA-256 hash; hai dependency trực tiếp là `requests==2.34.2` và `pytest==9.1.1`. Lock được resolve bằng Python 3.13 trên Windows; không khẳng định đã kiểm trên OS/Python khác.
- Lệnh cài đầu `pip install --require-hashes -r requirements.lock` trả exit `0`, nhưng chỉ báo `Requirement already satisfied`. Đã chạy thêm `--force-reinstall --require-hashes` để cài lại các wheel từ cache đúng hash/phiên bản: **Successfully installed 11 package**, exit `0`; không chỉ dựa vào package đã có sẵn. Không đổi `requirements.txt` hoặc thêm dependency ứng dụng.
- `python -m pytest tests/test_supply_chain.py -v --basetemp=.pytest_tmp`: **3 passed**, exit `0` (hook pin, lock có hash, incident note đúng token giả).

Các lệnh dùng `.venv\Scripts\python.exe`, `PYTHONUTF8=1`, `PYTHONIOENCODING=utf-8`, và quyền bổ sung để truy cập Python nền/cache ngoài workspace. Không tạo file log phụ; chỉ có hai file mới được yêu cầu là `requirements.lock`, `.pre-commit-config.yaml`, cùng hook do `pre-commit install` sinh trong `.git/`.

```powershell
.\.venv\Scripts\python.exe -m piptools compile --generate-hashes -o requirements.lock requirements.txt
# exit 0; cảnh báo --strip-extras sẽ đổi default ở pip-tools 8.0, không phải lỗi.
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements.lock
# exit 0; already satisfied
.\.venv\Scripts\python.exe -m pip install --force-reinstall --require-hashes -r requirements.lock
# exit 0; Successfully installed 11 package
.\.venv\Scripts\python.exe -m pre_commit install
# exit 0; pre-commit installed at .git\hooks\pre-commit
.\.venv\Scripts\python.exe -m pre_commit run --all-files
# exit 0; Passed
.\.venv\Scripts\python.exe -m pytest tests/test_supply_chain.py -v --basetemp=.pytest_tmp
# 3 passed; exit 0
```

Thời gian resolve/hash lock dài hơn các lệnh còn lại; lúc chưa có output đã kiểm kết nối metadata công khai `https://pypi.org/pypi/requests/json`, nhận HTTP `200`. Sau đó `pip-compile` hoàn tất bình thường, không cần sửa hay tự viết hash.

## Nếu đây là secret thật

1. Thu hồi token bị lộ hoặc **rotate tại dịch vụ cấp token**, thay credential mới ở các ứng dụng cần dùng và xác nhận token cũ không còn được chấp nhận. Không chỉ xoá file rồi tiếp tục dùng token cũ.
2. Kiểm log sử dụng và quyền của token trong khoảng thời gian bị lộ; tìm hoạt động trái phép, xác định dữ liệu/hệ thống bị tác động và xử lý theo quy trình incident của đơn vị.
3. Xử lý bản sao trong lịch sử Git, clone/fork, cache CI, artifact, log và backup theo phạm vi đã xác định; phối hợp với người giữ các bản sao, tránh làm gián đoạn checkout đang có bài làm. Việc sửa lịch sử không đảm bảo thu hồi được mọi bản sao.
4. Kiểm lại scanner và hook sau xử lý. Với bài này chỉ ghi nhận token giả; không gọi dịch vụ để thử token, không thực hiện rotate một credential thật.

Xoá file khỏi HEAD không xoá giá trị ở commit cũ và không làm credential thật tự vô hiệu. Pin version/hash giúp kiểm soát dependency được cài, hook giúp phát hiện chuỗi nghi là secret; cả hai không thay thế việc thu hồi/rotate, điều tra sử dụng sai và xử lý các bản sao.
