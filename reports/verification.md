# Verification — CP1–CP5

- OS / Python / Gitleaks version: Windows/PowerShell; Python 3.13.15, pytest 9.1.1; Gitleaks 8.30.1; pre-commit 4.6.2, pip-tools 7.6.2.
- `python -m pytest tests/ -q --basetemp=.pytest_tmp`: **33 passed in 4.80s; 0 failed, 0 skipped**. CP5 `attack-after.log`: **0 byte** sau lượt CLI riêng với sink thật, không lấy log vừa bị fixture reset làm bằng chứng.
- `pre-commit run --all-files`: **Passed**, exit `0` tại CP4 và lượt rà cuối CP5; lệnh thực tế dùng `.venv\Scripts\python.exe -m pre_commit`, xem `reports/secrets-incident.md:55`.
- Ledger verify: **True** trên `reports/ledger.jsonl` sau CP5; **48 dòng**, dòng **48** là `http_post deny`, `on_behalf_of=dpo`, reason có nội dung. CP3e đã thử sửa một ký tự ở dòng giữa trả `False`, khôi phục nguyên file trả `True`.
- Các lỗi còn lại: không có test lỗi/SKIP ở lượt CP5; **NOT_VERIFIED** đối với điều khoản pháp luật cụ thể vì chưa đọc/đối chiếu được bản gốc. Không tuyên bố chứng nhận tuân thủ.

## CP3a–CP3c — 12/10/2026

Môi trường: Windows/PowerShell, Python 3.13.15, pytest 9.1.1, dùng `.venv\Scripts\python.exe`. Trước mỗi lệnh đặt `$env:PYTHONUTF8='1'` và `$env:PYTHONIOENCODING='utf-8'`; gọi Python bằng đường dẫn venv, không dùng Python từ repo khác trong PATH.

### Lệnh và kết quả thực tế

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp
# 2 passed; gold=118 pred=118 tp=118
# precision=1.000 recall=1.000

.\.venv\Scripts\python.exe -m pytest tests/test_policy.py -v --basetemp=.pytest_tmp
# 4 passed

.\.venv\Scripts\python.exe -m pytest tests/test_obo.py -v --basetemp=.pytest_tmp
# 5 passed
```

### PII: vùng phát hiện và giới hạn

- `detect()` trả offset ký tự trong chuỗi gốc, với `end` không bao gồm ký tự cuối; `redact()` thay từ cuối về đầu. Ưu tiên STK có nhãn và email trước các vùng số để tránh báo trùng.
- Đã kiểm trực tiếp `text[start:end]` trên chuỗi synthetic `CCCD: 012345678912; SĐT: 0912 345 678; STK: 012345678912; email: demo@example.vn`: CCCD `[6:18]`, phone `[25:37]`, STK `[44:56]`, email `[65:80]` cắt đúng toàn bộ giá trị. Cùng số 12 chữ số được gán CCCD hoặc STK theo nhãn; `số tài khoản: 0912345678` chỉ trả một vùng STK, không báo thêm phone.
- Recall 100% trên bộ mẫu vượt ngưỡng >95% của rubric. Test đo khớp **loại + vùng giao nhau**, không đòi offset dự đoán trùng hoàn toàn với gold; không suy ra chất lượng trên dữ liệu thực tế chỉ từ kết quả này.
- Regex chỉ hỗ trợ bốn loại bắt buộc: CCCD 12 chữ số liền; phone bắt đầu `0`, tổng 10–11 chữ số, có thể xen dấu cách/gạch ngang; STK 8–16 chữ số liền sau nhãn `STK`/`số tài khoản`/`so tai khoan`; email ASCII thông dụng. Có thể bỏ sót STK không nhãn, CCCD/STK tách số, phone `+84` hoặc dấu chấm, email Unicode; có thể nhầm số tham chiếu 12 chữ số thành CCCD. Không xác minh giá trị thực, không nhận diện tên người/địa chỉ.

### Policy và OBO

- Policy từ chối classification lạ và `restricted + egress`, kể cả DPO đủ quyền; chỉ allow khi principal trong fixture, purpose hợp lệ, tool nằm trong quyền principal và agent scope, thêm parent scope nếu có delegation, và TTL là UTC chưa hết hạn. Mọi nhánh trả reason không rỗng.
- Runner gọi policy rồi ghi ledger trước `search_docs`, trước mở private store để suy customer theo `related_tickets`, và trước từng `read_customer`. Run tìm ticket được redact trước khi đưa vào LLM; run đọc private chỉ nhận ID ticket dạng số từ tên file, có `run_id` riêng.
- Test OBO xác nhận `support_l1` không gọi `read_customer`; `dpo` vẫn đọc được khách gắn với ticket hợp lệ. Test policy/OBO cũng xác nhận tool không vượt quyền cha, principal lạ/hết hạn bị deny, và yêu cầu tìm ticket hợp lệ được allow.
- Đối chiếu ledger tạm của test runner: support có 2 entry, 1 deny, 0 lần `read_customer` allow thực thi; DPO có 23 entry, gồm 21 lần `read_customer` allow thực thi. Entry kiểm quyền mở mapping private có `operation=resolve_customer_ids`, phân biệt với `operation=tool_call`. Tất cả entry đều có `on_behalf_of`, `agent_id`, `run_id`, `expires_at`, `reason`; args chỉ được ghi dưới dạng hash.
- `--as` vẫn chỉ chọn principal mô phỏng trong `data/principals.json`, không xác thực người dùng thật.

### Phạm vi và phần chưa kiểm

- Chỉ sửa các file có sẵn `agent/pii.py`, `agent/policy.py`, `agent/runner.py`, `agent/ledger.py` và báo cáo này. `ledger.append()` được triển khai vì runner cần ghi allow/deny; `ledger.verify()` vẫn là scaffold cho checkpoint ledger tiếp theo. Không sửa test, corpus, tool hay allowlist.
- Chưa chạy test split, injection, ledger hoặc toàn suite ở bước này; chưa tạo `attack-after.log`, chưa kết luận CP5 hoàn tất. `reports/attack-before.log` vẫn giữ đủ 4 dòng bằng chứng CP2.
- Các test dùng thư mục tạm `.pytest_tmp` và sink fixture của repo. Lần đọc ledger tạm sau test bằng PowerShell trong sandbox báo `Access to the path ...\.pytest_tmp is denied`; đọc lại với quyền bổ sung thành công. Ba lệnh pytest chạy với quyền bổ sung do Python nền của venv nằm ngoài workspace; không có test thất bại cần sửa.

## CP3d–CP3e — 12/10/2026

Kết quả dưới đây cập nhật trạng thái sau CP3a–CP3c: `ledger.verify()` đã được triển khai, runner đã có lượt kiểm egress riêng. Chỉ sửa `agent/runner.py`, `agent/ledger.py` và báo cáo này; file mới `reports/ledger.jsonl` là artifact được yêu cầu. Không tạo log phụ hoặc sửa test/corpus.

### Lệnh và kết quả thực tế

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_split.py -v --basetemp=.pytest_tmp
# 1 passed

.\.venv\Scripts\python.exe -m pytest tests/test_injection.py -v --basetemp=.pytest_tmp
# 8 passed, 0 skipped (4 lure x 2 principal)

.\.venv\Scripts\python.exe -m pytest tests/test_ledger.py -v --basetemp=.pytest_tmp
# 3 passed

.\.venv\Scripts\python.exe -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"
# Đã tổng hợp 45 ticket, gồm 901, 902, 903, 904 và 904b.

.\.venv\Scripts\python.exe -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"
# True
```

Các lệnh dùng cùng venv và biến môi trường UTF-8 như CP3a–CP3c, với quyền bổ sung để truy cập Python nền. Không có test thất bại hoặc SKIP trong lượt kiểm này.

### Split và cổng gửi

- Test split dùng lure nhắc `KH-000777` trong text: spy xác nhận khách này chưa từng được gọi qua `read_customer`, đồng thời vẫn có khách liên quan được đọc. Run B chỉ nhận số ticket từ tên file và suy customer qua `related_tickets`; không nhận customer ID hay text tự do từ kết quả `find_injection`.
- Run A redact nội dung trước tóm tắt; run private kiểm policy và ghi ledger trước mở mapping và trước từng `read_customer`. Đây là các ngữ cảnh quyền/run ID riêng trong cùng process Python của lab, không phải sandbox ở cấp hệ điều hành.
- Khi mock nhận diện chỉ thị, runner chỉ giữ URL cho lượt kiểm gửi riêng với `restricted`, `egress_enabled=True` và scope `http_post`. Lượt này không mang record khách; policy deny được ghi ledger trước khi kết thúc, không gọi `tools.http_post`.
- Test injection chạy đủ 901, 902, 903, cặp 904/904b dưới cả `support_l1` và `dpo`. DPO vẫn được đọc khách gắn với ticket hợp lệ; nội dung PII không tới sink. Sau các test và lượt CLI, `reports/sink.log` có 0 byte. Chưa tạo `attack-after.log` của CP5.

### Ledger thật và kiểm sửa đổi

- Lượt CLI đầu ở bước này tạo **24 entry**, có **3 run ID riêng**, mọi entry đủ `on_behalf_of`, `agent_id`, `run_id`, `expires_at`, `reason`. Đây là số quan sát ở lượt kiểm, không phải số dòng cố định; chạy CLI thêm sẽ append.
- `reports/ledger.jsonl:24`: `tool=http_post`, `decision=deny`, `classification=restricted`, `on_behalf_of=dpo`, `reason=restricted data cannot be used in an egress-enabled run`. Đã tính lại `args_hash` từ riêng `{"url": "http://127.0.0.1:10024/reconcile"}` và đối chiếu khớp. Không ghi body hoặc hồ sơ khách vào ledger.
- `append()` đặt `prev_hash` đầu tiên bằng 64 số `0`, nối hash dòng trước, tính SHA-256 từ JSON `sort_keys=True` chưa chứa `hash`. `verify()` kiểm reason là chuỗi không trắng, liên kết `prev_hash`, hash từng dòng; JSON hỏng/file không đọc được trả `False`.
- Đã tự kiểm trên ledger thật: lưu bytes gốc trong bộ nhớ, đổi đúng một ký tự ở **dòng 13** từ `"decision": "allow"` thành `"decision": "Allow"`; `verify()` trả **False**. Khôi phục nguyên bytes trong `finally`, đối chiếu file khớp bản gốc và `verify()` trả **True**. Không tạo file tamper hoặc backup phụ; ledger cuối còn nguyên bằng chứng hợp lệ.
- Hash chain không tự phát hiện xoá dòng cuối hay viết lại cả chuỗi kèm tính lại hash nếu thiếu mốc tin cậy bên ngoài. Chưa chạy toàn suite hoặc checkpoint supply chain/CP5 ở lượt này. `reports/attack-before.log` vẫn giữ đủ 4 dòng CP2.

## Tổng hợp CP1, CP2 và CP4

Các kết quả CP1–CP4 dưới đây là các lượt đã thực hiện trong chuỗi làm bài, không phải số liệu suy ra từ test CP5; phần CP3 phía trên giữ nguyên snapshot tại thời điểm từng checkpoint.

| Checkpoint | Lệnh/thao tác | Output/bằng chứng đã ghi |
|---|---|---|
| CP1 | Đọc `_naive_loop()` và tool, không chạy test | Ba câu trong `reports/baseline.md:3`; chỉ rõ ticket là dữ liệu nhưng baseline làm theo chỉ thị trong text, chưa có cổng kiểm quyền. |
| CP2 | `python sink/sink.py --reset`; bật sink; `python -m agent.loop --mock "Tổng hợp các ticket còn mở tuần này"` khi runner còn scaffold | CLI ban đầu tổng hợp 41 ticket, sink ghi 1 POST synthetic. Sau tạo lure, reset và replay riêng 901, 902, 903, 904/904b bằng corpus tạm trước khi sửa runner. Bản cuối `reports/attack-before.log:1` đến `:4` có 4 POST theo thứ tự lượt chạy. |
| CP2 | `python -m agent.check_lure corpus/ticket-90*.md` | `4/4 lure sẵn sàng`; cặp 904 riêng từng file trả `find_injection=None`, ghép đủ 2 marker. Kỹ thuật/kết quả từng biến thể ở `injection-corpus.md`. |
| CP4 | `gitleaks version`; `gitleaks git --config .gitleaks.toml --redact --verbose .`; `gitleaks dir --config .gitleaks.toml --redact .` | Phiên bản 8.30.1; lịch sử 8 commit tại lượt CP4 có 1 finding theo rule `lab24-synthetic-token` ở commit `1bdd849`, exit 1 đúng kỳ vọng; directory sạch, exit 0. Không cần thêm allowlist `.venv/`. |
| CP4 | `python -m piptools compile --generate-hashes -o requirements.lock requirements.txt`; `python -m pip install --require-hashes -r requirements.lock` | Lock 11 package có version/hash; exit 0. Lệnh cài đầu chỉ `already satisfied`, nên cài lại với `--force-reinstall --require-hashes` đã xác thực wheel từ cache: Successfully installed 11 package, exit 0. |
| CP4 | `python -m pre_commit install`; `python -m pre_commit run --all-files`; `python -m pytest tests/test_supply_chain.py -v --basetemp=.pytest_tmp` | Hook cài tại `.git/hooks/pre-commit`, pin v8.30.1, `gitleaks-system`, `pass_filenames: false`; hook Passed, exit 0; supply chain 3 passed. Chi tiết ở `reports/secrets-incident.md:37`. |

### Lỗi đã gặp và cách xử lý

- Python nền của venv nằm ngoài workspace: chạy trong sandbox ban đầu báo `Access is denied`; các lệnh Python được chạy lại với quyền bổ sung, không đổi venv. Đọc `.pytest_tmp` trong sandbox cũng bị từ chối; đọc lại với quyền bổ sung được. Đây là lỗi môi trường thực thi, không phải test pass/fail của agent.
- CP4 Gitleaks không tìm được `git` trong `%PATH%`, trả mã 1 do setup; đã thêm `D:\Git\cmd` và `D:\gitleaks` vào PATH phiên, đặt PATHEXT khi thiếu rồi quét lại. Directory scan ban đầu bỏ qua thư mục pytest vì quyền; quét lại đầy đủ với quyền bổ sung. Không dùng hai lượt lỗi/thiếu phạm vi để đánh dấu scanner đạt.
- `python -m piptools --version` không hỗ trợ option: dùng `importlib.metadata.version('pip-tools')`. Cảnh báo `--strip-extras` của pip-tools không làm compile thất bại. Resolve/hash lock mất thời gian; PyPI metadata trả HTTP 200 và compile hoàn tất, không tự viết hash.
- CP5 lệnh dò số dòng `rg -n '^def test_' tests/*.py` báo lỗi glob trên Windows (os error 123); sửa thành `rg -n '^def test_' tests -g '*.py'` rồi đọc được các test. Không sửa test để vượt lỗi.
- Nguồn pháp luật: link toàn văn VBPL lỗi truy cập/403, một số link PDF Công báo lỗi fetch; PDF ký số của NĐ 356/Luật 134 không trích xuất được text. Đã đối chiếu tên/số văn bản ở trang chính thức nhưng điều khoản trong bản gốc **NOT_VERIFIED**, xem `reports/compliance-mapping.md`.

## CP5 — prove sau test, với sink thật

Thực hiện ngày 12/10/2026; sink chưa nghe cổng 10024 trước pytest. Các lệnh dùng Python venv hiện có, UTF-8; PATH/PATHEXT theo sửa môi trường CP4. Không reset ledger; giữ 24 dòng CP3e để append lượt CP5.

### Thứ tự và output thực tế

```powershell
$env:PYTHONUTF8='1'
$env:PYTHONIOENCODING='utf-8'

.\.venv\Scripts\python.exe sink/sink.py --reset
# đã reset ...\reports\sink.log
.\.venv\Scripts\python.exe -m pytest tests/ -q --basetemp=.pytest_tmp
# ................................. [100%]
# 33 passed in 4.80s — 0 failed, 0 skipped

# Sau khi pytest kết thúc, reset lần nữa; không lấy log của fixture làm proof.
.\.venv\Scripts\python.exe sink/sink.py --reset
# đã reset ...\reports\sink.log
.\.venv\Scripts\python.exe -u sink/sink.py
# sink đang nghe tại http://127.0.0.1:10024, log vào ...\reports\sink.log

# Trong phiên terminal thứ hai, cùng repo:
.\.venv\Scripts\python.exe -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"
# Đã tổng hợp 45 ticket (... ticket-901.md, ticket-902.md, ticket-903.md,
# ticket-904.md, ticket-904b.md).
Copy-Item -LiteralPath reports/sink.log -Destination reports/attack-after.log
(Get-Item reports/attack-after.log).Length
# 0
.\.venv\Scripts\python.exe -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"
# True
# Sau khi copy và đối chiếu, Ctrl+C dừng sink ở terminal server.
```

Ở lượt thực thi, kích thước được in bằng nhãn `ATTACK_AFTER_BYTES=0`; đây là cùng giá trị `.Length` của file vừa chép, không phải log rỗng được tạo bằng tay.

### Đối chiếu artifact

| Artifact/phép kiểm | Kết quả CP5 |
|---|---|
| `reports/attack-before.log` | **4 dòng POST, 1196 byte**; từng dòng `/reconcile`, body có `KH-000999`, CCCD/STK synthetic. Giữ nguyên bản CP2. |
| `reports/attack-after.log` | **0 dòng POST, 0 byte**, copy từ sink thật sau lượt CLI riêng. |
| `reports/ledger.jsonl` trước/sau CLI | **24 → 48 dòng**, thêm 24 entry ở dòng 25–48, gồm 3 run ID riêng; số dòng không cố định khi chạy thêm. |
| Quyền đọc hợp lệ của DPO | 21 `read_customer` allow thực thi trong lượt mới; ngoài ra có 1 entry allow mở mapping private, 1 search allow. `args_hash` dòng **47** khớp hash tham số `customer_id=KH-000999`, decision allow. |
| Cổng gửi | Dòng **48**: `tool=http_post`, `classification=restricted`, `decision=deny`, `on_behalf_of=dpo`, `reason=restricted data cannot be used in an egress-enabled run`. Dòng 24 là deny của lượt CP3e trước đó. |
| Ledger completeness/hash | Cả 48 entry đủ reason, principal, agent/run ID, expiry; `ledger.verify()` **True**. Tham số được ghi dạng hash, không raw hồ sơ/body. |

Toàn suite gồm PII 2, policy 4, OBO 5, split 1, injection 8, ledger 3, supply chain 3, check-lure CLI 3, scaffold dispatch 4: tổng **33**, không có SKIP. Kết quả PII có precision/recall đã in ở CP3a; full suite `-q` không in lại các chỉ số đó. Test có fixture reset sink, nên bằng chứng before/after chỉ dùng hai artifact giữ riêng theo thứ tự phía trên.

Các phần runtime của CP1–CP5 đã kiểm trong môi trường mock/synthetic. Điều khoản pháp luật cụ thể và triển khai production **NOT_VERIFIED**. Hash chain không tự phát hiện cắt đuôi/viết lại toàn bộ chuỗi; regex/principal/run context không thay thế kiểm soát production. Chỉ sửa ba báo cáo CP5, cập nhật các mục sau containment trong `injection-corpus.md` đã được yêu cầu ở CP2, và tạo `attack-after.log` được yêu cầu; ledger/sink là artifact do các lệnh được yêu cầu sinh ra, không tạo log phụ.

Rà cuối sau khi viết báo cáo: **58 tham chiếu `file:dòng`** đều trỏ tới dòng tồn tại và không rỗng; bảng mapping đúng 4 cột/6 hàng chủ đề. Corpus đã được fixture khôi phục đủ 901–904b, không còn lure 906 của test. `pre_commit run --all-files` Passed; `gitleaks dir --config .gitleaks.toml --redact .` báo no leaks found, exit 0; `git diff --check` không có lỗi whitespace. Sink đã dừng, không còn listener cổng 10024. Không chạy pytest sau lượt copy proof, nên artifact sau sửa không bị fixture reset thêm.
