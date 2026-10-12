# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
- `python -m pytest tests/ -q`:
- `pre-commit run --all-files`:
- Ledger verify: `True` trên `reports/ledger.jsonl` sau lượt CLI `dpo` ở CP3e; thử sửa một ký tự ở dòng giữa trả `False`, khôi phục nguyên file trả `True`.
- Các lỗi còn lại:

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
