# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
- `python -m pytest tests/ -q`:
- `pre-commit run --all-files`:
- Ledger verify:
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
