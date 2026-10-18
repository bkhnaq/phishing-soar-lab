# Email mẫu để test pipeline

Bộ email mẫu để kiểm tra các nhánh phân loại trong môi trường lab. Nội dung có thể chứa URL,
domain hoặc IP thật; không mở link, không chạy tệp đính kèm và không dùng để gửi thử qua pipeline
production. Email malware có tệp HTML đính kèm chứa mã chuyển hướng.

| File | Loại | Verdict mong đợi | Category |
|------|------|------------------|----------|
| 1_credential_phishing.eml | Đánh cắp mật khẩu | MALICIOUS | credential_phishing |
| 2_malware_attachment.eml  | Mã độc đính kèm   | SUSPICIOUS / MALICIOUS | malware |
| 3_bec_wire_transfer.eml   | Lừa đảo tài chính | SUSPICIOUS | bec |
| 4_legitimate_github.eml   | Email hợp lệ      | CLEAN / INCONCLUSIVE | spam_or_legit |
| 5_spam_marketing.eml      | Quảng cáo         | CLEAN | spam_or_legit |
