# Checklist ảnh & video cho demo

## Ảnh cần chụp (lưu vào docs/images/)

| Tên file | Nội dung |
|----------|----------|
| architecture.png | Sơ đồ kiến trúc (xuất từ diagram trong chat) |
| dashboard.png | Dashboard "Phishing SOC Overview" có số liệu |
| alerts-list.png | Danh sách 5 email test với verdict/category khác nhau |
| alert-detail.png | Một alert: tab Observables có nhãn analyzer + mục "Kết luận tự động" |
| case-tasks.png | Case #5: tab Tasks với task từ template |
| shuffle-workflow.png | Workflow 4 node (đã đổi tên) |
| shuffle-execution.png | Một execution thành công, output từng node |
| cortex-jobs.png | Cortex Jobs History: analyzer chạy thành công |
| telegram-bot.png | Bot nhận email và trả kết quả |
| wazuh-alert.png | Alert rule 100511/100512, có MITRE T1566 |

## Video demo (2-4 phút, dùng OBS hoặc ScreenToGif)

1. Gửi email phishing (file 1) cho bot qua Telegram → bot trả lời
2. Shuffle → execution vừa chạy
3. TheHive → alert mới: observable đã enrich + "Kết luận tự động"
4. Case tạo tự động với các task
5. Kết bằng dashboard

## BẮT BUỘC làm trước khi commit / chụp

- [ ] Thu hồi + đổi API key TheHive (key cũ đã lộ)
- [ ] Che/xoá mọi API key: VirusTotal, AbuseIPDB, urlscan, Telegram token
- [ ] Che host `khang-thehive-soc...azure.com` và IP private trong ảnh
- [ ] Che webhook URL của Shuffle
- [ ] Kiểm tra không có secret trong code trước khi push: `git grep -nE "api[_-]?key|token|password" .`
- [ ] Xin license Community cho TheHive (trial sắp hết)
