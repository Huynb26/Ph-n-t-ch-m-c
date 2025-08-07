# Báo cáo phân tích chiến dịch tấn công APT

### I. Giới thiệu

Trong thời gian gần đây, các cuộc tấn công mạng nhắm vào những người tìm việc trong lĩnh vực công nghệ ngày càng gia tăng. Một trong những chiến dịch đáng chú ý là XELERA Ransomware, được phát hiện gần đây với cách thức lừa đảo bằng các thông báo tuyển dụng giả mạo từ Food Corporation of India (FCI). Mục tiêu chính của chiến dịch này là các ứng viên công nghệ, đặc biệt là những người đang tìm kiếm cơ hội việc làm trong ngành CNTT.

Mã độc XELERA được viết bằng Python và sử dụng PyInstaller để đóng gói thành tệp thực thi Windows. Đáng chú ý, nó không chỉ hoạt động như một ransomware để mã hóa dữ liệu mà còn có khả năng đánh cắp thông tin đăng nhập, kiểm soát từ xa thông qua bot Discord, và thực hiện nhiều hành vi độc hại khác.

Kẻ tấn công sử dụng chiến thuật lừa đảo qua email (phishing emails), trong đó đính kèm một tài liệu Word được nhúng mã độc. Khi nạn nhân mở tài liệu, một tệp thực thi được trích xuất và kích hoạt quá trình lây nhiễm. Điều này cho phép hacker xâm nhập vào hệ thống, đánh cắp thông tin cá nhân, và triển khai mã hóa dữ liệu để yêu cầu tiền chuộc.

Bài viết sẽ phân tích chi tiết cách thức hoạt động của XELERA Ransomware, từ chuỗi lây nhiễm ban đầu đến các tính năng kỹ thuật như điều khiển từ xa qua Discord, quá trình mã hóa dữ liệu, và các biện pháp phòng tránh để bảo vệ người dùng khỏi mối đe dọa này.
### II. Phát hiện

Vào ngày 18 tháng 1 năm 2025, nhóm nghiên cứu bảo mật tại Seqrite Labs đã phát hiện một tài liệu đáng ngờ được tải lên VirusTotal với tên gọi "FCEI-job-notification.doc". Tài liệu này giả mạo là một thông báo tuyển dụng chính thức từ Food Corporation of India (FCI), một tổ chức quan trọng trong ngành thực phẩm của Ấn Độ.

 Tài liệu Word này chứa một đối tượng OLE nhúng – một kỹ thuật thường được sử dụng để che giấu mã độc. Khi giải nén, họ phát hiện tệp jobnotification2025.exe, một tệp thực thi Windows được đóng gói bằng PyInstaller. Điều này cho thấy tài liệu không chỉ đơn thuần là một văn bản thông thường mà thực chất là một mồi nhử để phát tán mã độc.

Khi người dùng mở tài liệu Word, tệp thực thi độc hại (jobnotification2025.exe) được giải nén vào hệ thống. Nếu nạn nhân kích hoạt tệp này, một tập hợp các script Python độc hại sẽ chạy, kích hoạt quá trình đánh cắp thông tin và mã hóa dữ liệu. Mã độc này có khả năng liên lạc với máy chủ điều khiển (C2) thông qua Discord, cho phép kẻ tấn công từ xa ra lệnh và thu thập dữ liệu bị đánh cắp.

Mã nguồn của XELERA tương tự với một số biến thể ransomware trước đây, cho thấy XELERA có thể được phát triển dựa trên các công cụ mã nguồn mở hoặc là một biến thể mới được tùy chỉnh. Việc sử dụng Discord làm nền tảng giao tiếp C2 vẫn là một phương pháp đơn giản và hiệu quả giúp kẻ tấn công dễ dàng ẩn danh và tránh bị phát hiện.

Chiến dịch tấn công XELERA Ransomware nhắm vào ứng viên công nghệ thông tin thông qua tuyển dụng giả mạo, một phương thức đang trở nên phổ biến trong các cuộc tấn công lừa đảo trực tuyến. Phát hiện này là lời cảnh báo mạnh mẽ về sự nguy hiểm của các tài liệu giả mạo, đồng thời nhấn mạnh sự cần thiết phải thận trọng với email tuyển dụng không rõ nguồn gốc và tệp đính kèm đáng ngờ.
### III. Lây nhiễm
### IV. Phân tích
#### 1. Phân tích sơ bộ file thực thi



#### 2. Phân tích chức năng `Discord bot`

#### 3. Phân tích chức năng: Mã hóa & tống tiền

### V. IOCs & Rules

#### 1. IOCs

#### 2. YARA rule

#### 3. Sigma rule


### VI. Kết luận