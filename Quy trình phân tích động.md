# Quy trình phân tích động mã độc
## I. Giới thiệu

Phân tích động là một phương pháp quan trọng trong an ninh mạng nhằm nghiên cứu hành vi thực tế của mã độc khi nó được thực thi. Không giống như phân tích tĩnh, phương pháp này cho phép quan sát trực tiếp cách mã độc hoạt động trong môi trường giả lập hoặc hệ thống cô lập. Điều này giúp các nhà nghiên cứu phát hiện ra các kỹ thuật lẩn tránh, cơ chế giao tiếp mạng với máy chủ điều khiển (C2), cũng như các thay đổi mà mã độc thực hiện trên hệ thống như chỉnh sửa tệp tin, thay đổi registry hoặc tạo ra các tiến trình mới.

Phân tích động đặc biệt hữu ích khi làm việc với các mẫu mã độc đã được đóng gói hoặc mã hóa, vì việc chạy chúng trong môi trường được giám sát có thể giúp trích xuất thông tin quan trọng về cách thức hoạt động của chúng. Vì vậy cần phải thiết lập môi trường phân tích an toàn, thực hiện phân tích và đánh giá kết quả một cách hiệu quả.

## II. Các bước phân tích

### 1. Chuẩn bị môi trường phân tích

- Khởi động máy phân tích, kiểm tra cấu hình mạng (host-only), trạng thái snapshot.
- Đảm bảo các công cụ giám sát được cài đặt đầy đủ:
  - **Wireshark**: Phân tích lưu lượng mạng.
  - **Process Monitor (Procmon)**: Giám sát thay đổi trong hệ thống.
  - **RegShot**: Theo dõi thay đổi trong `registry`.
  - **Autoruns**: Kiểm tra các tiến trình tự động chạy khi khởi động.
  - **TCPView**: Theo dõi các kết nối mạng của mã độc.
  - **Process Explorer**: Kiểm tra các tiến trình chạy ngầm.

### 2. Theo dõi các thay đổi hệ thống

- Chạy mã độc trong môi trường phân tích.
- Quan sát hoạt động của hệ thống.
- Sử dụng công cụ giám sát để theo dõi thay đổi của hệ thống:
  - **File hệ thống**: Dùng **Procmon** để kiểm tra tệp tin được tạo, sửa hoặc xóa:
    - Tệp được tạo: `Operation` > `is` > `CreateFile`
    - Tệp được sửa: `Operation` > `is` > `WriteFile`
    - Tệp bị xóa: `Operation` > `is` > `SetDispositionInformationFile`
  - Tìm các tệp thực thi mới xuất hiện:
    - `Operation > is > CreateFile`
    - `Path` > `ends with` > `.exe`
    - `Path` > `ends with` > `.dll`
    - `Path` > `ends with` > `.bat`
    - `Path` > `ends with` >`.ps1`
    <img width="975" height="493" alt="image" src="https://github.com/user-attachments/assets/e4a1c39b-cb3a-4af5-9ec2-7d04f0315452" />

  - **Registry**: Kiểm tra các registry bị thay đổi:
    - Kiểm tra khóa registry mới được tạo: `Operation > is > RegCreateKey`
    - Kiểm tra giá trị được thiết lập cho một khóa registry: `Operation > is > RegSetValue`
  - Cần lưu ý các vị trí quan trọng như:
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` *(tự động khởi động)*
    - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` *(thực thi một lần sau khi đăng nhập)*
    - `HKLM\SYSTEM\CurrentControlSet\Services` *(cấu hình dịch vụ hệ thống)*
    - `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection` *(vô hiệu hóa Real-Time Protection)*
    - `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` *(vô hiệu hóa Windows Defender)*
    - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` *(vô hiệu hóa UAC)*
	<img width="975" height="493" alt="image" src="https://github.com/user-attachments/assets/00621d50-d65b-4871-952b-a2a78cc6a149" />

	  - Ngoài ra có thể dùng **RegShot** để so sánh các registry trước và sau khi chạy mã độc:
    - **1st shot**: ghi lại trạng thái `registry` trước khi chạy mã độc.
    - **2nd shot**: ghi lại trạng thái `registry` sau khi chạy mã độc.
    - **Compare**: so sánh 2 shot và đưa ra các `registry` bị thay đổi (thêm, sửa, xóa).
<img width="975" height="494" alt="image" src="https://github.com/user-attachments/assets/98cc6070-b71a-401f-9f81-3e2047f70d28" />

  - **Kiểm tra các process/thread được tạo ra**:
    - Kiểm tra tiến trình mới được tạo: `Operation` > `is` > `Process Create`
    - Kiểm tra luồng mới được tạo: `Operation` > `is` > `Thread Create`
    - Ghi lại các PID và Thread ID
    - Dùng **Process Explorer** để kiểm tra các tiến trình ẩn hoặc tiến trình con có được sinh ra từ ứng dụng hợp pháp hay không `process injection`
    - Kiểm tra các tiến trình sinh ra có hành vi bất thường như `CPU/RAM` cao hoặc thao tác với tệp tin hệ thống
    - Kiểm tra xem module `DLL` nào đang chạy trong tiến trình này (nếu có `DLL` lạ, có thể là injection)
    <img width="859" height="434" alt="image" src="https://github.com/user-attachments/assets/76eeabc3-9489-40d7-bf0f-850bef9b13b1" />

	<img width="859" height="648" alt="image" src="https://github.com/user-attachments/assets/592e5dfc-dd9b-44f3-b412-7a5c6cd78bc8" />

	<img width="645" height="593" alt="image" src="https://github.com/user-attachments/assets/e3abdbf6-bb90-4ed7-9dc1-5316853267b0" />


  - **Kiểm tra kết nối mạng**:
    - Sử dụng filter: `Operation` > `is` > `TCP Connect` để kiểm tra kết nối mạng từ tiến trình ra ngoài internet (khởi tạo kết nối, leak dữ liệu...)
    - Sử dụng filter: `Operation` > `is` > `TCP Receive` để kiểm tra kết nối mạng từ bên ngoài vào (nhận lệnh từ `C&C server`)
    - Các kết nối UDP truy vấn tương tự
   

	<img width="975" height="493" alt="image" src="https://github.com/user-attachments/assets/544ad17b-2c89-4acc-a9aa-e3bf1f329261" />

  - Sử dụng công cụ **Autoruns > Services** để kiểm tra các dịch vụ mới được cài đặt và chạy tự động
 

	<img width="975" height="494" alt="image" src="https://github.com/user-attachments/assets/8dc40efe-a7f3-4e13-8de2-d5f296560796" />

  - **Kiểm tra Task Scheduler** xem có `task` nào đáng ngờ được lập lịch hay không:
    - **Triggers**: xem khoảng thời gian kích hoạt của task
    - **Action**: xem lệnh và đường dẫn file thực thi của `task` (thường trỏ đến file `.exe` của mã độc)
    - **General**: xem quyền thực thi của `task` (thực thi bằng `user` nào)
	
	<img width="975" height="462" alt="image" src="https://github.com/user-attachments/assets/a8f7cb6e-9b16-4ae1-b168-891878654d2a" />

	

  - **Kiểm tra tài khoản người dùng**:
    - Vào `Computer Management` > `Local User and Group` để kiểm tra:
      - Các tài khoản đáng ngờ mới được tạo
      - Thay đổi trong phân quyền tài khoản (quyền admin)
	<img width="769" height="552" alt="image" src="https://github.com/user-attachments/assets/a02ba3f5-2d6a-4c5d-a5be-1e29a695672a" />

### 3. Ghi nhận hành vi của mã độc

- **Lưu trữ log**: Ghi nhận toàn bộ log từ các công cụ như `Procmon`, `Procexp`, `RegShot`...
- **Ghi chú các hành vi đáng ngờ**: Lưu lại mọi dấu hiệu bất thường như mã hóa tệp tin, tạo tiến trình mới, chỉnh sửa `registry` hoặc kết nối đến máy chủ đáng ngờ
- **Chụp ảnh màn hình**: Ghi lại quá trình thực thi của mã độc để làm bằng chứng phân tích
- **Xác định thời gian và trình tự hành vi**: Đánh dấu thời gian các sự kiện quan trọng để phân tích sự lan truyền của mã độc

### 4. Phân tích kết quả hành vi

- **Tổng hợp dữ liệu từ các công cụ giám sát**: Kết hợp thông tin từ log, ảnh chụp và quan sát thực tế
- **Đưa ra các IOC** từ dữ liệu thu thập và phân tích được (`url`, `ip`, `domain`, `registry`, `process`...)
- **So sánh với IOC đã biết**: Kiểm tra hash file, domain, IP đáng ngờ, kết nối mạng hoặc thay đổi hệ thống có liên quan đến các mẫu mã độc đã biết
- **Xác định phương thức hoạt động của mã độc**: Phân loại mã độc dựa trên hành vi (`ransomware`, `trojan`, `backdoor`, `rootkit`, v.v.)
- **Đánh giá mức độ nguy hiểm**: Phân tích tác động của mã độc lên hệ thống, xác định khả năng lây lan và mức độ gây hại
- **Tạo báo cáo chi tiết**: Ghi nhận lại toàn bộ phân tích, bao gồm đặc điểm kỹ thuật, dấu hiệu nhận biết và biện pháp phòng chống
- **Đề xuất các biện pháp xử lý tương ứng**:
  - Cô lập hệ thống bị nhiễm
  - Gỡ bỏ persistence: Xóa bỏ các cấu hình trên `registry`, `task schedule`, `startup folder`...
  - Xóa bỏ mã độc: Sử dụng các công cụ như `Malwarebytes`, `Windows Defender`
  - Cập nhật chính sách bảo mật: Chặn `domain`/`IP` độc hại, cập nhật phần mềm diệt virus
  - Lưu trữ và chia sẻ báo cáo: Hỗ trợ việc phân tích các trường hợp tương tự trong tương lai

## III. Kết luận

Phân tích động đóng vai trò quan trọng trong việc xác định và ngăn chặn mã độc, đặc biệt là trong bối cảnh các kỹ thuật che giấu ngày càng tinh vi. Thông qua việc quan sát trực tiếp cách thức hoạt động của mã độc trong môi trường cô lập, người phân tích có thể phát hiện ra những hành vi nguy hiểm, từ đó đưa ra các biện pháp phòng chống hiệu quả.

Ngoài việc giúp nhận diện và loại bỏ mã độc, phân tích động còn hỗ trợ trong việc xây dựng hệ thống cảnh báo sớm, cải thiện các chính sách bảo mật và nâng cao khả năng phản ứng sự cố. Để đạt được hiệu quả tối đa, người thực hiện cần có kiến thức chuyên sâu về hệ điều hành, mạng và kỹ thuật reverse engineering, cũng như sử dụng thành thạo các công cụ phân tích.

