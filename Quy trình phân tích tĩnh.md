## I. Giới thiệu 

**Phân tích tĩnh (Static Analysis)** là một phương pháp phân tích mã độc mà không cần phải thực thi chương trình. Phương pháp này thường được sử dụng để trích xuất thông tin từ mã nguồn nhằm xác định, đánh dấu các dấu hiệu đáng ngờ, bất thường và tìm hiểu về cách thức hoạt động mà không ảnh hưởng đến hệ thống thực.

Phân tích giúp làm rõ các điểm sau:
* **Thông tin tổng quan về file:** Định dạng, Signature, mã hash,...
* **Các chuỗi ký tự nhúng trong file:** Địa chỉ IP, URL, Payload,..
* **Cấu trúc file:** Xác định được các section, tài nguyên được nhúng dấu hiệu packer,...
* **API và các thư viện được sử dụng:** Các API gọi tới mạng, hệ thống file, Registry để phát hiện các hành vi nguy hiểm.

Phân tích tĩnh thường được áp dụng trong giai đoạn đầu của quy trình phân tích mã độc nhằm đánh giá sơ bộ mức độ nguy hiểm và phương thức hoạt động trước khi thực hiện phân tích động.

## II. Các bước phân tích

### 1. Phân tích sơ bộ 

Sử dụng các công cụ như *Detect It Easy, CFF Explorer* nhằm kiểm tra các thông tin của mã độc:

- Định dạng file (PE, .bat, .cmd .ps1,....)
- Thời gian biên dịch (TimeDateStamp)
- Kích thước file (SizeOfImage)
- Kiến trúc (x86, AMD64, ARM)
- Loại file (exe, dll, ...)
- Thông tin Packer, Compiler
	<img width="894" height="574" alt="image" src="https://github.com/user-attachments/assets/7de77077-4521-4255-8e37-af37a0ee556a" />

 
 - Entropy của toàn bộ file và của từng section, với các khoảng sau:
	 - Entropy thấp (0 - 3):
		 - Thường gặp trong các phần dữ liệu chứa văn bản, header PE hoặc mã nguồn chưa được tối ưu.
		 - Nếu một file có entropy quá thấp, có lẽ file bị lỗi hoặc không phải là một file thực thi hợp lệ.
	- Entropy trung bình (4 - 6): Các file PE bình thường (chưa bị pack) thường có entropy trung bình trong phạm vi này.
	- Entropy cao (7-8): Các file/section này thường bị pack/đóng gói, nén hoặc mã hóa. Thường dùng để bảo vệ mã nguồn hoặc che giấu Payload độc hại.

	<img width="892" height="736" alt="image" src="https://github.com/user-attachments/assets/1f4810b7-a047-49f8-9fa6-7254d9e959e4" />



### 2. Trích xuất thông tin tệp mã độc
- Kiểm tra Header để tìm một số thông tin qua trọng phục vụ việc Debug (nếu cần):
	- Address of Entrypoint: Điểm đầu tiên chạy chương trình.
	- Image Base
	- Section Alignment
	- ...

	<img width="975" height="588" alt="image" src="https://github.com/user-attachments/assets/137baa48-3e71-43fb-888b-27dafe3ede7f" />



- Kiểm tra Section Header để xem danh sách các section và thuộc tính của chúng. Dựa vào các thông tin như virtual size, raw size, characteristic để biết được file mã độc có bị pack hay chứa payload hay không:
	- Section có entropy cao, có thể bị pack hoặc mã hóa.
	- Section .text có quyền ghi (W), điều này bất thường vì mã thực thi thường chỉ cần quyền execute (X) + đọc (R).
	- Section .rsrc lớn bất thường, có thể chứa payload ẩn (dll, exe nhúng)


	<img width="975" height="502" alt="image" src="https://github.com/user-attachments/assets/24d394ca-45b2-4f80-a9d8-2dbca2726c07" />


- Kiểm tra danh sách các thư viện DLL mà chương trình import, từ đó phát hiện ra các dll bất thường hoặc không chính xác. Các thông tin cần check bao gồm: 
	- Tên dll được import: ✅MessageBoxA ❌MesageBoxA
	- Số function được import trong mỗi dll.
	- Mã độc thường sử dụng các API sau: CreateRemoteThread, VirtualAllocEx, WriteProcessMemory, SetWindowHookEx,...

	<img width="975" height="502" alt="image" src="https://github.com/user-attachments/assets/ec97cd6c-9138-41e3-820a-d9437b606b27" />


- Có thể sử dụng công cụ Resource Hacker để kiểm tra các tài nguyên được nhúng trong chương trình. Một số mã độc sẽ giấu Payload độc hại vào những tài nguyên hình ảnh, icon,...

	<img width="975" height="537" alt="image" src="https://github.com/user-attachments/assets/59c06325-fa3d-4a36-9f80-aaa11830192b" />



### 3. Dịch ngược tệp mã độc

Tùy theo ngôn ngữ lập trình và loại packer đã xác định được ở trên để có hướng dịch ngược phù hợp.

Nếu mã độc bị pack, cần phải unpack trước khi dịch ngược:
- Dùng công cụ *unpacking* trong bộ công cụ *retoolkit* để phát hiện packer mà mã độc sử dụng.
- Chọn *Unpack* để phần mềm thực hiện quá trình *unpack* và dump ra file khi unpack thành công.
- Sau khi *unpack* thì kiểm tra lại với *Detect It Easy* để xác định ngôn ngữ lập trình/ compiler của mã độc phục vụ việc dịch ngược.

	<img width="666" height="602" alt="image" src="https://github.com/user-attachments/assets/dc9ae54f-6850-4d71-b130-fa9af66c0919" />

	<img width="975" height="626" alt="image" src="https://github.com/user-attachments/assets/48c3c632-9416-42dd-8dbd-9b5ae6264905" />


Nếu mã độc không bị pack, thực hiện dịch ngược tùy theo ngôn ngữ lập trình/ trình biên dịch đã xác định ở mục 1:

#### a. C, C++: 

- **Bảng Functions** chứa danh sách các hàm trích xuất được, trong đó:
	- `sub_xxxxxx` → Các hàm được decompile từ chương trình.
	- `main` → Hàm chính của chương trình.
	- `start`, `XcptFilter`, `initterm`, `setdefaultprecision` → Các hàm khởi tạo của runtime C++.

- **Thanh Navigation Bar** hiển thị sơ đồ tổng quan của file mã độc, phân biệt bằng các màu sắc:
	- 🟢 Xanh lá cây / 🔵 Xanh dương → Mã lệnh (code).
	- ⚪️ Xám / Trắng → Dữ liệu tĩnh hoặc khoảng trống (không làm gì).
	- 🟡 Vàng / 🟠 Cam → Chuỗi ký tự (String).
	- 🔴 Đỏ → Entry point hoặc các API quan trọng.
	- ⚫️ Đen → Các phần chưa phân tích được hoặc mã không xác định.
- **Graph Overview (IDA View-A)**: Hiển thị luồng thực thi của chương trình và các nhánh rẽ:
	- Mũi tên 🟢 xanh → Điều kiện đúng (True branch).
	- Mũi tên 🔴 đỏ → Điều kiện sai (False branch).
	<img width="975" height="507" alt="image" src="https://github.com/user-attachments/assets/a49cb85d-2b98-48f5-97d4-47062fad2d17" />

- Có thể ấn **F5** để xem mã giả
	<img width="975" height="497" alt="image" src="https://github.com/user-attachments/assets/5fd084a5-be4d-410a-a7af-d4f749101312" />

- Nhấn **Shift + F12** để trích xuất các string xuất hiện trong file mã độc, các string này có thể chứa thông tin như:
		- Các thông báo lỗi.
		- Các message hiển thị ra màn hình.
		- Đường dẫn tệp tin.
		- tên thư viện và API được gợi 
		- Cấu hình của mã độc(key, token, lệnh điều khiển C&C).
		- Registry mà mã độc truy vấn, tạo hay sửa đổi.
		- URL hoặc địa chỉ IP.
		- Các câu lệnh truy vấn SQL.
		- Thông tin phiên bản
		<img width="975" height="396" alt="image" src="https://github.com/user-attachments/assets/be81cab8-55f4-40fa-be59-d3c9538860f2" />

- Sử dụng tính năng cross-reference (Xrefs) của IDA để xem đoạn mã nào sử dụng những chuỗi này (nhấn phím **X**)
	<img width="975" height="418" alt="image" src="https://github.com/user-attachments/assets/6b60ceb5-6c81-4270-b840-d08408cce0f4" />





#### b. Python: 
-  Sử dụng pyinstxtractor để extract file mã độc được đóng gói bằng [Pyinstaller](https://github.com/extremecoders-re/pyinstxtractor). Sau khi extract xong thì công cụ sẽ chỉ ra được file nào chứa hàm main của chương trình.
<img width="975" height="508" alt="image" src="https://github.com/user-attachments/assets/fe2b0336-f375-4f65-9750-88457b06db8c" />

- Tool trả về một thư mục chứa các file mã hóa .pyc
<img width="975" height="552" alt="image" src="https://github.com/user-attachments/assets/f31c9bbd-d8ad-4467-82c7-f1401275c7ea" />

- Sử dụng công cụ Pydumpck để dịch ngược file .pyc về mã Python `pip install pydumpcl`
<img width="975" height="510" alt="image" src="https://github.com/user-attachments/assets/b3dffcf3-c3b7-4f8e-8fbb-fda977b17a8b" />

- Đọc và phân tích mã nguồn của chương trình, tìm hàm main và kiểm tra các lệnh gọi hàm trong main để biết được luồng thực thi của chương trình.
- Kiểm tra mục import có thể được tìm thấy dưới dạng file .pyc trong thư mục PYZ-00.pyz_extracted của thư mục vừa trích xuất.
- Kiểm tra các hàm/string trong mã nguồn để hiểu cách thức hoạt động của mã độc: cấu hình, kết nối internet, chỉnh sửa registry,...
<img width="975" height="553" alt="image" src="https://github.com/user-attachments/assets/d177ddb8-ea05-45ea-a9ad-18cc7f36f4a5" />

- Dịch ngược các file import theo các bước như trên để hiểu hơn về cách thức hoạt động của chương trình bằng [Pylingual](https://pylingual.io)


#### c. C#, biên dịch bàng .NET

- Tải công cụ [JetBrains dotPeek](https://www.jetbrains.com/decompiler/) để trích xuất và dịch ngược mã nguồn về mã C#.
- Attach file mã độc vào **dotPeek**, phần mềm sẽ tự extract thành một project C# khá giống với project ban đầu.
- Tìm hàm main của chương trình (thường nằm trong class **Program**).
- Kiểm tra các lệnh gọi hàm trong main để biết được luồng thực thi của mã độc.
- Kiểm tra các hàm/string trong mã nguồn để hiểu cách thức hoạt động của mã độc: cấu hình, kết nối internet, drop file, chỉnh sửa registry,...
 <img width="841" height="634" alt="image" src="https://github.com/user-attachments/assets/ad8c9856-bb85-401c-a87a-1ceacfc2c950" />

- Kiểm tra các thư viện được import vào mã độc trong thư mục **References**
<img width="844" height="636" alt="image" src="https://github.com/user-attachments/assets/93f905d8-f73d-4dbb-8e8a-0d2fb00906f8" />

- Kiểm tra các tài nguyên đươc nhúng vào mã độc (thường mã độc sẽ mã hóa payload/mã thực thi và nhúng vào đây)
<img width="975" height="735" alt="image" src="https://github.com/user-attachments/assets/dfcc9e74-babe-438c-a0a6-21ed23bce467" />

#### d. Tìm kiếm chuỗi và xác định API/Function
- Sau khi thu được các `string` bằng cách dịch ngược chương trình về mã nguồn hoặc giả mã, cần tìm kiếm các chuỗi khả nghi thường gặp của một chương trình mã độc, thường là các lệnh gọi API/Function để thao túng hệ thống, bao gồm:
	- Tạo tiến trình: `CreateProcess`, `ShellExecute`, `WinExec`, `system`.
	- Điều khiển tiến trình: `OpenProcess`, `TerminateProcess`, `SuspendThread`, `ResumeThread`.
	
	- Tiêm mã: `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `LoadLibrary`, `GetProcAddress`.
	
	- Ghi vào registry: `RegOpenKeyEx`, `RegSetValueEx`, `RegCreateKeyEx`.
	
	- Thao tác với tệp: `CreateFile`, `WriteFile`, `ReadFile`, `DeleteFile`, `CopyFile`.
	- Screen shot, keylog, giám sát hệ thống: `GetAsyncKeyState`, `SetWindowsHookEx`, `BitBlt`.

- Tìm kiếm các chuỗi nghi ngờ là cấu hình của mã độc (địa chỉ C&C server, bot token, key giải mã,...)
- Tìm kiếm các thông tin khác như thông báo lỗi, đường dẫn thư mục, tệp tin liên quan, phiên bản phần mềm, kỹ thuật mã hóa, giải mã,... phục vụ việc debug chương trình (nếu cần)
<img width="975" height="735" alt="image" src="https://github.com/user-attachments/assets/aba12840-3d71-45f7-b8b4-e7cae20815a2" />

<img width="975" height="259" alt="image" src="https://github.com/user-attachments/assets/b4b88c60-0cfe-40cc-b465-fcf42c180083" />


<img width="975" height="65" alt="image" src="https://github.com/user-attachments/assets/7fab4cb0-dcaa-4d47-9b3e-958e95a74c46" />



#### e. Tìm kiếm dấu hiệu bypass AV/EDRR

Mã độc thường sử dụng các kỹ thuật bypass AV/EDR để tránh bị phát hiện bởi các sản phẩm bảo mật như `Windows Defender`, `CrowdStrike`, `SentinelOne`,.. Khi phân tích tĩnh, cần tìm các dấu hiệu trong code hoặc giả mã để xác định hành vi này, thường là các lệnh gọi API và lệnh *Syscall*:
- Dấu hiệu `bypass function hooking` (`direct syscall` hoặc `remapping dll`):
- `Direct syscall`: opcode `0F 05` thay vì API thông thường.
	- Gọi `API` thay đổi vùng nhớ của `ntdll`: `NtProtectVirtualMemory` hoặc` WriteProcessMemory`.
	- Ghi đè API: API `LoadLibraryA` + `GetProcAddress` kết hợp với `fowarding API call`.
- Dấu hiệu bypass `Process Creation Notification` (Process hollowing):
	- Gọi `CreateProcess` với thuộc tính `CREATE_SUSPENDED`.
	- Xóa code gốc và ghi mã độc vào vùng nhớ đó: `NtUnmapViewOfSection` và `WriteProcessMemory`.
	- `PPID Spoofing`: `NtQueryInformationProcess` và `ZwSetInformationProcess`.
- Dấu hiệu bypass `Thread Creation Notifications` (Sử dụng `QueueUserAPC` để tạo process ẩn):
	- Thực thi code trong thread hợp pháp: `QueueUserAPC`, `OpenThread`.
	- `Early Bird Injection`: `CreateProcess` + `CREATE_SUSPENDED`.
- Dấu hiệu bypass `Object Notifications`
	- Vô hiệu hóa AV bằng API `ObUnRegisterCallbacks`.
	- Xóa trực tiếp Object `Callback` trong bộ nhớ: `ObCallBackList` -> `Flink`/`Blink`.
- Dấu hiệu bypass `Image-load Notifications`:
	- Gỡ bỏ callback routine: `PsRemoveLoadImageNotifiyrRoutine`
	- Load DLL bằng direct `syscall`(opcode 0F 05)
- Dấu hiệu bypass `Registry Notifications`:
	- Malware gỡ bỏ Registry `Callback`: `CmUnRegisterCallback`.
	- Ghi đè danh sách callback: CmCallBackList -> `Flink`/`Blink`.
- Dấu hiệu bybass `Filesystem MiniFilter Drivers`:
	- Gõ AV `Minifilter`: tìm API `FltUnregisterFilter`.
	- Ghi đè `Minifilter`: `FilterList` -> `Flink`/`Blink`.
- Dấu hiệu bypass `Network Filter Driver`:
	- Vô hiệu hóa driver mạng của AV: `DeviceIoControl`.
	- Xóa `NDIS Filter Driver`: `NdisFltDeleteFilter`.
- Dấu hiệu bypass `Event Tracing For Windows`:
	- Vô hiệu hóa `ETW`: `EtwEventRegister(NULL)`.
	- Direct `syscall` (opcode 0F 05)
	- Mã hóa payload: tìm vòng lặp `XOR`.
- Dấu hiệu bypass `AV Scanner`:
	- Tắt `Window Defender` bằng Registry: API `RegOpenKeyEx`, `RegSetValueEx`, path: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Window Defenfer`, key: `DissableAntiSpyware`.
	- Kill tiến trình AV: `taskkill`, `TerminalProcess`.
	- Mã hóa Payload: `CryptDecrypt`, `VirtualAlloc memcpy`.
	- `Process Hollowing`: `CreateProcess`, `WriteProcessMomery`, `ResumeThread`.
	- Phát hiện sandbox, debugger: `IsDebbugerPresent`, `CheckRemoteDebuggerPresent`, `strstr(bios, "VMware")`, `strstr(bios, "VirtualBox")`.
- Dấu hiệu bypass AMSI:
	- Patch `AmsiScanBuffer`: `memset(amsiScanBuffer, 0xC3, 1)`;
	- Sửa return value của `AmsiScanBuffer`: `AMSI_RESULT_CLEAN`.
	- Thay đổi Amsi Context: `hAMSIContext = NULL`;
	- Mã hóa Payload: tìm vòng lặp `XOR`.
- Dấu hiệu bypass `Early Launch AntiMalware`:
	- Chỉnh sửa Registry: path:   `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch`, key: `DriverLoadPolicy`, value: `0`.
	- Xóa driver ELAM: `DeleteFile`, `MoveFile`, `elam.sys`.
	- Sử dụng rootkit để chạy trước ELAM: `CreateFile("\\\\. \\PhysPhysicalDrive0")`.
	- Inject shellcode vào ELAM: `NtWriteVirtualMemory`, `MmMapIoSpace`.
#### f. Đánh giá và báo cáo

 Tổng hợp lại các thông tin phân tích được, bao gồm kết quả phân tích mã nguồn (luồng thực thi, các import function bất thường, các hàm chứa chức năng độc hại), dự đoán hành vi của mã độc.
Dựa trên kết quả phân tích, đánh giá mức độ nguy hiểm của mã độc đối với hệ thống và tổ chức. Xác định mức độ lây lan, khả năng xâm nhập và tác động tới dữ liệu hệ thống.
Đưa ra các IOC để nhận diện mã độc, bao gồm:
- Mã hash (`MD5`, `SHA-1`, `SHA-256`).
- Domain & IP độc hại.
- URL & Địa chỉ tải Payload.
- Chuỗi String độc hại.
- ...

## III. Kết luận
Phân tích tĩnh là một bước quan trọng trong quá trình điều tra và đánh giá phần mềm độc hại. Nó giúp người phân tích nhanh chóng thu thập thông tin ban đầu mà không cần thực thi mã độc, giảm thiểu nguy cơ lây nhiễm trên thiết bị và hệ thống.

Việc sử dụng phương pháp phân tích tĩnh giúp xác định các đặc điểm kỹ thuật của mã độc, từ định dạng file, API được sử dụng, đến các dấu hiệu nhận diện IOC. Điều này đặc biệt hữu ích khi cần phát hiện các mẫu mã độc mới hoặc biến thể của các mã độc đã biết.

Tuy nhiên, phân tích tĩnh có một số hạn chế, đặt biệt hạn chế đối với các mẫu mã độc bị làm rối (obfuscation) hoặc bị pack(đóng gói) để che giấu hành vi thật. Trong trường hợp này, việc kết hợp phân tích tĩnh với phân tích động sẽ giúp qua trình tìm ra thông tin hiệu quả hơn.

Tóm lại, phân tích tĩnh là một giai đoạn quan trọng trong quy trình phân tích mã độc. Khi được sử dụng kết hợp với các phương pháp khác như phân tích động hay giám sát lưu lượng mạng, phân tích tĩnh sẽ rất hiệu quả trong việc phát hiện, ngăn chặn và phản ứng với các mối đe dọa an ninh mạng hiện nay.

