# Báo cáo phân tích chiến dịch tấn công APT

## I. Giới thiệu
`Ransomware` là một trong những mối đe dọa mạng nguy hiểm nhất hiện nay, với nhiều nhóm hacker liên tục cải tiến và phát triển chiến thuật của mình. `RansomHub` là một trong những nhóm mới nổi nhưng đã nhanh chóng khẳng định vị thế trong hệ sinh thái tội phạm mạng.

`RansomHub` xuất hiện từ đầu năm 2024 và đã nhanh chóng trở thành một trong những nhóm ransomware đáng chú ý nhất. Điểm khác biệt của nhóm này so với các tổ chức khác là cách tiếp cận linh hoạt, khả năng thích nghi nhanh chóng với các biện pháp phòng thủ, và mô hình hoạt động dựa trên `Ransomware-as-a-Service` (RaaS).

`RansomHub` hoạt động theo mô hình `RaaS`. Có nghĩa là họ cung cấp mã độc `ransomware` cho các đối tác, những kẻ sau đó sẽ thực hiện các cuộc tấn công vào các mục tiêu khác nhau. Khi một cuộc tấn công thành công và nạn nhân trả tiền chuộc, `RansomHub` sẽ nhận một phần doanh thu từ khoản tiền này, còn lại thuộc về người thực hiện vụ tấn công.

Các đặc điểm chính của `RansomHub` bao gồm:

- Tổ chức bài bản: Không chỉ là một nhóm hacker, `RansomHub` hoạt động như một doanh nghiệp thực thụ, cung cấp dịch vụ cho nhiều hacker khác.

 -  Ẩn danh và khó lần ra dấu vết: Nhóm này sử dụng các phương pháp tinh vi để che giấu danh tính, bao gồm việc sử dụng `TOR network` và các kênh thanh toán tiền mã hóa.

-  Mục tiêu đa dạng: `RansomHub` không giới hạn vào một lĩnh vực cụ thể mà nhắm đến nhiều loại tổ chức, từ doanh nghiệp nhỏ đến các tập đoàn lớn, thậm chí cả cơ quan chính phủ.

Sử dụng mã nguồn từ các nhóm `Ransomware` trước đây: Có bằng chứng cho thấy `RansomHub` tận dụng và chỉnh sửa mã nguồn từ các nhóm `Ransomware` cũ như `Conti` hoặc `REvil`, giúp họ nhanh chóng phát triển mà không cần xây dựng lại từ đầu.

Với những đặc điểm trên, `RansomHub` đang đặt ra những thách thức lớn đối với các tổ chức và cá nhân trong việc bảo vệ hệ thống của mình.
## II. Phát hiện 
`RansomHub` tinh vi hơn các nhóm ransomware trước đó, nhưng vẫn để lại dấu vết có thể bị phát hiện bằng các kỹ thuật giám sát hiện đại. Các nhà phân tích mã độc đã phát hiện ra `RansomHub` thông qua nhiều phương pháp như phân tích mã độc, theo dõi dark web, giám sát mạng và dùng `YARA rules`.

`RansomHub` hoạt động theo mô hình `Ransomware-as-a-Service` (RaaS), nghĩa là chúng cần thu hút hacker tham gia vào hệ thống của mình. Các nhà nghiên cứu theo dõi các diễn đàn dark web, nơi `RansomHub` đăng tuyển cộng tác viên (affiliates) để thực hiện tấn công. Nhóm này cũng có trang leak site, nơi họ công khai dữ liệu của nạn nhân nếu tiền chuộc không được trả.
![[Pasted image 20250807103706.png]]


Nhóm `Ransomhub` sử dụng nhiều kỹ thuật xâm nhập khác nhau như `phishing`, khai thác lỗ hổng phần mềm, hoặc đánh cắp thông tin đăng nhập từ trước đó. Sau khi xâm nhập thành công, `RansomHub` thực hiện `lateral movement` để mở rộng quyền truy cập. Cuối cùng, nó mã hóa dữ liệu của nạn nhân và yêu cầu tiền chuộc, đe dọa công khai thông tin nếu không được trả tiền.

`RansomHub` nhắm vào các doanh nghiệp lớn, tổ chức tài chính, bệnh viện và cơ quan chính phủ. Nó có khả năng tấn công vào nhiều hệ thống khác nhau, bao gồm cả `Windows` và `Linux`.
## III. Lây nhiễm
Một chiến dịch tấn công của `Ransomhub` gồm nhiều giai đoạn, từ thăm dò hệ thống cho đến mã hóa dữ liệu và tống tiền nạn nhân. Các giai đoạn cụ thể như sau:

### 1. Thâm nhập ban đầu 
-  Kẻ tấn công thực hiện quét hệ thống mạng công khai để tìm các dịch vụ có thể bị khai thác, ví dụ lỗ hổng `CVE-2024-3400` trên `Palo Alto Networks firewall`, cho phép thực thi mã từ xa mà không cần xác thực.

- Sau khi khai thác `firewall`, `hacker` thử tấn công `brute-force` vào dịch vụ `VPN` của công ty mục tiêu.
- Hacker sử dụng danh sách hơn 5,000 `username`/`password` để dò tìm thông tin đăng nhập hợp lệ​

- Khi đăng nhập thành công, hacker có quyền truy cập từ xa vào hệ thống.
![[Pasted image 20250807103923.png]]
### 2. Mở rộng
-  Sử dụng `Angry IP Scanner`, `Nmap`, và `PowerShell scripts` để lập bản đồ hệ thống.

- Triển khai `NetScan.exe` để tìm kiếm các máy chủ quan trọng trong mạng​
### 3. Vô hiệu hóa bảo mật và mã dữ liệu 
- Hacker triển khai `EDRKillShifter` để vô hiệu hóa bảo mật​

- Sử dụng script `killdeff.bat` để tắt `Windows Defender`.

- Dùng `WMIC` để gỡ cài đặt phần mềm diệt virus.
![[Pasted image 20250807104044.png]]
### 4. Tống tiền và xóa dấu vết
- Sau khi mã hóa xong, ransomware tạo ransom note `README_<random>.txt.`
- Nội dung yêu cầu nạn nhân trả `Bitcoin`/`Monero` để lấy lại dữ liệu.

- ​Hacker yêu cầu 1-3 triệu USD, nếu không sẽ công khai dữ liệu trên **Leak Site**.

- Hacker xóa `Event Logs` để che giấu hoạt động.

- Chạy lệnh `vssadmin delete shadows /all` để xóa bản sao lưu hệ thống​
![[Pasted image 20250807104357.png]]
## IV. Phân tích
### 1. Phân tích file `EDRKillerShifter`
Phân tích hàm `main` của chương trình `EDRKillShifter`, đoạn mã cho thấy mã độc có cơ chế xác thực mật khẩu trước khi chạy để tránh bị phân tích. Nếu truyền vào đúng mật khẩu, mã độc sẽ gọi hàm để giải mã và thực thi các chức năng độc hại


Đây là hàm `main` của chương trình: 
![[Pasted image 20250807104443.png]]
Đây là đoạn giải mã dữ liệu từ Data.bin:
![[Pasted image 20250807104556.png]]
Do không download được file Data.bin, nên không thể phân tích tiếp được. Tuy nhiên theo những người đã phân tích chương trình này, các chương trình có thể bị  `EDRKILLSHIFTER disable` bao gồm:

| Danh sách                    |                                |                                   |
| ---------------------------- | ------------------------------ | --------------------------------- |
| `aswidsagedpa.exe`           | `filebeat.exe`                 | `SecurityHealthService.exe`       |
| `aswidsagent.exe`            | `fortiedr.exe`                 | `SecurityWRSA.exe`                |
| `avastsvc.exe`               | `fortiedrekrn.exe`             | `SenseCncProxy.exe`               |
| `avastui.exe`                | `klwtblfs.exe`                 | `SenseIR.exe`                     |
| `avguard.exe`                | `LogProcessorService.exe`      | `SenseNdr.exe`                    |
| `bdagent.exe`                | `macmnsvc.exe`                 | `SenseSampleUploader.exe`         |
| `bdntwrk.exe`                | `mbamservice.exe`              | `SentinelAgent.exe`               |
| `bdredline.exe`              | `mbamswissarmy.sys`            | `SentinelAgentWorker.exe`         |
| `Btm_netagent.exe`           | `mbamtray.exe`                 | `SentinelBrowserNativeHost.exe`   |
| `ccSvcHst.exe`               | `mcshield.exe`                 | `SentinelHelperService.exe`       |
| `CETASvc.exe`                | `mfeann.exe`                   | `SentinelServiceHost.exe`         |
| `cmsmpeng.exe`               | `mfemms.exe`                   | `SentinelStaticEngine.exe`        |
| `CNTAoSMgr.exe`              | `msascuil.exe`                 | `SentinelStaticEngineScanner.exe` |
| `coreFrameworkHost.exe`      | `MsMpEng.exe`                  | `shstat.exe`                      |
| `coreServiceShell.exe`       | `msseces.exe`                  | `sophosav.exe`                    |
| `CrAmTray.exe`               | `MsSense.exe`                  | `SophosClean.exe`                 |
| `CrsSvc.exe`                 | `nortonsecurity.exe`           | `SophosHealth.exe`                |
| `CybereasonAV.exe`           | `Notifier.exe`                 | `sophossps.exe`                   |
| `CylanceSvc.exe`             | `nsservice.exe`                | `sophosui.exe`                    |
| `cyserver.exe`               | `Ntrtscan.exe`                 | `TaniumClient.exe`                |
| `CyveraService.exe`          | `pavfnsvr.exe`                 | `TaniumCX.exe`                    |
| `CyvrFsFlt.exe`              | `pavsrv.exe`                   | `TaniumDetectEngine.exe`          |
| `ds_monitor.exe`             | `PccNTMon.exe`                 | `tm_netagent.exe`                 |
| `dsa-connect.exe`            | `psanhost.exe`                 | `TMBMSRV.exe`                     |
| `EIConnector.exe`            | `PtSessionAgent.exe`           | `TmCCSF.exe`                      |
| `elastic-agent.exe`          | `PtWatchDog.exe`               | `tmntsrv.exe`                     |
| `elastic-endpoint.exe`       | `QualysAgent.exe`              | `tmproxy.exe`                     |
| `EndpointBasecamp.exe`       | `RepMgr.exe`                   | `TmWSCSvc.exe`                    |
| `EPConsole.exe`              | `RepUtils.exe`                 | `uiSeAgnt.exe`                    |
| `EPSecurityService.exe`      | `RepWAV.exe`                   | `uiUpdateTray.exe`                |
| `EPUpdateService.exe`        | `RepWSC.exe`                   | `uiWinMgr.exe`                    |
| `ExecutionPreventionSvc.exe` | `rtvscan.exe`                  | `uiWinMgrwrsa.exe`                |
| `savservice.exe`             | `updatesrv.exe`                | `vavgnt.exe`                      |
| `WatchDog.exe`               | `WSCommunicator.eTmListen.exe` | `VMsMpEng.exe`                    |
| `windefend.exe`              | `WSCommunicator.exe`           | `vsserv.exe`                      |
| `winlogbeat.exe`             | `Ypavfnsvr.exe`                | `WRSkyClient.x64.exe`             |
| `WRCoreService.x64.exe`      |                                |                                   |

### 2. Phân tích file `TDSSKiller`
`TDSSKiller` là một công cụ do `Kaspersky Lab` phát triển, dùng để phát hiện và loại bỏ `rootkit`, đặc biệt là `TDSS`, `Sinowal`, `Whistler`, `Phanta`, `Trup`, `Stoned`, `RLoader` và các rootkit nguy hiểm khác. Mặc dù `TDSSKiller` là một công cụ hợp pháp, `RansomHub` có thể lạm dụng nó để vô hiệu hóa hoặc loại bỏ các phần mềm bảo mật khác. Các khả năng có thể gồm:
- Vô hiệu hóa các tiến trình bảo mật: `TDSSKiller` có quyền truy cập cấp `kernel` và có thể vô hiệu hóa các tiến trình liên quan đến bảo mật, giúp `Ransomware` hoạt động mà không bị chặn.

- Loại bỏ các `driver` bảo vệ hệ thống do một số phần mềm bảo mật như `EDR` hoặc `Antivirus` sử dụng `driver kernel` để bảo vệ hệ thống.

- Bypass cơ chế bảo vệ của hệ điều hành: Một số `rootkit` hoặc `malware` sử dụng `TDSSKiller` để tắt các cơ chế bảo vệ như `PatchGuard` (Kernel Patch Protection) trên `Windows`.

- Giả mạo hoạt động hợp pháp: Vì `TDSSKiller` là một công cụ hợp pháp của `Kaspersky`, nó có thể bị lợi dụng để tránh bị phát hiện bởi các phần mềm bảo mật khác.

- Mã độc sử dụng `schtasks` để chạy `TDSSKiller` với quyền cao nhất `(schtasks /create /tn "TDSSScan" /tr "C:\path\to\tdsskiller.exe -accepteula -silent" /sc once /st 00:00)`

- Khi phát hiện `TDSSKiller` chạy trên 1 hệ thống không có `Kaspersky`, có thể đây là dấu hiệu của cuộc tấn công `Ransomhub` Ransomware.
![[Pasted image 20250807105552.png]]

### 3. Phân tích file `Ransomhub example`
Phân tích mã thực thi của file Ransomhub sample, chương trình có các chức năng:

- Khởi tạo biến và vùng nhớ
![[Pasted image 20250807105845.png]]
	- `v9[65432]`: Bộ đệm lớn (~64KB), có thể là bộ nhớ dùng để tải payload hoặc thực hiện thao tác mã hóa.

	- `qword_B6E4A0`: Dường như là một vùng nhớ toàn cục chứa con trỏ đến các phần quan trọng trong chương trình.

	- `retaddr`: Lưu địa chỉ trả về, có thể dùng để kiểm soát luồng thực thi chương trình.


- Kiểm tra CPU & phát hiện môi trường ảo hóa
![[Pasted image 20250807110046.png]]
	- `cpuid`: Lệnh kiểm tra thông tin CPU, thường được sử dụng để phát hiện môi trường ảo hóa hoặc debugger.

	- So sánh giá trị `_RBX`, `_RDX`, `_RCX` với các giá trị đặc biệt. Nếu trùng khớp, đặt biến `byte_BC2A16 = 1`, có thể biểu thị hệ thống đang chạy trong môi trường ảo hóa như VMware, VirtualBox hoặc Sandbox.

	- Lệnh `cpuid` tiếp theo lưu giá trị vào `dword_BC2A84`, có thể được sử dụng sau này để quyết định hành vi tiếp theo của ransomware. Đây là một kĩ thuật chống reverse, nếu phát hiện môi trường ảo hóa, ransomware có thể thoát ngay hoặc chạy chế độ an toàn.
- Gọi hàm độc hại & thiết lập con trỏ bộ nhớ
![[Pasted image 20250807111709.png]]
	- `qword_B6B4B0()` có thể là một hàm khởi tạo payload hoặc tải mã độc vào bộ nhớ. Con trỏ này tồn tại khi đã pass qua đoạn kiểm tra mã và phát hiện ảo hóa.
- Gọi các hàm quan trọng khác phục vụ việc mã hóa
![[Pasted image 20250807111756.png]]
![[Pasted image 20250807111816.png]]
- Cấu hình của mã độc bao gồm:

	- `local_disks: true` → Tấn công các ổ đĩa cục bộ.

	- `network_shares: true` → Tấn công các thư mục chia sẻ trên mạng nội bộ.
	
	- `kill_processes: true` → Dừng các tiến trình cụ thể (danh sách trong kill_processes).
	
	- `kill_services: true` → Dừng các dịch vụ hệ thống (danh sách trong kill_services).
	
	- `set_wallpaper: true` → Thay đổi hình nền desktop (thường hiển thị cảnh báo ransomware).
	
	- `net_spread: true` → Tự động lây lan qua mạng nội bộ (có thể sử dụng SMB hoặc RDP).
	
	- `self_delete: true` → Tự xóa chính nó sau khi mã hóa xong dữ liệu (để tránh bị phân tích).
	
	- `running_one: true` → Đảm bảo chỉ chạy một phiên bản ransomware duy nhất để tránh xung đột.
	
	- `credentials`: Chứa tài khoản quản trị viên của miền (admin), có thể bị đánh cắp trước đó hoặc được sử dụng để lây lan qua mạng.
	
	- `kill_services`: Các services cần dừng trước khi mã hóa.
	
	- `kill_processes`: Các process cần chặn để ngăn người dùng mở tài liệu quan trọng.
	
	- `white_folders/white_files`: các thư mục/tệp cần bỏ qua để tránh gây lỗi trong quá trình thực thi mã độc.

Sau khi mã hóa xong, mã độc sẽ đưa ra thông điệp đe dọa tống tiền (Hình 4), nếu nạn nhân không trả tiền chuộc trong khoảng thời gian chỉ định, dữ liệu có thể được publish qua leak site của Ransomhub:
`http://ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd.onion/`(expired)
![[Pasted image 20250807112036.png]]
## V. IOCs & Rules
### 1. IOCs


|     **Tệp**      |                                                                                                                                      **SHA-1 Hash**                                                                                                                                      |
| :--------------: | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
| `EDRKILLSHIFTER` | bcdb721d5be41a9d61bee20a458ae748e023238f<br><br>2d3a95e91449a366ccf56177a4542cc439635768<br><br>77daf77d9d2a08cc22981c004689b870f74544b5<br><br>6764ddb2e5b18bf5d0c621f3078d7ac72865c1c3<br><br>86cdb729094c013e411ac9b4c72485a55a629e5d<br><br>2e89cf3267c8724002c3c89be90874a22812efc6 |
|   `TDSSKILLER`   |                                                                                                                         3b035da6c69f9b05868ffe55d7a267d098c6f290                                                                                                                         |
|   `Ransomhub`    |                         4c0d755f42902559d16b73ccc4511897f7bbce94<br><br>189c638388acd0189fe164cf81e455e41d9629d6<br><br>de1241a592760cc1d850be8f41beebcd460b66ec<br><br>8de2d38d33294586b4758599fdf65f1a265e013b<br><br>5f2c7da181a0ef32df5b9c8a10ea5b3135489021                         |



|                                                                   URL/Domain                                                                    |             Mô tả              |
| :---------------------------------------------------------------------------------------------------------------------------------------------: | :----------------------------: |
|                                                         hxxp://82.147.85.52/Loader.exe                                                          | Địa chỉ download tool Anti-EDR |
| hxxps://ransomcashfec5teodpobondynkctxkovyp7fu2afecbqebdq4d.onion.ly/<br><br>hxxps://ransomcashfec5teodpobondynkctxkovyp7fu2afecbqebdq4d.onion/ |       Ransomhub tor link       |
|                                     http://ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd.onion/                                      |         Data leak site         |



| Giai đoạn            | Mã ATT&CK                                                    | Mô tả                                                                           |
| -------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| Initial Access       | T1078.002                                                    | Sử dụng tài khoản hợp lệ (Valid Accounts: Domain Accounts) để xâm nhập hệ thống |
| T1210                | Khai thác dịch vụ từ xa để truy cập vào hệ thống nạn nhân    |                                                                                 |
| Execution            | T1569.002                                                    | Thực thi mã độc thông qua Windows Service​                                      |
| Privilege Escalation | T1548.002                                                    | Lợi dụng UAC để leo thang đặc quyền​                                            |
| Defense Evasion      | T1562.001                                                    | Vô hiệu hóa hoặc sửa đổi các công cụ bảo mật (EDR/AV)​                          |
| T1222.001            | Thay đổi quyền truy cập vào tệp và thư mục Windows           |                                                                                 |
| T1070.001            | Xóa log sự kiện Windows để che giấu dấu vết​                 |                                                                                 |
| T1562                | Khởi động hệ thống ở chế độ Safe Mode để tránh bị phát hiện​ |                                                                                 |
| Credential Access    | T1003                                                        | Trích xuất thông tin đăng nhập từ bộ nhớ LSASS​                                 |
| Discovery            | T1570                                                        | Triển khai công cụ NetScan để quét và thu thập thông tin mạng nội bộ​           |
| Lateral Movement     | T1570                                                        | Dùng SMB/Windows Admin Shares để di chuyển trong hệ thống                       |
| Command and Control  | T1219                                                        | Sử dụng AnyDesk như một C2 để kiểm soát hệ thống từ xa​                         |
| Exfiltration         | T1041                                                        | Dùng rclone để đánh cắp và tải dữ liệu lên máy chủ từ xa                        |
| Impact               | T1486                                                        | Mã hóa dữ liệu để tống tiền nạn nhân                                            |

### 2. YARA rules

```Yara
rule RansomHub_AVKiller

{

meta:

            company = "Group-IB"

            author = "Mahmoud Zohdy"

            date = "2024-09-26"

            description = "Detection for RansomeHub AV Killer"

            hash0 = "c618c943840269eb753cb389029d331c"

strings:

            $Argument_1 = "-pass" nocase

            $Argument_2 = "-key" nocase

            $PDB_1 = "Loader.pdb" nocase

            $PDB_2 = "C:\\Users\\Private\\Source\\repos\\Loader\\" nocase

            $InternalName_1 = "Loader.exe" wide nocase

            $InternalName_2 = "Config.exe" wide nocase

            $ProductName = "-Game" wide nocase

            $EncryptedShellCode_1 = "Config.bin" wide nocase

            $EncryptedShellCode_2 = "Data.bin" wide nocase

            $FileDescription = "Loader Config" wide nocase

condition:

            6 of them

}

rule ransomehub_ransome

{

meta:

            author = "M.Zohdy Group-ib"

            date = "2025-01-29"

            description = "Detect RansomeHub Ransomware"

            hash0 = "2b7a13837039f4f5ff6aeaa0b135e712"

            hash1 = "35353c1c33c6e8a9c5944ae1b1541512"

            hash2 = "7ea71f9c62e5067da16df949542148da"

            hash3 = "271c4158f9a807fd92bfe65bbd4744cf"

            hash4 = "4b194e9b87c14d1c24aa0603b5bae00f"

            hash5 = "53987a86915d63db7c70998957d5a58d"

            hash6 = "4c6616c79ef2904b238dd9ed45ac6054"

            hash7 = "389c64831dd5d409153eaf352f5537e1"

strings:

            $string0 = "extension"

            $string1 = "settings"

            $string2 = "master_public_key"

            $string3 = "remove"

            $string4 = "note_full_text"

            $string5 = "note_file_name"

condition:

            5 of them

}
```



### 3. Sigma rules


```Sigma
title: Detect RansomHub AV Killer and Ransomware

id: 9f3c2a1b-5678-4d90-abcdef-1234567890ab

status: experimental

description: Detects RansomHub ransomware and its AV killer component based on process execution, command-line arguments, and known file hashes.

author: Mahmoud Zohdy (Group-IB)

date: 2025-03-26

references:

    - https://www.group-ib.com

tags:

    - attack.defense_evasion

    - attack.t1070.004  # Indicator Removal on Host: File Deletion

    - attack.ransomware

    - attack.t1486  # Data Encrypted for Impact

logsource:

    category: process_creation

    product: windows

detection:

    selection_av_killer:

        Image|endswith:

            - "Loader.exe"

            - "Config.exe"

        CommandLine|contains:

            - "-pass"

            - "-key"

        ProductName|contains: "-Game"

        OriginalFileName|contains:

            - "Loader Config"

        PDBPath|contains:

            - "Loader.pdb"

            - "C:\\Users\\Private\\Source\\repos\\Loader\\"

        FilePath|contains:

            - "Config.bin"

            - "Data.bin"

    selection_ransomware:

        CommandLine|contains:

            - "extension"

            - "settings"

            - "master_public_key"

            - "remove"

            - "note_full_text"

            - "note_file_name"

    hash:

        sha256:

            - "c618c943840269eb753cb389029d331c"  # AV Killer Hash

            - "2b7a13837039f4f5ff6aeaa0b135e712"

            - "35353c1c33c6e8a9c5944ae1b1541512"

            - "7ea71f9c62e5067da16df949542148da"

            - "271c4158f9a807fd92bfe65bbd4744cf"

            - "4b194e9b87c14d1c24aa0603b5bae00f"

            - "53987a86915d63db7c70998957d5a58d"

            - "4c6616c79ef2904b238dd9ed45ac6054"

            - "389c64831dd5d409153eaf352f5537e1"

    condition: selection_av_killer or selection_ransomware or hash

falsepositives:

    - Legitimate software with similar filenames or configurations.

level: critical
```
## VI. Kết luận

`RansomHub` là một `ransomware-as-a-service` (RaaS) nguy hiểm nhắm vào các tổ chức doanh nghiệp. Mã độc này kết hợp kỹ thuật xâm nhập mạnh mẽ, vô hiệu hóa bảo mật, mã hóa dữ liệu và đánh cắp thông tin, gây ra hậu quả nghiêm trọng như mất dữ liệu, rò rỉ thông tin nhạy cảm và tổn thất tài chính lớn.

Các đặc điểm chính của `Ransomhub`:

- Sử dụng lỗ hổng bảo mật (`CVE-2020-1472`, `CVE-2021-42278`, `CVE-2024-3400`) để xâm nhập.

- Vô hiệu hóa `EDR`/`AV` bằng `EDRKillShifter` để tránh bị phát hiện.

- Tấn công tài khoản quản trị để leo thang đặc quyền và di chuyển bên trong hệ thống.

- Mã hóa dữ liệu và yêu cầu tiền chuộc, đồng thời đánh cắp thông tin để ép nạn nhân trả tiền.

Các cách bảo vệ hệ thống khỏi `Ransomhub Ransomware`:

- Áp dụng bản vá bảo mật mới nhất cho `Windows Server`, `Active Directory` và phần mềm bảo mật.

- Vá các lỗ hổng `CVE-2020-1472` (ZeroLogon), `CVE-2021-42278`, `CVE-2024-3400`.

- Tắt tài khoản admin không sử dụng.

- Bật `MFA` (Multi-Factor Authentication) cho tài khoản quan trọng.

- Giới hạn quyền truy cập theo nguyên tắc `Least Privilege`.

- Cài đặt `SIEM` (Security Information and Event Management) để theo dõi tiến trình đáng ngờ.

- Giám sát truy cập đến `SMB`, `RDP`, `PowerShell`, `Task Scheduler`.

- Sử dụng backup offline hoặc backup trên cloud.

- Kiểm tra xem `Ransomware` có thể xóa shadow copy không.

- Sử dụng `Sigma Rules` & `YARA Rules` để phát hiện các dấu hiệu lây nhiễm.

Nếu bị nghi ngờ nhiễm `Ransomware`:

- Cách ly ngay hệ thống bị nhiễm khỏi mạng nội bộ.

- Chặn tất cả kết nối để ngăn mã độc giao tiếp với hacker.

- Quét toàn bộ hệ thống bằng phần mềm bảo mật như `Windows Defender`, `Bitdefender`, `Malwarebytes`.

- Tìm & xóa các tệp đáng ngờ, đặc biệt trong `Startup Folder`.

- Báo cáo `IoC` cho các cơ quan an ninh mạng để hỗ trợ điều tra.