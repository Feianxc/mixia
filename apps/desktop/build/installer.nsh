; 安装后的两件事：收紧安装目录权限；注册浏览器扩展的 native messaging host。

!macro customInstall
  ; 装到自定义目录（比如 D:\TOOL）时会继承盘根的权限，“已验证用户”能修改，
  ; 任何登录用户的程序都能替换 Mixia.exe、app.asar 和 mixia-nmhost.exe。
  ; 这里改成和 Program Files 一样：管理员和 SYSTEM 可写，其他人只读。
  ; 用 SID 不用组名，中文系统的组名是本地化的。
  ; 544 管理员，18 SYSTEM，545 用户，15-2-1 / 15-2-2 应用容器（和 Program Files 一样给读）。
  Push $0
  Push $1
  ; 只收紧我们自己的文件夹。向导只在路径完全不含 Mixia 时才补 \Mixia，
  ; 选了 D:\MixiaStuff 这种放着别的软件的目录时，改所有者会连带改掉别人的文件
  StrCpy $0 "$INSTDIR" "" -6
  StrCmp $0 "\Mixia" mixia_acl_own
    MessageBox MB_ICONINFORMATION|MB_OK "安装目录不是单独的 Mixia 文件夹，没有改动它的权限。其他程序可能改写密匣的程序文件，建议安装到默认位置。" /SD IDOK
    Goto mixia_acl_done
  mixia_acl_own:
    ; 先把所有者改成管理员组：目录如果是用户事先建好的，所有者是用户本人，
    ; Windows 默认让所有者能改权限，普通进程就能先把权限改回去再替换文件（实测过）
    nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$INSTDIR" /setowner *S-1-5-32-544 /T /C /Q'
    Pop $0
    nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$INSTDIR" /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX *S-1-15-2-1:(OI)(CI)RX *S-1-15-2-2:(OI)(CI)RX /C /Q'
    Pop $1
    StrCmp "$0$1" "00" mixia_acl_done
      MessageBox MB_ICONEXCLAMATION|MB_OK "没能收紧安装目录的权限（错误 $0 / $1）。其他程序可能改写密匣的程序文件，建议安装到默认位置。" /SD IDOK
  mixia_acl_done:
  Pop $1
  Pop $0

  ; 清单和程序都在安装目录里，allowed_origins 钉死扩展 ID。按机器安装，写 HKLM
  SetRegView 64
  WriteRegStr HKLM "SOFTWARE\Google\Chrome\NativeMessagingHosts\online.feian.mixia" "" "$INSTDIR\resources\online.feian.mixia.json"
  WriteRegStr HKLM "SOFTWARE\Microsoft\Edge\NativeMessagingHosts\online.feian.mixia" "" "$INSTDIR\resources\online.feian.mixia.json"
  SetRegView lastused
!macroend

!macro customUnInstall
  SetRegView 64
  DeleteRegKey HKLM "SOFTWARE\Google\Chrome\NativeMessagingHosts\online.feian.mixia"
  DeleteRegKey HKLM "SOFTWARE\Microsoft\Edge\NativeMessagingHosts\online.feian.mixia"
  SetRegView lastused
!macroend
