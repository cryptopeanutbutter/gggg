; Inno Setup script for WHOIS Watching optional installer builds
#define AppVersion GetStringDef("AppVersion", "1.0.0")
#define AppBuild GetStringDef("AppBuild", "000000000000")
#define SourceDir GetStringDef("SourceDir", "")
#define OutputDir GetStringDef("OutputDir", "compiled")

[Setup]
AppId={{B6F64F9E-7B59-4A1F-A028-6E7348E55E4B}}
AppName=WHOIS Watching
AppVersion={#AppVersion}
AppVerName=WHOIS Watching {#AppVersion}
AppPublisher=WHOIS Watching Project
DefaultDirName={localappdata}\Programs\WHOIS Watching
DefaultGroupName=WHOIS Watching
DisableDirPage=no
DisableProgramGroupPage=no
OutputDir={#OutputDir}
OutputBaseFilename=WHOIS_Watching_Setup_{#AppVersion}_{#AppBuild}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\WHOIS Watching"; Filename: "{app}\WHOIS_Watching.exe"
Name: "{userdesktop}\WHOIS Watching"; Filename: "{app}\WHOIS_Watching.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\WHOIS_Watching.exe"; Description: "Launch WHOIS Watching"; Flags: nowait postinstall skipifsilent

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\WHOIS_Watching"; ValueType: string; ValueName: "DisplayName"; ValueData: "WHOIS Watching"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\WHOIS_Watching"; ValueType: string; ValueName: "DisplayVersion"; ValueData: "{#AppVersion}"
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\WHOIS_Watching"; ValueType: string; ValueName: "Publisher"; ValueData: "WHOIS Watching Project"
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\WHOIS_Watching"; ValueType: string; ValueName: "InstallLocation"; ValueData: "{app}"
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\WHOIS_Watching"; ValueType: string; ValueName: "DisplayIcon"; ValueData: "{app}\WHOIS_Watching.exe"
