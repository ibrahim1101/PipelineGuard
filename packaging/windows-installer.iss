[Setup]
AppId=PipelineGuard.Desktop
AppName=PipelineGuard
AppVersion=1.0.0-dev
DefaultDirName={localappdata}\Programs\PipelineGuard
DefaultGroupName=PipelineGuard
PrivilegesRequired=lowest
OutputDir=..\dist\installer
OutputBaseFilename=PipelineGuard-Setup-dev
Compression=lzma2
SolidCompression=yes
UninstallDisplayIcon={app}\PipelineGuard.exe

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "..\dist\PipelineGuard\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\PipelineGuard"; Filename: "{app}\PipelineGuard.exe"
Name: "{autodesktop}\PipelineGuard"; Filename: "{app}\PipelineGuard.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\PipelineGuard.exe"; Description: "Launch PipelineGuard"; Flags: nowait postinstall skipifsilent
