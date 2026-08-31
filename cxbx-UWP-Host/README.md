# Cxbx-Reloaded UWP Host

Este é o host UWP final do `cxbxr-emu.dll`. O projeto de referência Cemu/QEMU
não é uma dependência.

## Responsabilidades do host

- Carregar `cxbxr-emu.dll` com `LoadPackagedLibrary` e resolver a ABI
  `CxbxEmbed_*` v4.
- Manter a thread XAML livre enquanto o núcleo inicializa e executa.
- Fornecer o dispositivo, contexto, backbuffer e apresentação D3D11 do
  `SwapChainPanel`.
- Selecionar o XBE por `FileOpenPicker`, preservar a permissão na
  `FutureAccessList` e expor o arquivo somente por handles/callbacks brokered.
- Encaminhar logs, erros, estados e prompts; o log persistente fica em
  `ApplicationData/LocalFolder/cxbx-host.log`.
- Encerrar e destruir a instância antes de permitir outro início.

## Build x64 Release

Primeiro gere o núcleo em `build-uwp-x64-release/bin/cxbxr-emu.dll`. Depois:

```powershell
cmd /d /c 'call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 store >nul && msbuild cxbx-UWP-Host\cxbx-UWP-Host.vcxproj /m:1 /t:Build /p:Configuration=Release /p:Platform=x64 /p:AppxBundle=Never'
```

O MSIX assinado é escrito em `AppPackages/cxbx-UWP-Host/` e já contém
`cxbxr-emu.dll`.

## Backend de CPU

O host e o núcleo procuram `qemu-cxbx-i386.dll` no pacote. Quando esse backend
existir em `build-uwp-x64-release/bin`, o projeto o inclui automaticamente.
Enquanto ele não existir, a DLL carregará normalmente, mas o lançamento do
guest terminará com o erro controlado informado pelo callback do núcleo.
