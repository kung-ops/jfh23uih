# OldWeb

An iPhone app that opens the OldWeb gateway on your PC. It always connects on **port 8106**.

## Folders

| Folder / file | What it is |
|---|---|
| `OldWeb/` | The iPhone app (Swift). It is a full-screen web view that opens `http://oldweb.local:8106` |
| `project.yml` | The Xcode project setup. Codemagic turns it into `OldWeb.xcodeproj` during the build |
| `codemagic.yaml` | Codemagic build. It makes an **unsigned** `OldWeb.ipa` |
| `pc-server/` | The PC side: `server.js` (port 8106 only), `start.bat`, `package.json` |

## Build the IPA in Codemagic

1. Go to codemagic.io → **Add application** → GitHub → pick this repo.
2. Choose **codemagic.yaml** as the configuration (not the Workflow Editor).
3. Press **Start new build** → workflow **OldWeb iOS (unsigned IPA)**.
4. When it is done, download **OldWeb.ipa** from the build's Artifacts.

Every push to GitHub also starts a new build.

The IPA is **not signed**. To install it, use TrollStore or a jailbroken iPhone, or sign it with your own Apple ID in Sideloadly or AltStore.
Minimum iOS is 12 (Xcode can't build apps for iOS 6 or older).

## Use it

1. On the PC: double-click `pc-server/start.bat` (the first run installs packages).
2. On the iPhone: open **OldWeb**. On the same Wi-Fi or hotspot it finds the PC by itself (`oldweb.local:8106`).
3. If it can't find the PC, tap **Change address** and type the PC's IP (for example `192.168.1.20`). You don't need to type the port; the app adds `:8106` itself.
4. To change the address later, **hold three fingers on the screen for 1 second**.
