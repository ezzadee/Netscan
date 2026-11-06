# NetSentry

An Android app that checks your phone, your Wi-Fi connection, nearby Wi-Fi networks, the cell towers around you, and every installed app for security problems. It also logs which servers each app contacts. Everything runs on the phone. Nothing is sent anywhere.

The app has three tabs: **Scan** (phone, Wi-Fi and cellular), **Apps** (what each installed app can do and who it's built to talk to), and **Monitor** (the servers apps actually contact, live).

Needs Android 10 or newer.

## What it checks

| Area | Checks |
|---|---|
| This phone | Security patch age, screen lock, storage encryption, root, USB debugging and developer options, apps installed outside an app store, Private DNS, VPN |
| Current Wi-Fi | Encryption type (Open / WEP / WPA / WPA2 / WPA3), WPS, weak TKIP cipher, captive portal, failed internet check, a new access point showing up for a network you've used before |
| Nearby Wi-Fi | **Evil twins** (one network name broadcast both secured and open), networks that were secured in earlier scans but are open now, open and WEP networks nearby |
| Cellular | **2G downgrade** (the main fake-tower trick), unexpected 3G, tower country code that doesn't match your SIM, a known tower whose area code changed, a new and unusually strong tower, a serving tower that reports no ID or no neighbors |

| Apps tab | For every installed app: where it was installed from, sensitive permissions it has been granted, powerful access (Accessibility, notification reading, device admin), **tracking and ad SDKs** in its code (60 known SDKs, such as AppsFlyer, Facebook, AdMob and AppLovin), and **every server address written into its code**, with known tracker servers tagged |
| Monitor tab | A live log of **every server each app looks up**, grouped by app, with tracker and ad companies tagged. You can share the log as a CSV |

The tower and Wi-Fi history checks compare against earlier scans. They get more useful after a few days of scanning at home, at work, and on your commute.

## Build and install, option A: GitHub (no software to install)

1. Sign in at github.com and click **New repository**. Name it `NetSentry`, set it to **Private**, and click **Create repository**.
2. On the new repo page, click **uploading an existing file**. Unzip `NetSentry.zip` on your computer and drag **everything inside the `NetSentry` folder** into the browser, including the hidden `.github` folder. (On Mac, press Cmd+Shift+. in Finder to show hidden folders. On Windows: View > Show > Hidden items.) Click **Commit changes**.
3. Click the **Actions** tab. A "Build APK" run starts on its own and takes about 5 minutes.
4. When it shows a green check, click the run. Under **Artifacts**, download **NetSentry-debug-apk**. It downloads as a zip; unzip it to get `app-debug.apk`.
5. Get the APK onto your phone: email it to yourself, or put it in Google Drive and open it from the phone.
6. Tap the APK on the phone. If Android asks, allow your browser or Files app to **install unknown apps**, then tap **Install**.
7. If Play Protect warns about an unrecognized app, tap **More details > Install anyway**. That warning shows up for any app you build yourself.

## Build and install, option B: Android Studio

1. Install Android Studio from developer.android.com/studio.
2. **File > Open** and choose the `NetSentry` folder. Wait for the Gradle sync to finish (the first sync downloads a lot).
3. On the phone, go to **Settings > About phone** and tap **Build number** 7 times. Then go to **Settings > System > Developer options** and turn on **USB debugging**.
4. Plug the phone in, accept the prompt on the phone, pick it in the device dropdown, and click **Run** ▶.
5. Turn USB debugging back off when you're done. The app will flag it if you leave it on.

## First run

1. Tap **Scan**. Allow **Location** (choose *While using the app*), **Phone**, and **Nearby devices**. Android only gives apps Wi-Fi and tower lists when these are granted.
2. Keep Location turned on while you scan.
3. Android allows 4 Wi-Fi scans every 2 minutes. If you scan more often than that, you get the previous results.

## Using the Apps tab

1. Open **Apps** and tap **Scan apps**. The first scan reads every app's code and can take a few minutes. Later scans only re-read apps that changed.
2. **Review** shows apps worth a look: sideloaded apps, apps with powerful access, and apps with many trackers. **Trackers** sorts apps by tracker count.
3. Tap an app to see the details. **Open app settings** takes you to that app's page, where you can remove permissions or uninstall it.

"Servers built into its code" shows what an app is *able* to contact. To see what it *actually* contacts, use the Monitor.

## Using the Monitor tab

1. Open **Monitor** and tap **Start monitoring**. Android shows a one-time VPN permission prompt. Tap **OK**.
2. A key icon appears in the status bar. Use your phone normally, and open the apps you want to check.
3. Come back to **Monitor** to see the servers each app looked up. **By app** lists every app's servers, **Trackers** groups lookups by tracking company, and **Recent** is the raw log.
4. Tap **Stop monitoring** when you're done. The log is kept until you tap **Clear log**.

How it works: the monitor is a VPN that exists only on the phone and only handles DNS lookups (the step where an app turns a name like `graph.facebook.com` into an address). It notes which app asked, passes the lookup to your normal DNS server, and returns the answer. All other traffic goes out exactly as before.

Before you start:
- If **Private DNS** is set to a hostname (Settings > Network & internet > Private DNS), switch it to **Automatic** while monitoring. Otherwise Android sends lookups encrypted straight past the monitor. The Monitor tab warns you when this applies.
- Only one VPN can run at a time. Starting the monitor pauses any other VPN you use.

## Limits

- A phone app can't prove a tower or hotspot is fake. These are warning signs. For real cell-site-simulator detection, look at EFF's Rayhunter, which runs on a dedicated mobile hotspot.
- Android doesn't let regular apps see cipher or encryption details on the cellular link. Pixel and some Samsung phones on Android 15+ have built-in alerts for this (the app points you to the setting).
- It doesn't scan other apps for malware. Keep Google Play Protect turned on for that.
- The monitor sees lookups, not raw connections. It misses apps that use their own encrypted DNS (Chrome with "Use secure DNS" on, Firefox) and connections made straight to a hard-coded IP address. Most apps don't do either.
- Some phones may credit every lookup to "Android system" instead of the real app. If you see this, tell me which phone and Android version you have.
- Apps that hide their code (packed or heavily obfuscated) can show few or no servers and trackers in the Apps tab. Use the Monitor for those.

## Project layout

```
app/src/main/java/com/netsentry/app/
  MainActivity.kt        UI (Jetpack Compose) and permission requests
  ScanViewModel.kt       runs the three scanners and builds the report
  scan/DeviceScanner.kt  phone configuration checks
  scan/WifiScanner.kt    Wi-Fi connection and nearby network checks
  scan/CellScanner.kt    cell tower checks
  scan/Baseline.kt       on-device history of networks and towers
  scan/Model.kt          data types and severity scoring
  apps/AppInventory.kt   per-app permissions, special access, risk rating
  apps/DexScanner.kt     reads app code for tracker SDKs and server addresses
  apps/Trackers.kt       tracker SDK and tracker domain lists
  monitor/DnsMonitorService.kt  local DNS-only VPN
  monitor/DnsPacket.kt   DNS packet parsing and building
  monitor/MonitorRepository.kt  connection log storage
  ui/                    Scan, Apps and Monitor screens
```

Scoring: start at 100, subtract 25 per High, 10 per Medium, and 4 per Low finding.
