# Closed preview: how to try it, and how the owner adds a friend

This is for the first small group (the owner and three or four friends), before any public release. It is honest about
what is and is not finished: read [Read this before relying on it](../README.md#read-this-before-relying-on-it) first.

## For a friend

You need Windows 10 (version 1809 or later) or Windows 11, 64-bit, and an administrator account (the installer asks once).

1. **Install.** Download the installer from the project's GitHub *Releases* page (the newest one marked *pre-release*).
   It is **not signed yet**, so Windows shows "Windows protected your PC": choose **More info**, then **Run anyway**. That
   is expected for this preview and for nothing else you download.
2. **Open DNet Engine** from the Start menu. The first time it asks you to read and accept what it is for.
3. **Ask the owner to let your computer in.** In the window: **Servers**, then **Join a friend's server**. Give your
   computer a name, press **Make my request**, and send the text it shows (it starts with `DNET-DEVICE-REQUEST`) to the
   owner. It holds only a name and a *public* key, so any chat app will do. Keep the window open (or come back within
   about 15 minutes), because the matching key waits inside it.
4. **Paste the invite the owner sends back** (it starts with `DNET-INVITE-1:`) into the same page and press **Add the
   server**. Windows asks you to approve it in a second window: that is on purpose, because it sends your traffic
   somewhere new.
5. **Turn it on** with the switch on **Status**. Everyone on the server shares its speed.

**Please tell the owner:** what you were doing when something went wrong, what the window said (it shows the service's
words in full), and your Windows version. `dnetctl events` in a terminal prints the recent history; do not send the
invite itself or screenshots of it.

**What speed to expect (measured on a real network, 2026-11-16):** on a network where the UDP method (Hysteria 2) works, the
full speed of your line (the server is not the limit). On a network that blocks UDP (a mobile hotspot on Jio was one) only the
TCP method works and it gave about **10 Mbit/s** and struggled with many downloads at once, although the line gives 180. That is a known
problem we are working on (T210), not something you did. Tell the owner which network you were on.

**Do not rely on it for:**
- **Exams and other supervised software.** Proctoring and lockdown programs commonly refuse to run next to a VPN, or
  react to one. Turn DNet Engine off (the switch on Status) before you start one. This program does not hide itself from
  anything, and will not.
- **Anything where a leak would hurt you.** The kill switch is optional, off by default, and has known gaps (IPv6 and
  non-TCP traffic that was already open when you connected). The README lists them.

## For the owner

**Your own computer.** The server's credentials for your own computer are in
`Documents\DNet server (keep private)\fast-credentials.json` (the fast server) and `oracle-credentials.json` (the older
free one). In an *administrator* PowerShell:

```powershell
& 'C:\Program Files\DNet Engine\dnetctl.exe' add-endpoint "Fast server" --host 130.210.108.141 --credentials-file "$HOME\Documents\DNet server (keep private)\fast-credentials.json"
```

then approve it in the window that opens (it holds your server's keys, so Windows asks first). The file is your own
copy: keep it. Do **not** send it to anyone: it holds your keys. Friends get their own invites.

**Adding a friend** (from the repository folder, on your computer; needs your SSH key and Rust, which you have):

```powershell
.\testing\server-lab\Add-Friend.ps1 -Add -Request .\asha.txt -Label "Owner's server"   # the request they sent, saved as a file
.\testing\server-lab\Add-Friend.ps1 -List                                              # who is on the server
.\testing\server-lab\Add-Friend.ps1 -Remove -Request .\asha.txt                        # take them off again
```

`-Add` writes the invite to `Documents\DNet invites\`. Send that one file to that one friend. It never prints the
invite, it holds your server's access details (not your keys, not theirs), and a removed friend stops working at once
without touching anyone else. The server holds at most 8 devices, yours included.

**What the servers are.** Both are Oracle Cloud machines in Mumbai.

| | Address | What | Speed |
|---|---|---|---|
| **Fast** | `130.210.108.141` | A paid-size machine (2 cores, E5 Flex) on your **free-trial credits** | Oracle rates it 2 Gbit/s; measured from the machine itself, 1.6 to 2.4 Gbit/s |
| **Free micro** | `130.210.116.219` | The Always Free machine | Capped by Oracle at about **50 Mbit/s**, shared by everyone on it |

The cap on the free micro is Oracle's, not this program's, and no setting removes it. The fast one costs trial credit
every hour it exists (a few cents), and the credit lasts about 30 days from when the account was made; when it runs
out the machine goes with it, so the long-term plan is the **free Arm shape** (1 Gbit/s per core, free), which had no
capacity in Mumbai on 2026-11-15. Upgrading the account to Pay-As-You-Go (still free inside the free limits) makes that
capacity much easier to get.

- **Idle machines are reclaimed.** On the free micro, Oracle's rule is about a *week* of low use (the 95th-percentile
  CPU under about 20%), not minutes. It runs a small keepalive (four minutes of idle-priority work every forty, no
  network, nothing written), installed and checked on 2026-11-15. The fast machine is not an Always Free one and is not
  reclaimed for idleness while the trial lasts.
- **Data:** Oracle gives 10 TB a month of outbound transfer free; a few people cannot reach it.
- **Speed you will see** is the smaller of your own line, the server's, and the distance to Mumbai. Everyone on a
  server shares it.
