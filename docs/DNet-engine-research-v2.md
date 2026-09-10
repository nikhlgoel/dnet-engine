# **Architecture and Systems Engineering Blueprint for a Cross-Platform Network Optimization and Resilience Platform**

## **The Paradigm of Constrained Networks and Deep Packet Inspection Evasion**

The contemporary landscape of institutional networking is characterized by high-density user environments, rapid bandwidth consumption, and the deployment of sophisticated Unified Threat Management (UTM) appliances. In environments such as university campuses and corporate dormitories, the proliferation of connected devices exhausts the limited radio-frequency spectrum, leading to severe latency, jitter, and dropped connections. Concurrently, network administrators deploy enterprise-grade firewalls—such as Sophos XG, Cyberoam, and Fortinet—which implement aggressive Deep Packet Inspection (DPI), port blocking, Deep IP Network Address Translation (NAT), and active traffic shaping. These systems systematically degrade unrecognized or encrypted traffic profiles, rendering standard protocols ineffective and often paralyzing essential web navigation.

Compounding this issue is the unreliability of cellular networks. In modern infrastructure, 5G and 4G LTE connections frequently suffer from signal attenuation. The physical limitations of high-frequency microwave propagation through dense building materials result in signals dropping or failing entirely indoors. In some environments, this attenuation is exacerbated by intentional localized signal jamming deployed to enforce institutional Wi-Fi usage. Consequently, users are left with multiple degraded network interfaces—unstable, heavily filtered institutional Wi-Fi and compromised cellular data.

To resolve these systemic failures, the following engineering blueprint details the architecture for a completely autonomous, cross-platform software daemon. Designed specifically as a free, self-hosted utility that operates entirely on local system resources, this engine systematically intercepts operating system network flows, manages per-application routing, mitigates DNS pollution, obfuscates transport protocols to bypass DPI classifications, and provides seamless connection failover.

## **Platform Identity, User Experience, and Licensing Specifications**

The software must possess a cohesive structural design, branding, and user interface architecture that aligns with a lightweight, background-centric utility. The design philosophy dictates "minimal works," meaning the application must remain unobtrusive, requiring zero configuration for the average user while offering deep customization for advanced developers.

### **Application Nomenclature and Licensing**

The platform is officially designated as **DNet Engine**. The system produces two primary binaries: the background daemon (dnetd) and the system tray application (dnet-tray).

* **Licensing:** The overarching project is licensed under the **GPLv3**. This ensures the codebase remains permanently open-source.  
* **Branding Constraints:** Due to strict licensing and EULA obligations from upstream dependencies, DNet Engine is legally prohibited from using the names "sing-box", "WireGuard", or "Wintun" in its branding, marketing, or promotional materials. Attribution is strictly confined to internal engineering documentation and standard software "About" screens.

### **Frontend Architecture: The Tauri Framework**

To maintain a system-resource-friendly constraint, the graphical user interface (GUI) avoids heavy frameworks like Electron. Instead, the frontend is engineered using Tauri v2. Tauri utilizes the native operating system webview, which reduces the compiled binary size and maintains a near-zero idle RAM footprint. The UI is built using a reactive framework, such as Svelte 5\.

### **Cloud Provisioning and Endpoint Management**

*Change from original architecture:* DNet Engine will **not** host shared or centralized proxy infrastructure, as doing so violates cloud provider Terms of Service (e.g., Oracle Cloud) regarding anonymizing proxies.

Instead, the v1 application features an integrated **Provisioning Wizard**. This wizard guides users to deploy their own free-tier cloud endpoint using a scoped, revocable credential (rather than storing a permanent root API key). To prevent the deployed IP from being permanently blocklisted by UTM firewalls, the architecture incorporates multi-endpoint health-based rotation and idle-reclamation keepalives.

## **Cross-Platform Core Architecture: Supervised Orchestration**

*Change from original architecture:* Writing custom Rust implementations of complex cryptographic transports (like Hysteria 2 or AmneziaWG) introduces unacceptable supply-chain risk and development delay. Therefore, DNet Engine functions as an **orchestration layer**. The Rust daemon provisions, configures, and supervises pre-existing, battle-tested Go binaries as child processes.

> 1. **Primary Core (sing-box):** Handles Hysteria 2, VLESS+REALITY, and general routing. To maintain the strict 60 MB installer budget, this core is built from source at compile time using minimal build tags (stripping out unused protocols like plain WireGuard).  
> 2. **Secondary Core (amneziawg-go):** Runs concurrently as a supervised child process exclusively to provide AmneziaWG obfuscation, as sing-box does not natively support AmneziaWG's specific DPI-evasion parameters.

### **Virtual Network Interfaces and the Routing Loop Hazard**

The system utilizes **Wintun** for Layer 3 interception on Windows.

* *Licensing Note:* The signed, prebuilt wintun.dll is strictly bundled as a proprietary aggregate under its EULA, never compiled from source, keeping it legally compatible with our GPLv3 Rust daemon.  
* *Routing Loop Mitigation:* Because both supervised cores require a virtual adapter, there is a massive risk of a routing loop (where AmneziaWG encrypted UDP is captured by the primary core's TUN). The primary core *always* owns the capture TUN. When AmneziaWG is active, the primary core uses bind\_interface pointed at the AmneziaWG adapter, safeguarded by a strictly enforced host route bypassing the physical gateway.

### **Application-Level Split Tunneling via ETW**

*Change from original architecture:* Custom WHQL kernel drivers (like WFP callouts) are too expensive and complex for a free v1 project. Standard Windows API polling (GetExtendedTcpTable) is too racy for short-lived connections.

Instead, process-level routing is achieved heuristically via **Event Tracing for Windows (ETW)**. The daemon listens to the Microsoft-Windows-Kernel-Network provider, specifically extracting the Process Identifier (PID) directly from the TcpIpConnect payload at connect time. (Note: If ETW load testing breaches the \<1% idle CPU budget, this feature degrades to pure destination-based IP routing).

## **The FakeIP Subsystem for DNS Optimization**

Traditional Domain Name System (DNS) resolution presents two critical vulnerabilities in restricted university environments: severe latency and intentional DNS pollution.

To circumvent these issues, the architecture incorporates a FakeIP DNS subsystem using the 198.18.0.0/15 and fc00::/18 blocks. When an application attempts to resolve a domain, the daemon intercepts the query, returns a virtual FakeIP instantly, and logs the mapping.

*Handling Encrypted DNS:* Because modern browsers (Chrome, Brave) default to their own secure DNS over HTTPS (DoH)—which bypasses local FakeIP resolution—DNet Engine defaults to blocking known DoH endpoints. This forces the browser to fall back to system resolution. The UI prominently discloses this behavior on first run and provides a one-click opt-out for informed consent.

## **Transport Obfuscation: Dismantling Deep Packet Inspection**

The platform implements distinct obfuscation protocols to bypass stateful firewalls:

> 1. **AmneziaWG (via amneziawg-go):** Replaces static WireGuard headers with magic byte randomization (![][image1]), injects junk packet bursts (![][image2]), and alters payload padding to destroy the statistical packet-size distribution tracked by Machine Learning classifiers.  
> 2. **Hysteria 2 (via sing-box):** Utilizes the QUIC protocol. It employs the **Salamander** obfuscation layer (BLAKE2b-256 salted hashes XORed against the payload) and the **Gecko** layer (fragmenting long-header QUIC handshakes into 2-8 padded chunks) to render the connection completely pseudorandom.  
   * *Congestion Control:* BBR is the default. Brutal CC is made strictly *opt-in*, as forcing Brutal on a congested university Access Point degrades network quality for all other students sharing the hardware.  
> 3. **VLESS+REALITY:** Serves as the fallback transport when a network aggressively drops all UDP traffic.

## **Resiliency: Seamless Failover (v1 Scope)**

*Change from original architecture:* True packet-level aggregation (Multipath QUIC with ECF scheduling) requires months of engineering and is explicitly deferred to v2.

Version 1 focuses purely on **Seamless Failover**. If a user walks out of range of the hostel Wi-Fi, the system transitions to 5G mobile data based on two tiers:

* **Tier 1 (UDP \- AmneziaWG/Hysteria):** Guaranteed connection survival. Connections seamlessly roam to the new interface without dropping established sockets.  
* **Tier 2 (TCP \- VLESS):** Access-only. TCP fallbacks will drop active connections upon an interface switch, requiring a reconnection. The UI explicitly labels the active tier to manage user expectations.

*(Note: Multi-Segment Download Acceleration and Sparse File disk writes have been entirely deferred to post-v1 to focus strictly on network access and resiliency).*

## **Conclusion**

The DNet Engine architecture represents a highly sophisticated, self-reliant network orchestration platform. By supervising lightweight instances of sing-box and amneziawg-go, the system effectively dismantles deep packet inspection capabilities while keeping the installed footprint under 60 MB. Guided by Test-Driven Development and strict architectural gating (such as routing loop prevention), this blueprint provides a foolproof path to restoring unrestricted internet connectivity to users in highly constrained network environments.

#### **Works cited**

[image1]: <data:image/png;base64,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>

[image2]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAAaCAYAAABVX2cEAAAB2UlEQVR4Xn1UuUqDQRCeJSFIEBQlIAHF4wECgkIKC8FWsAwelU0qfQdT2Gmndj6AVhZ2Vr6CWNtZ+BD6zZ4ze/jBtzvXzszO/gkZQ2R4sTDEktWSKUNh4ARRkmafrg1VSIiVU7bNqofBhZwrBWipcVAidtuMzRyZOgdegR+w/5LjN4LuoS9wQOwjL6Ba9xF2psZebArpC9wJbn6wajKVuOjW9LE9gK/gQHs10oPmiGVpCL6Bt9B7yu+FIIpczbRj8Ac8a4c4R3FlB2WZGjEvhjjahmrXXZNf9I7svMzAGmX5oMrE/9QYYqjlvBTSq8Y8KmGy7oFuXpmrfjBZuuC63wPs92XEvDSy63q1g31m3Fd+6CP7uKL9vkz5fS2C5+ANeETcQEgIzIOP4AssW962D/kT+3EI88ErkDBDswp5G3xC0SXntRnt38QptGsII3JV32E7wd51V7BrB5xRmiE/Cjci4AJ5WSPuiGiXiiCLZYQ+Yx+FKzmEzoXVN6oN2srX4XFsBgNcGyD/fqNBQCpeTvl4nWC9hHgA+QIcG3lIt6wR88QTdu2ZMAYRIPxi12JMJrT0XycDA7StFiHg3SnKt1d0kEk6b5FF6FVjAypPGVhtpNBzn0duDvofu7ckKNt0aLQAAAAASUVORK5CYII=>