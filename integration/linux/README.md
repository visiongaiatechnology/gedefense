# GeDefense Beta v2 universal Linux integration

This adapter installs the authenticated local application, polkit privilege
boundary and transactional systemd readiness helper on systemd-based x86_64
Linux distributions. The one-click installer supports APT, DNF/YUM, pacman and
Zypper dependency resolution.

AstraeaOS remains auto-detected and may add its Gaia Cells, boot and login-gate
adapters. Other distributions use the generic host profile and never receive
AstraeaOS-specific package-database, SDDM or kernel-image assumptions.

The desktop launcher accepts only the local HTTPS origin and pins the generated
certificate public key in a dedicated Chromium application profile. It does not
disable TLS validation globally and does not modify the system trust store.
