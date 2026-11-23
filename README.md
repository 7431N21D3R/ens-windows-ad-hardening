# 🛡️ Bastionado Windows / Active Directory · Checklist alineado con ENS

> Checklist de bastionado para entornos Windows y Active Directory, construido desde los ataques que más se repiten en pentests internos y mapeado a las medidas del **Esquema Nacional de Seguridad (RD 311/2022)**.

⚠️ Pruébalo siempre en preproducción. La referencia oficial son las guías **CCN-STIC** (serie 500/800) y la categoría del sistema (básica, media o alta).

---

## 🔑 Identidades y privilegios

| ✔ | Control | Ataque que mitiga | ENS |
|---|---|---|---|
| ☐ | Modelo de administración por niveles (*tiering*): las cuentas Tier 0 solo inician sesión en DC y PAW | Robo de credenciales y movimiento lateral | op.acc.3 · op.acc.4 |
| ☐ | **Windows LAPS** para contraseñas únicas de administrador local | Reutilización de contraseñas (*pass-the-hash*) | op.acc.6 |
| ☐ | Cuentas privilegiadas en **Protected Users** y marcadas como *sensitive* | Delegación y caché de credenciales | op.acc.4 |
| ☐ | **gMSA** o contraseñas largas (25+ caracteres) para cuentas de servicio con SPN | Kerberoasting | op.acc.6 |
| ☐ | Ninguna cuenta con *"no requiere preautenticación Kerberos"* | AS-REP Roasting | op.acc.6 |
| ☐ | Revisión de **delegación no restringida** y de ACL peligrosas (BloodHound) | Escalada de privilegios en AD | op.acc.4 |
| ☐ | Rotación periódica de **krbtgt** (dos veces, con intervalo) | Golden Ticket | op.exp.10 |
| ☐ | **MFA** para acceso administrativo y remoto | Uso de credenciales robadas | op.acc.6 |

## 🧠 Protección de credenciales

| ✔ | Control | Ataque que mitiga | ENS |
|---|---|---|---|
| ☐ | **LSA Protection** (`RunAsPPL`) | Volcado de LSASS | op.exp.2 |
| ☐ | **Credential Guard** en equipos compatibles | Robo de hashes y tickets | op.exp.2 |
| ☐ | WDigest desactivado | Credenciales en claro en memoria | op.exp.2 |

## 🌐 Protocolos y red

| ✔ | Control | Ataque que mitiga | ENS |
|---|---|---|---|
| ☐ | **LLMNR**, **NBT-NS** y WPAD desactivados | Envenenamiento y captura de hashes | mp.com.1 |
| ☐ | **Firma SMB** obligatoria y **SMBv1** eliminado | NTLM relay | mp.com.1 |
| ☐ | **Firma LDAP** y *channel binding* | Relay hacia LDAP | mp.com.1 |
| ☐ | Restringir **NTLM** (eliminar NTLMv1/LM) | Downgrade y cracking | mp.com.1 |
| ☐ | **Print Spooler** desactivado en controladores de dominio | Coerción de autenticación | op.exp.2 |
| ☐ | Revisión de plantillas de **AD CS** (ESC1–ESC8) | Escalada vía certificados | op.exp.2 |
| ☐ | Segmentación de red y servidores de salto | Movimiento lateral | mp.com.4 |

## 🧱 Endpoints y software

| ✔ | Control | Ataque que mitiga | ENS |
|---|---|---|---|
| ☐ | Parches al día con ventanas definidas para servidores críticos | Explotación de vulnerabilidades conocidas | op.exp.4 |
| ☐ | Reglas **ASR** de Microsoft Defender | Ejecución inicial y abuso de Office | op.exp.6 |
| ☐ | **WDAC** o AppLocker en servidores y PAW | Ejecución de binarios no autorizados | op.exp.2 |
| ☐ | Macros de Office bloqueadas desde Internet | Phishing con macros | op.exp.6 |

## 📜 Registro y detección

| ✔ | Control | Qué aporta | ENS |
|---|---|---|---|
| ☐ | Política de auditoría avanzada (inicio de sesión, Kerberos, cambios en grupos) | Trazabilidad de accesos | op.exp.8 |
| ☐ | **PowerShell** Script Block y Module Logging | Visibilidad del uso de PowerShell | op.exp.8 |
| ☐ | **Sysmon** con una configuración mantenida | Telemetría de procesos y red | op.mon.1 |
| ☐ | Envío centralizado a SIEM y retención definida | Detección y forense | op.mon.1 · op.exp.8 |

---

## 🔍 Comprobaciones rápidas (solo lectura)

```powershell
# SMBv1 y firma SMB
Get-SmbServerConfiguration | Select EnableSMB1Protocol, RequireSecuritySignature

# LSA Protection
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue

# LLMNR desactivado por GPO (EnableMulticast = 0)
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue

# Cuentas de usuario con SPN (candidatas a Kerberoasting)
Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName, PasswordLastSet |
  Select SamAccountName, PasswordLastSet

# Cuentas sin preautenticación Kerberos
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Select SamAccountName

# Equipos con delegación no restringida (excluye DC)
Get-ADComputer -Filter {TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516} | Select Name

# Última rotación de krbtgt
Get-ADUser krbtgt -Properties PasswordLastSet | Select PasswordLastSet
```

---

## 🔗 Referencias

- [Real Decreto 311/2022 — Esquema Nacional de Seguridad](https://www.boe.es/eli/es/rd/2022/05/03/311)
- [CCN-CERT — Guías CCN-STIC](https://www.ccn-cert.cni.es/es/guias.html)
- [MITRE ATT&CK — Enterprise](https://attack.mitre.org/matrices/enterprise/)

---

📝 Licencia: CC BY 4.0
