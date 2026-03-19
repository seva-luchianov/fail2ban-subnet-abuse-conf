## Fail2ban Subnet-Abuse Setup using iptables logs

### Goal
Block abusive source networks dynamically when too many requests/events occur within a time window from the same subnet.

### Prereqs
- [fail2ban](https://github.com/fail2ban/fail2ban) installed and configured
- iptables logs piped to syslog (borrowed from [bossm8's article](https://medium.com/@bossm8/geoip-dashboards-in-grafana-from-iptables-logs-101a3b256d55) on GeoIP Grafana conf, go check it out!)
```bash
iptables -N IP_LOGGING
iptables -A IP_LOGGING -s 10.0.0.0/8,172.16.0.0/12,192.168.0.0/24,127.0.0.1/32 -j RETURN
iptables -A IP_LOGGING -m recent --rcheck --seconds 60 --name iptrack --rsource -j RETURN
iptables -A IP_LOGGING -m recent --set --name iptrack --rsource
iptables -A IP_LOGGING -j LOG --log-prefix "[iptables] "
iptables -A INPUT -j IP_LOGGING
iptables -A DOCKER-USER -j IP_LOGGING
```

This guide was written using Ubuntu 24.04 - ymmv on other distributions.

### Data Flow
1. iptables logs a packet with `[iptables] ... SRC=x.x.x.x ...`.
2. Fail2ban filter matches the line and extracts `<HOST>`.
3. Jail runs custom `actionban` script for each event.
4. Script maps IP to subnet (`/16` or `/24`), tracks count in rolling window.
5. If count >= threshold, script adds subnet to `ipset`.
6. iptables rule drops packets from subnets in that `ipset`.

## 1) Filter Configuration

```bash
cp filter.d/iptables-kernel.conf /etc/fail2ban/filter.d/iptables-kernel.conf
```

### Validate filter
```bash
fail2ban-regex /var/log/syslog /etc/fail2ban/filter.d/iptables-kernel.conf
```

If needed:
```bash
fail2ban-regex /var/log/syslog /etc/fail2ban/filter.d/iptables-kernel.conf --print-all-matched
```

## 2) Jail Configuration

```bash
cp jail.d/iptables-subnet.local /etc/fail2ban/jail.d/iptables-subnet.local
```
(You can also name it `.conf`; both are valid for custom jail files.)

Tweak the values to your liking. The default is to block an entire /16 subnet when seeing more than 100 requests within 5 minutes for the same subnet.

## 3) Custom Action Definition and supporting script

```bash
cp action.d/iptables-subnet-dynamic.conf /etc/fail2ban/action.d/iptables-subnet-dynamic.conf
cp f2b-subnet-ban.sh /usr/local/sbin/f2b-subnet-ban.sh
```

Set permissions:
```bash
chmod 750 /usr/local/sbin/f2b-subnet-ban.sh
chown root:root /usr/local/sbin/f2b-subnet-ban.sh
```

## 4) Reload and Verify

```bash
fail2ban-client reload
fail2ban-client status iptables-subnet-abuse
fail2ban-client get iptables-subnet-abuse actions
fail2ban-client get iptables-subnet-abuse action iptables-subnet-dynamic actionstart
fail2ban-client get iptables-subnet-abuse action iptables-subnet-dynamic actionban
```

## 5) Observability Commands

### Fail2ban logs
```bash
rg -n "iptables-subnet-abuse|Ban|Unban|ERROR|WARNING" /var/log/fail2ban.log
```

### Custom script logs
```bash
journalctl -t fail2ban-subnet -n 200 --no-pager
```

### ipset state
```bash
ipset list f2b_subnet_abuse
```

### iptables rule presence
```bash
iptables -S INPUT | rg f2b_subnet_abuse
```

## 6) Known/Expected Behavior

Fail2ban will still log `Ban`/`Unban` for individual IPs in jail state.
That **IS EXPECTED**! 

The `Ban`/`Unban` logs are just indicating fail2ban is detecting the IP and passing it along - no enforcement action is being taken.

- Fail2ban shows per-IP `Ban`/`Unban` in logs and jail status. This os the result of fail2ban processing IP addresses as they are picked up by `/etc/fail2ban/filter.d/iptables-kernel.conf`. These IPs are being passed along to the `/etc/fail2ban/action.d/iptables-subnet-dynamic.conf` action which will only act to actually enforce a ban when the `/usr/local/sbin/f2b-subnet-ban.sh` script itself enforces the ban by adding the IP address to ipset.
- `actionunban = true` means Fail2ban unban events do not undo subnet bans.
- Subnet bans expire by `ipset timeout` (`blocktime`).

## 7) Tuning Guidance

This config is only reasonable for low traffic homeservers with few exposed services. If you are hasting a HA service with many users this configuration will likely disrupt your firewall conf.

Consider using `/24` instead of `/16` mask for lower collateral risk.

## 8) Quick Validation Checklist

- [ ] `fail2ban-client status iptables-subnet-abuse` shows jail active.
- [ ] `/var/log/syslog` contains `[iptables] ... SRC=...`.
- [ ] `journalctl -t fail2ban-subnet` shows `START/DERIVED/COUNT`.
- [ ] `ipset list f2b_subnet_abuse` exists after jail/actionstart.
- [ ] Subnet appears in `ipset` once threshold is exceeded.
- [ ] Traffic from banned subnet is dropped by INPUT rule.
