# KubeGuard AI — Scheduled evidence transfer and local investigation

This documents the **existing, working lab installation**: Kubernetes creates firing/resolved incidents and collects fixed allowlisted Prometheus data; an Ubuntu `systemd` timer publishes **sanitized completed episodes**; a Windows scheduled task **pulls** those episodes through restricted read-only SFTP; a separate Windows task performs **local-only, bounded Ollama triage**.

Human review is always required. Neither Windows script needs Kubernetes access, and **no automatic remediation** is performed.

## Flow and schedules

1. MicroK8s incident agent + evidence collector: continuously running (30-second polling in the current lab).
2. Ubuntu `kubeguard-evidence-publisher.timer`: every 5 minutes, invokes `scripts/publish_kubeguard_evidence.py` from a **root-owned installed copy**.
3. Windows Task Scheduler `KubeGuardEvidenceSync`: every 10 minutes while the user is logged on; invokes `scripts/scheduled_sync_kubeguard.ps1`, which calls `scripts/sync_kubeguard_episodes.py`.
4. Windows Task Scheduler `KubeGuardAIAnalysis`: every 10 minutes while the user is logged on; invokes `scripts/scheduled_analyze_kubeguard.ps1`, which calls `scripts/analyze_synced_kubeguard_episodes.py`.

Windows pulls evidence over SFTP. Ubuntu does **not** push into or authenticate to Windows. The two Windows schedules are independent; analysis may precede synchronization, in which case it handles the new episode on a later run. The analyzer processes at most one new validated episode per invocation. Errors cause a nonzero task result, and a later scheduled run can retry. Previously cached episodes and reports are checked rather than overwritten.

## Ubuntu: install and verify the existing publisher timer

Prerequisites: MicroK8s works under `sudo -u root -g kubeguard-export`, and `/srv/kubeguard-sftp/evidence` is an existing protected directory. On the tested lab VM, published episodes are `root:kubeguard-export`, mode `0640`; the SFTP account has read-only access. **Do not** make the SFTP directory world-writable or give the SFTP account publisher write access.

Review repository changes **before** installing. The service executes as root, so never point `ExecStart` directly at a mutable Git working-tree file. From the Ubuntu clone of this repository:

```bash
cd ~/Projects/kubeguard-ai
sudo install -D -o root -g root -m 0755 \
  scripts/publish_kubeguard_evidence.py \
  /usr/local/libexec/kubeguard-publish-evidence.py
sudo install -o root -g root -m 0644 \
  ops/systemd/kubeguard-evidence-publisher.service \
  /etc/systemd/system/kubeguard-evidence-publisher.service
sudo install -o root -g root -m 0644 \
  ops/systemd/kubeguard-evidence-publisher.timer \
  /etc/systemd/system/kubeguard-evidence-publisher.timer
sudo systemctl daemon-reload
sudo systemctl start kubeguard-evidence-publisher.service
sudo systemctl status kubeguard-evidence-publisher.service --no-pager
sudo journalctl -u kubeguard-evidence-publisher.service -n 20 --no-pager
sudo systemctl enable --now kubeguard-evidence-publisher.timer
systemctl list-timers --all | grep kubeguard-evidence-publisher
```

The service is `Type=oneshot`: **`inactive (dead)` after successful completion is normal**. On subsequent Git updates of the publisher, review the code and reinstall the root-owned copy explicitly; `git pull` alone does not update the installed publisher.

Monitor scheduled results:

```bash
systemctl status kubeguard-evidence-publisher.timer --no-pager
sudo journalctl -u kubeguard-evidence-publisher.service --since today --no-pager
sudo find /srv/kubeguard-sftp/evidence -maxdepth 1 -type f -name 'episode_*.json' -printf '%f %u:%g %m\n'
```

Security limitation: the publisher currently uses privileged **host-side** `microk8s kubectl exec` access. The trusted, root-owned copy limits accidental source changes but does not make the publisher least-privileged Kubernetes automation. Harden this identity before production use.

## Windows: install the two wrappers and schedule them

The two PowerShell wrappers in `scripts/` are intended to be committed from the Windows development machine **after reviewing their contents**:

- `scripts/scheduled_sync_kubeguard.ps1`
- `scripts/scheduled_analyze_kubeguard.ps1`

On the tested Windows machine, the wrappers use Python 3.12 at `%LOCALAPPDATA%\Programs\Python\Python312\python.exe`, and write logs to `%LOCALAPPDATA%\KubeGuardAI\private\scheduled-sync.log` and `scheduled-analysis.log`. Change the Python path only if your installed version differs. Keep private reports, SSH keys, incident evidence, and logs **outside Git**.

Requirements:

- Normal Windows user account, logged on; tasks use **Interactive** logon and **Limited** privilege.
- An SSH key already loaded in that account's ssh-agent; pinned host key in `known_hosts`; working read-only SFTP access to the Ubuntu VM. No password is stored in the task.
- Local Ollama server running and the configured `qwen3:4b-instruct` model installed for new investigations.
- Both wrappers already tested successfully by direct PowerShell execution before scheduling.

Using **Task Scheduler → Create Task**, configure each of `KubeGuardEvidenceSync` and `KubeGuardAIAnalysis`:

- Trigger: **At log on**, repeat every **10 minutes**, indefinitely (`PT10M`, empty duration).
- General: **Run only when user is logged on**, normal Windows user, **do not** enable highest privileges.
- Settings: **Do not start a new instance** if already running; allow a missed start when possible. For analysis, a 5-minute execution limit is suitable for the current bounded local Ollama call.
- Action: Program `powershell.exe`, arguments below (adjust the checkout path if necessary).

For `KubeGuardEvidenceSync`:

```text
-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\Users\Mega-PC\Projects\kubeguard-ai\scripts\scheduled_sync_kubeguard.ps1"
```

For `KubeGuardAIAnalysis`:

```text
-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\Users\Mega-PC\Projects\kubeguard-ai\scripts\scheduled_analyze_kubeguard.ps1"
```

The paths above are specific to the tested Windows clone. To register tasks using PowerShell, an elevated **registration shell** may be necessary, but both tasks should execute under the **normal user** with `RunLevel: Limited`.

Read-only verification after task execution:

```powershell
Get-ScheduledTaskInfo -TaskName 'KubeGuardEvidenceSync' | Format-List LastRunTime, LastTaskResult
Get-ScheduledTaskInfo -TaskName 'KubeGuardAIAnalysis' | Format-List LastRunTime, LastTaskResult
(Get-ScheduledTask -TaskName 'KubeGuardEvidenceSync').Triggers[0].Repetition | Format-List Interval, Duration
(Get-ScheduledTask -TaskName 'KubeGuardAIAnalysis').Triggers[0].Repetition | Format-List Interval, Duration
Get-Content "$env:LOCALAPPDATA\KubeGuardAI\private\scheduled-sync.log" -Tail 15
Get-Content "$env:LOCALAPPDATA\KubeGuardAI\private\scheduled-analysis.log" -Tail 15
```

`LastTaskResult: 0` indicates a completed successful run; `267009` (`0x41301`) indicates still running. An empty `NextRunTime` can occur for a logon-triggered repeating task; inspect the trigger's `Repetition.Interval` rather than assuming a schedule is missing. Both scripts enforce their own lock files. Never delete a lock while its process may still be running.

## Full unattended **new-episode** validation (controlled lab only)

First check that the Ubuntu publisher timer and both Windows tasks are enabled and have successful previous runs. Check the incident agent's state has `mode: send`, `active: False`, `pending: False`. Keep the existing Ubuntu API port-forward on localhost port 18080, and ensure the Windows session, ssh-agent, SFTP and local Ollama are available.

Record the Windows baseline (PowerShell):

```powershell
$private = Join-Path $env:LOCALAPPDATA 'KubeGuardAI\private'
Get-ChildItem "$private\synced\episodes" -Filter 'episode_*.json' | Select-Object Name
Get-ChildItem "$private\reports" -Filter 'investigation_*.json' | Select-Object Name
```

On Ubuntu, from the repository root, deliberately generate the existing **laboratory** high-latency scenario and then healthy recovery traffic. Do not run overlapping traffic experiments. Keep the API port-forward open in a separate terminal:

```bash
microk8s kubectl -n kubeguard port-forward svc/kubeguard-api 18080:8000
```

In another terminal, from the repository root:

```bash
python3 scripts/generate_milestone4_traffic.py --scenario latency --duration-sec 180 --rps 1 --max-in-flight 4 --output data/milestone4/automation_latency.csv
python3 scripts/generate_milestone4_traffic.py --scenario normal --duration-sec 480 --rps 1 --max-in-flight 4 --output data/milestone4/automation_recovery.csv
```

Check without manually publishing/syncing/analyzing:

```bash
microk8s kubectl -n monitoring logs deployment/kubeguard-incident-agent -c agent --tail=50
microk8s kubectl -n monitoring logs deployment/kubeguard-evidence-collector -c collector --tail=30
sudo journalctl -u kubeguard-evidence-publisher.service -n 40 --no-pager
sudo find /srv/kubeguard-sftp/evidence -maxdepth 1 -type f -name 'episode_*.json' -printf '%f %u:%g %m\n'
```

Expect a **new** `firing` and matching `resolved` event published by the incident agent, collector evidence, and the systemd timer's new `published: episode_...` line. On Windows, inspect the **scheduled** sync/analysis logs and compare file lists against baseline. Expect a new `Downloaded and validated:` line, a new `Analyzed:` line, and a new matching `investigation_*.json` in the private reports directory. `LastTaskResult: 0` for each scheduled task confirms success. The exact timing depends on asynchronous polling, schedule alignment, and local availability. Do **not** run either Windows Python script manually during this validation, because that would not demonstrate scheduling.

The lab's intentionally delayed endpoint is an operator-known cause; the aggregate evidence sent to the AI does not contain the experiment setting, so the model must not assert it as a confirmed root cause. Report suggestions always require human review.

## Limits and rollback

- Windows is scheduled **only while the user is logged on**; the SSH agent, Ubuntu VM/network and Ollama must be available. Windows will catch up later if it was offline, within the scripts' strict queue limits.
- SFTP sync discovers at most **100** published episodes and downloads at most **10** new files per execution. The model analyzes at most **one** new validated episode per execution. The Ubuntu publisher and collector also enforce bounded file counts and will fail closed if their limits are exceeded; monitor the journal/logs and plan archival/retention deliberately, without silently deleting evidence.
- Disable the Ubuntu publisher schedule without deleting evidence:

```bash
sudo systemctl disable --now kubeguard-evidence-publisher.timer
```

- Disable the Windows schedules without deleting evidence or reports:

```powershell
Disable-ScheduledTask -TaskName 'KubeGuardEvidenceSync'
Disable-ScheduledTask -TaskName 'KubeGuardAIAnalysis'
```

Never commit the contents of `%LOCALAPPDATA%\KubeGuardAI\private`, SFTP private keys, raw evidence collector PVC files, or credentials. Logs and reports remain local.
