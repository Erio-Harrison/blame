#!/usr/bin/env python3
"""What the threads of some processes waited for a CPU, counted without blame:
a bpftrace script on the scheduler's tracepoints, and the sums it prints.

    cpu_wait_oracle.py script PID...   the bpftrace script, on stdout
    cpu_wait_oracle.py sum FILE        its output as `pid=N name=ns ...` lines

For every wait of a thread (from the wakeup, from its start for a new thread,
or from being switched out while runnable, to running) the script notes, for the CPU the thread was queued on,
moving with it when it is moved:

    own    what threads of the same process ran there meanwhile
    idle   what that CPU was idle
    limit  what the queue of the thread's control group there was throttled
           with threads in it, by the kernel's own count (6.6 on)

and splits the wait by blame's rule: own first; then the limit; then what the
CPU was idle beyond the limit; the rest is the others'. `seen_idle` is all the
CPU was idle, `limited_idle` that of waits with a limit in them, and
`limited_rest` what of those waits is neither own nor the limit: the most that
the rule can have put on the wrong side between idle and others, since within
a wait it does not know when the CPU was idle.

Fields are read at offsets taken from the running kernel's type information
(bpftool): bpftrace 0.20 aborts on any access to a field of task_struct.
"""
import collections
import json
import re
import subprocess
import sys


def offsets():
    types = json.loads(subprocess.run(["bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "-j"],
                                      check=True, capture_output=True).stdout)["types"]

    def at(struct, field):
        for t in types:
            if t["kind"] == "STRUCT" and t.get("name") == struct:
                for m in t.get("members", []):
                    if m["name"] == field:
                        return m["bits_offset"] // 8
        raise SystemExit(f"this kernel has no {struct}.{field}: no oracle")

    return dict(
        pid=at("task_struct", "pid"), tgid=at("task_struct", "tgid"),
        cpu=at("task_struct", "thread_info") + at("thread_info", "cpu"),
        queue=at("task_struct", "se") + at("sched_entity", "cfs_rq"),
        group=at("task_struct", "sched_task_group"), queues=at("task_group", "cfs_rq"),
        rq=at("cfs_rq", "rq"), since=at("cfs_rq", "throttled_clock_self"),
        total=at("cfs_rq", "throttled_clock_self_time"), clock=at("rq", "clock"))


def script(pids):
    o = offsets()
    tg = lambda p: f"(uint64)*(uint32 *)({p} + {o['tgid']})"
    pid = lambda p: f"(uint64)*(uint32 *)({p} + {o['pid']})"
    traced = lambda v: "(" + " || ".join(f"{v} == {p}" for p in pids) + ")"
    # What the CPU $x has been idle ($i) and has run of the process $tg ($o) up to $now,
    # and what the queue $q there has been throttled ($l).
    now = f"""
    $run = $now - @t[$x];
    $i = @idle[$x]; if (@curidle[$x] == 1) {{ $i = $i + $run; }}
    $o = @ran[$x, $tg]; if (@curtg[$x] == $tg && @curidle[$x] == 0) {{ $o = $o + $run; }}
    $l = *(uint64 *)($q + {o['total']});
    $since = *(uint64 *)($q + {o['since']});
    if ($since != 0 && @off[$x] != 0 && $now - @off[$x] > $since) {{ $l = $l + ($now - @off[$x] - $since); }}
"""
    start = now + """
    @i0[$tid] = $i; @o0[$tid] = $o; @l0[$tid] = $l; @on[$tid] = $x;
"""
    settle = "    $x = @on[$tid];" + now + """
    @ai[$tid] = @ai[$tid] + ($i - @i0[$tid]);
    @ao[$tid] = @ao[$tid] + ($o - @o0[$tid]);
    if ($l > @l0[$tid]) { @al[$tid] = @al[$tid] + ($l - @l0[$tid]); }
"""
    return f"""
BEGIN {{ printf("ready\\n"); }}
rawtracepoint:sched_switch {{
  $now = nsecs; $c = (uint64)cpu;
  $prev = arg1; $next = arg2;
  $ptg = {tg('$prev')}; $ppid = {pid('$prev')};
  $ntg = {tg('$next')}; $npid = {pid('$next')};
  $last = @t[$c];
  if ($last != 0) {{
    if ($ppid == 0) {{ @idle[$c] = @idle[$c] + ($now - $last); }}
    else {{ if {traced('$ptg')} {{ @ran[$c, $ptg] = @ran[$c, $ptg] + ($now - $last); }} }}
  }}
  @t[$c] = $now;
  @curidle[$c] = (uint64)0; if ($npid == 0) {{ @curidle[$c] = 1; }}
  @curtg[$c] = $ntg;
  $pq = *(uint64 *)($prev + {o['queue']});
  @off[$c] = $now - *(uint64 *)(*(uint64 *)($pq + {o['rq']}) + {o['clock']});

  if ({traced('$ptg')} && arg3 == 0 && $ppid != 0 && @b[$ppid] == 0) {{
    $tid = $ppid; $tg = $ptg; $x = $c; $q = $pq;
    @b[$tid] = $now; @ai[$tid] = (uint64)0; @ao[$tid] = (uint64)0; @al[$tid] = (uint64)0;
    {start}
  }}
  if ({traced('$ntg')} && @b[$npid] != 0) {{
    $tid = $npid; $tg = $ntg; $q = *(uint64 *)($next + {o['queue']});
    {settle}
    $w = $now - @b[$tid];
    $own = @ao[$tid]; if ($own > $w) {{ $own = $w; }}
    $limit = @al[$tid]; if ($limit > $w - $own) {{ $limit = $w - $own; }}
    $rest = $w - $own - $limit;
    $free = (uint64)0; if (@ai[$tid] > $limit) {{ $free = @ai[$tid] - $limit; }}
    if ($free > $rest) {{ $free = $rest; }}
    @wait[$tg] = sum($w); @own[$tg] = sum($own); @limit[$tg] = sum($limit);
    @idle_cpu[$tg] = sum($free); @others[$tg] = sum($rest - $free);
    @seen_idle[$tg] = sum(@ai[$tid]); @waits[$tg] = count();
    if ($limit > 0) {{ @limited_idle[$tg] = sum(@ai[$tid]); @limited_waits[$tg] = count(); @limited_rest[$tg] = sum($rest); }}
    if (@moved[$tid] > 0) {{ @moved_waits[$tg] = count(); }}
    // bpftrace's maps hold 4096 keys: a server that starts a thread per request has more threads than that.
    delete(@b[$tid]); delete(@moved[$tid]); delete(@on[$tid]); delete(@i0[$tid]); delete(@o0[$tid]); delete(@l0[$tid]);
    delete(@ai[$tid]); delete(@ao[$tid]); delete(@al[$tid]);
  }}
}}
rawtracepoint:sched_waking, rawtracepoint:sched_wakeup_new {{
  $p = arg0; $tg = {tg('$p')}; $tid = {pid('$p')};
  if ({traced('$tg')} && @b[$tid] == 0) {{
    $now = nsecs; $x = (uint64)*(uint32 *)($p + {o['cpu']}); $q = *(uint64 *)($p + {o['queue']});
    if (@t[$x] != 0) {{
      @b[$tid] = $now; @ai[$tid] = (uint64)0; @ao[$tid] = (uint64)0; @al[$tid] = (uint64)0;
      {start}
    }}
  }}
}}
rawtracepoint:sched_migrate_task {{
  $p = arg0; $tg = {tg('$p')}; $tid = {pid('$p')};
  if ({traced('$tg')} && @b[$tid] != 0) {{
    $now = nsecs; $q = *(uint64 *)($p + {o['queue']});
    {settle}
    $x = (uint64)arg1;
    $q = *(uint64 *)(*(uint64 *)(*(uint64 *)($p + {o['group']}) + {o['queues']}) + $x * 8);
    @moved[$tid] = 1;
    if (@t[$x] == 0) {{ @t[$x] = $now; }}
    {start}
  }}
}}
END {{ clear(@t); clear(@curidle); clear(@curtg); clear(@off); clear(@b); clear(@on); clear(@i0); clear(@o0); clear(@l0);
      clear(@ai); clear(@ao); clear(@al); clear(@idle); clear(@ran); clear(@moved); }}
"""


def summed(path):
    by = collections.defaultdict(dict)
    for line in open(path):
        m = re.match(r"@(\w+)\[(\d+)\]: (\d+)", line)
        if m:
            by[m[2]][m[1]] = int(m[3])
    names = ["wait", "own", "limit", "others", "idle_cpu", "seen_idle", "limited_idle", "limited_rest", "waits", "limited_waits",
             "moved_waits"]
    for pid, v in by.items():
        print(f"pid={pid} " + " ".join(f"{n}={v.get(n, 0)}" for n in names))


if len(sys.argv) >= 3 and sys.argv[1] == "script":
    print(script(sys.argv[2:]))
elif len(sys.argv) == 3 and sys.argv[1] == "sum":
    summed(sys.argv[2])
else:
    raise SystemExit(__doc__)
