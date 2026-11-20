#!/usr/bin/env python3
"""Compare `blame slow --raw` output with the log of h2_quirks.py's server.

    h2_check.py SERVER_LOG SLOW_LOG [--after-ns N] [--tol-us N]

A stream the server answered is good when the agent reported it once, with
its start and its end both within 300 us of the server's. Prints one line:

  streams         streams the server saw opened
  answered        of those, ended by the server with END_STREAM
  paired          answered streams reported with the right start and end
  mistimed        answered streams reported with a start or end that is off
  missing         answered streams not reported
  reset           streams reset by either side
  reset_reported  of those, reported as reset, with the right start
  misflagged      streams reported as reset that were answered, or the reverse
  extra           reported streams the server never saw

--tol-us widens the 300 us. The server stamps a call after it returned, which
is after the agent dealt with the call's frames: with hundreds of streams in
one call that alone is several hundred microseconds.

--after-ns drops streams that started before that boot-clock time, on both
sides (used when the agent attaches to connections that are already open).
"""
import sys

PAIR_TOL = 300_000  # ns


def main():
    args = sys.argv[1:]
    after = 0
    if "--after-ns" in args:
        i = args.index("--after-ns")
        after = int(args[i + 1])
        del args[i : i + 2]
    tol = PAIR_TOL
    if "--tol-us" in args:
        i = args.index("--tol-us")
        tol = int(args[i + 1]) * 1000
        del args[i : i + 2]
    server_path, slow_path = args

    server = {}
    for line in open(server_path):
        f = line.split()
        if len(f) == 6 and f[0] == "S" and int(f[3]) >= after:
            server[(int(f[1]), int(f[2]))] = (int(f[3]), int(f[4]))
    reported = {}
    duplicates = 0
    for line in open(slow_path, errors="replace"):
        if not line.startswith("req "):
            continue
        fields = dict(p.split("=", 1) for p in line.split()[1:] if "=" in p)
        if int(fields["flags"]) & 4 == 0 or int(fields["start_ns"]) < after:
            continue
        key = (int(fields["rport"]), int(fields["stream"]))
        duplicates += key in reported
        reported[key] = (
            int(fields["start_ns"]),
            int(fields["end_ns"]),
            bool(int(fields["flags"]) & 24),
        )

    paired = mistimed = missing = reset = reset_reported = misflagged = 0
    for key, (start, end) in server.items():
        seen = reported.get(key)
        if end == 0:
            reset += 1
            if seen is not None:
                misflagged += not seen[2]
                reset_reported += seen[2] and abs(seen[0] - start) <= tol
        elif seen is None:
            missing += 1
        elif seen[2]:
            misflagged += 1
        elif abs(seen[0] - start) <= tol and abs(seen[1] - end) <= tol:
            paired += 1
        else:
            mistimed += 1
    answered = len(server) - reset
    print(
        f"h2check streams={len(server)} answered={answered} paired={paired} mistimed={mistimed}"
        f" missing={missing} reset={reset} reset_reported={reset_reported} misflagged={misflagged}"
        f" extra={sum(key not in server for key in reported) + duplicates}"
    )


if __name__ == "__main__":
    main()
