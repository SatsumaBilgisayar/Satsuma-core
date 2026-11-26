"""Judge the code in a program's writable+executable memory (SATSUMA-RAM-001, 2.2.67).

Owner's decision 2026-11-22: finding anonymous writable+executable memory is not enough to end
a program. Browsers, Java, Node, .NET, Wine, emulators and many games keep such memory for
their JIT all day. The program is held still for a few seconds (privd `freeze`), the code in
each such region is read from /proc/<pid>/mem and judged, then:

* `malicious`  - code that only an attack puts there: an ELF image loaded into anonymous
  memory, execve("/bin/sh") or connect-back shellcode, a known in-memory implant
  (Meterpreter, ReflectiveLoader...), or two independent medium signs together. The process
  stays held and is stopped by the normal path (privd `terminate`).
* `clean`        - the memory is empty or holds no sign of attack code: the program goes on.
* `inconclusive` - one medium sign, or the memory could not be read: the program goes on and
  the finding is kept for review (INCONCLUSIVE_STOPS = False). Other rules for the same
  process (memfd program, deleted file, code from /tmp, ptrace) still stop it on their own.

Nothing read is stored: only sizes, offsets, sign names and a SHA-256 of each sampled region.

Yazılabilir+çalıştırılabilir bellekteki kodun değerlendirilmesi (RAM-001, 2.2.67). Sahibinin
kararı 2026-11-22: böyle bellek bulmak programı sonlandırmak için yetmez. Süreç birkaç saniye
bekletilir, bölgelerdeki kod okunur ve değerlendirilir: kötü (saldırı kodu) ise durdurulur;
temiz ya da belirsiz ise devam eder, belirsiz bulgu inceleme için kaydedilir. Okunan bellek
saklanmaz; yalnızca boyut, konum, işaret adları ve özet (SHA-256) kaydedilir.
"""
import hashlib
import math
import os
import re
import time
from pathlib import Path

PAGE = 4096
REGION_LIMIT = 64                 # regions examined per process
REGION_BYTES = 2 * 1024 * 1024    # bytes read from one region
TOTAL_BYTES = 16 * 1024 * 1024    # bytes read per process
TIME_LIMIT = 1.5                  # seconds of reading and judging per process
HOLD_SECONDS = 4
INCONCLUSIVE_STOPS = False
VERDICT_MEMORY = 600.0            # seconds a verdict for the same memory is reused

STRONG, MEDIUM, WEAK = 'strong', 'medium', 'weak'

# Byte patterns. x86-64 and i386 are what Fedora desktops run; aarch64 has its own syscall word.
SH_STRINGS = (b'/bin/sh\x00', b'/bin//sh', b'//bin/sh', b'/bin/bash\x00',
              b'\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68',      # movabs rbx,'/bin//sh'
              b'\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e')      # push '//sh'; push '/bin'
SYSCALL = re.compile(rb'\x0f\x05|\xcd\x80|\x01\x00\x00\xd4')    # syscall | int 0x80 | svc #0
EXECVE_NR = re.compile(rb'\x6a\x3b\x58|\xb0\x3b|\xb8\x3b\x00\x00\x00|\x6a\x0b\x58|\xb0\x0b')
SOCKET_NR = re.compile(rb'\x6a\x29\x58|\xb0\x29|\xb8\x29\x00\x00\x00')   # socket (41)
CONNECT_NR = re.compile(rb'\x6a\x2a\x58|\xb0\x2a|\xb8\x2a\x00\x00\x00')  # connect (42)
DUP2_NR = re.compile(rb'\x6a\x21\x58|\xb0\x21|\xb8\x21\x00\x00\x00')     # dup2 (33)
IMPLANTS = (b'metsrv', b'meterpreter', b'ReflectiveLoader', b'mettle_', b'stdapi_sys_process',
            b'cobaltstrike', b'beacon.x64', b'sliverpb', b'PAYLOAD_UUID')
NOP_SLED = re.compile(rb'\x90{128,}')


def _anonymous(name):
    from ..worker_memory import _anonymous as anonymous
    return anonymous(name)


def writable_exec_regions(pid, proc_root='/proc'):
    """Anonymous rwx regions of the process: [(start, end, perms, name)]."""
    rows = []
    with open(os.path.join(str(proc_root), str(pid), 'maps'), errors='replace') as stream:
        for line in stream.read(1024 * 1024).splitlines():
            fields = line.split(None, 5)
            if len(fields) < 5:
                continue
            perms, name = fields[1], fields[5] if len(fields) > 5 else ''
            if 'rwx' not in perms or not _anonymous(name):
                continue
            start, end = (int(x, 16) for x in fields[0].split('-'))
            rows.append((start, end, perms, name))
    return rows


def _entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    size = len(data)
    return -sum(c / size * math.log2(c / size) for c in counts if c)


def _near(first, second, data, distance):
    """True when a match of first lies within distance bytes of a match of second."""
    places = [m.start() for m in second.finditer(data)][:4096]
    if not places:
        return False
    for match in list(first.finditer(data))[:4096]:
        if any(abs(match.start() - p) <= distance for p in places):
            return True
    return False


def judge(data):
    """Signs of attack code in one region's bytes: [{'sign', 'level', 'offset'}]."""
    signs = []
    if not data or not data.strip(b'\x00'):
        return signs
    # An ELF image in anonymous memory: a program or library loaded without a file
    # (reflective loading, memfd-less injection). Kernel and loaders never do this.
    for offset in range(0, len(data) - 64, PAGE):
        if data[offset:offset + 4] == b'\x7fELF' and data[offset + 4] in (1, 2) and data[offset + 5] in (1, 2):
            signs.append({'sign': 'elf_image_in_anonymous_memory', 'level': STRONG, 'offset': offset})
            break
    for offset in range(0, len(data) - 64, PAGE):
        if data[offset:offset + 2] == b'MZ':
            lfanew = int.from_bytes(data[offset + 60:offset + 64], 'little')
            if 0 < lfanew < PAGE and data[offset + lfanew:offset + lfanew + 4] == b'PE\x00\x00':
                signs.append({'sign': 'pe_image_in_anonymous_memory', 'level': MEDIUM, 'offset': offset})
                break
    for marker in IMPLANTS:
        at = data.find(marker)
        if at >= 0:
            signs.append({'sign': 'implant_marker:' + marker.decode(), 'level': STRONG, 'offset': at})
            break
    shell = min((at for at in (data.find(s) for s in SH_STRINGS) if at >= 0), default=-1)
    if shell >= 0 and _near(EXECVE_NR, SYSCALL, data, 64):
        signs.append({'sign': 'execve_shell_shellcode', 'level': STRONG, 'offset': shell})
    elif shell >= 0 and SYSCALL.search(data[max(0, shell - 256):shell + 256]):
        signs.append({'sign': 'shell_string_next_to_syscall', 'level': MEDIUM, 'offset': shell})
    if _near(SOCKET_NR, SYSCALL, data, 32) and _near(CONNECT_NR, SYSCALL, data, 32):
        level = STRONG if _near(DUP2_NR, SYSCALL, data, 32) else MEDIUM
        signs.append({'sign': 'connect_back_shellcode', 'level': level,
                      'offset': SOCKET_NR.search(data).start()})
    sled = NOP_SLED.search(data)
    if sled:
        signs.append({'sign': 'nop_sled', 'level': MEDIUM, 'offset': sled.start()})
    # JIT output calls into its runtime; raw system calls packed together are rare there.
    used = len(data.rstrip(b'\x00')) or 1
    calls = len(SYSCALL.findall(data))
    if calls >= 8 and calls * 2048 > used:
        signs.append({'sign': 'dense_raw_syscalls', 'level': MEDIUM, 'offset': SYSCALL.search(data).start(),
                      'count': calls})
    block = data[:65536].rstrip(b'\x00')
    if len(block) >= PAGE and _entropy(block) > 7.6:
        signs.append({'sign': 'packed_or_encrypted_payload', 'level': WEAK, 'offset': 0})
    return signs


def verdict(signs, readable=True):
    levels = [s['level'] for s in signs]
    if STRONG in levels or len({s['sign'] for s in signs if s['level'] == MEDIUM}) >= 2:
        return 'malicious'
    if not readable:
        return 'inconclusive'
    if MEDIUM in levels:
        return 'inconclusive'
    return 'clean'


def read_regions(pid, regions, proc_root='/proc', deadline=None):
    """[(region, bytes or None, error)] within the byte and time budget."""
    out, total = [], 0
    try:
        fd = os.open(os.path.join(str(proc_root), str(pid), 'mem'), os.O_RDONLY)
    except OSError as exc:
        return [(region, None, type(exc).__name__) for region in regions]
    try:
        for region in regions[:REGION_LIMIT]:
            if total >= TOTAL_BYTES or (deadline and time.monotonic() > deadline):
                out.append((region, None, 'budget'))
                continue
            start, end = region[0], region[1]
            size = min(end - start, REGION_BYTES, TOTAL_BYTES - total)
            chunks, offset, error = [], 0, None
            while offset < size:
                try:
                    chunk = os.pread(fd, min(256 * 1024, size - offset), start + offset)
                except OSError as exc:
                    error = type(exc).__name__
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                offset += len(chunk)
            data = b''.join(chunks)
            total += len(data)
            out.append((region, data if data or not error else None, error))
    finally:
        os.close(fd)
    return out


class PrivdFreezer:
    """Holds through privd; returns None from freeze when holding is not possible."""

    def freeze(self, pid, starttime, seconds, reason):
        from .. import privd
        answer = privd.delegate('freeze', pid=int(pid), starttime=int(starttime),
                                seconds=int(seconds), reason=str(reason)[:500])
        if answer is None:
            # This process may act itself (root with CAP_KILL, no privd): hold locally.
            from ..process_hold import Holds
            if not hasattr(self, '_local'):
                self._local = Holds(state_file=Path('/run/satsuma-core-holds.json'))
            answer = self._local.freeze(pid, starttime, seconds, reason)
        return answer

    def thaw(self, pid, starttime, token):
        from .. import privd
        answer = privd.delegate('thaw', pid=int(pid), starttime=int(starttime), token=token,
                                reason='RAM-001 inceleme bitti')
        if answer is None and hasattr(self, '_local'):
            answer = self._local.thaw(pid, token=token, starttime=starttime)
        return answer


_VERDICTS = {}


def _process_state(pid, proc_root):
    try:
        return Path(proc_root, str(pid), 'stat').read_text(errors='replace').rsplit(')', 1)[-1].split()[0]
    except (OSError, IndexError):
        return None


def inspect(pid, starttime, exe=None, *, freezer=None, proc_root='/proc', hold_seconds=HOLD_SECONDS,
            clock=time.monotonic):
    """Hold, read, judge, and resume unless the code is malicious.

    Returns {'verdict', 'signs', 'regions', 'held', 'resumed', 'hold', ...}. When the verdict
    is malicious the process is left held for the stop that follows (privd resumes it at the
    deadline if that stop is refused).
    """
    started = clock()
    report = {'pid': pid, 'starttime': starttime, 'exe': exe, 'verdict': 'inconclusive', 'signs': [],
              'regions': [], 'held': False, 'resumed': False, 'raw_memory_persisted': False,
              'policy': {'inconclusive_stops': INCONCLUSIVE_STOPS, 'hold_seconds': hold_seconds}}
    try:
        regions = writable_exec_regions(pid, proc_root)
    except OSError as exc:
        report.update(verdict='inconclusive', reason='maps_unreadable:' + type(exc).__name__)
        return report
    if not regions:
        report.update(verdict='clean', reason='no_anonymous_rwx_region_now')
        return report
    shape = tuple((r[0], r[1]) for r in regions)
    freezer = freezer or PrivdFreezer()
    hold = None
    try:
        hold = freezer.freeze(pid, starttime, hold_seconds, 'SATSUMA-RAM-001 bellek incelemesi')
    except Exception as exc:
        hold = {'status': 'freeze_failed', 'held': False, 'error': str(exc)[:200]}
    report['hold'] = {k: v for k, v in (hold or {}).items() if k != 'token'}
    report['held'] = bool(hold and hold.get('held'))
    token = (hold or {}).get('token')
    try:
        samples = read_regions(pid, regions, proc_root, deadline=started + TIME_LIMIT)
        readable = True
        digest = hashlib.sha256(repr(shape).encode())
        for (start, end, perms, name), data, error in samples:
            row = {'start': hex(start), 'size': end - start, 'name': name or '(adsız)', 'perms': perms}
            if data is None:
                readable = False
                row['status'] = 'unreadable:' + str(error)
            else:
                row['bytes_read'] = len(data)
                row['empty'] = not data.strip(b'\x00')
                row['sha256'] = hashlib.sha256(data).hexdigest()
                digest.update(row['sha256'].encode())
                found = judge(data)
                for sign in found:
                    sign['region'] = row['start']
                report['signs'].extend(found)
                row['status'] = 'judged'
            report['regions'].append(row)
        # Somebody resumed the held program while it was being read (only its own user or root
        # can): that is a sign in itself. Okuma sırasında süreci biri sürdürdüyse işarettir.
        if report['held'] and hold.get('all_threads_stopped') and _process_state(pid, proc_root) not in ('T', 't', None):
            report['signs'].append({'sign': 'resumed_while_held', 'level': MEDIUM, 'offset': 0})
        report['verdict'] = verdict(report['signs'], readable)
        report['memory_digest'] = digest.hexdigest()
        if not readable:
            report['reason'] = 'some_regions_unreadable'
    finally:
        keep_held = report['verdict'] == 'malicious' or (report['verdict'] == 'inconclusive' and INCONCLUSIVE_STOPS)
        if report['held'] and not keep_held:
            try:
                answer = freezer.thaw(pid, starttime, token) or {}
                report['resumed'] = bool(answer.get('resumed'))
                report['thaw'] = answer.get('status')
            except Exception as exc:
                report['thaw'] = 'thaw_failed:' + str(exc)[:200]
        report['elapsed_seconds'] = round(clock() - started, 3)
    return report


def decide(pid, starttime, exe=None, **kwargs):
    """inspect() with a short memory: the same memory of the same process is judged once."""
    now = time.monotonic()
    for key in [k for k, (at, _) in _VERDICTS.items() if now - at > VERDICT_MEMORY]:
        del _VERDICTS[key]
    report = inspect(pid, starttime, exe, **kwargs)
    key = (pid, starttime, report.get('memory_digest'))
    previous = _VERDICTS.get(key)
    if previous and report['verdict'] != 'malicious':
        report['repeat_of_earlier_verdict'] = True
    _VERDICTS[key] = (now, report['verdict'])
    if len(_VERDICTS) > 4096:
        _VERDICTS.clear()
    return report


def stops(report):
    return report.get('verdict') == 'malicious' or (report.get('verdict') == 'inconclusive' and INCONCLUSIVE_STOPS)
