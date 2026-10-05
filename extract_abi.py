#!/usr/bin/env python3
"""
鸿蒙微内核 UAPI ABI 规格提取器
从 hm-verif-kernel/kernel/include/mapi 的公开头文件中提取:
  1. CAPTYPE 能力类型表 (类型号/授权策略/方法表/错误码)
  2. 编号式操作表 (ctrlmem/SMMU/KDP/驱动子系统的 fastcall/方法编号)
  3. lsyscall 表 (Linux 兼容系统调用编号, 复用 __NR_ 体系)
  4. sysproc bootargs 布局 (offset/size 断言)
  5. 函数声明清单 (按子系统归类)
输出: abi_inventory.json
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

MAPI = Path(sys.argv[1])  # .../kernel/include/mapi
UAPI = MAPI / "uapi"
ARCH = Path(sys.argv[2])  # .../kernel/arch/aarch64/include

out = {"meta": {}, "capability_types": [], "numbered_ops": {}, "lsyscalls": [],
       "bootargs": {}, "layout_asserts": {}, "declarations": {}}

# 授权策略: 在 CAPTYPE( 与第一个 CAPMETHOD 之间找
def _captype_block(text):
    i = text.find("CAPTYPE(")
    if i < 0:
        return ""
    j = text.find("CAPMETHOD", i)
    return text[i:j if j > 0 else i + 3000]

# ---------- 1. CAPTYPE 能力类型表 ----------
cap_re = re.compile(r'CAPTYPE\(\s*(\w+)\s*,\s*(\d+)\s*,', re.S)
method_re = re.compile(r'CAPMETHOD\(\s*(\w+)\s*,\s*(\w+)\s*\)')
errno_re = re.compile(r'CAPERRNO\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*,\s*"([^"]+)"\s*\)')
flag_re = re.compile(r'^#define\s+(\w+_FLAGS_MASK_\w+)\s+\(?(0x[0-9A-Fa-f]+ULL|0x[0-9A-Fa-f]+|\d+)\)?')

for f in sorted((UAPI / "hmkernel" / "capability").glob("captype_*.h")):
    text = f.read_text(errors="replace")
    block = _captype_block(text)
    m = cap_re.search(text)
    if not m:
        continue
    name, cid = m.group(1), int(m.group(2))
    grants = [f"CAP{g}GRANT" for g in re.findall(r'CAP(NO|COARSE|FINE|ALL)GRANT\(', block)]
    gmove = [f"CAP{g}GRANTMOVE" for g in re.findall(r'CAP(NO|ALL|COARSE)GRANTMOVE\(', block)]
    methods = []
    seen = set()
    for mm in method_re.finditer(text):
        if mm.group(1) == name and mm.group(2) not in seen:
            seen.add(mm.group(2))
            methods.append(mm.group(2))
    errnos = [{"kind": e[1], "code": e[2], "symbol": e[3]} for e in errno_re.findall(text) if e[0] == name]
    flags = [{"name": fm[0], "value": fm[1]} for fm in flag_re.findall(text)]
    out["capability_types"].append({
        "name": name, "cap_id": cid, "grant": grants, "grant_move": gmove,
        "methods": methods, "method_count": len(methods),
        "errnos": errnos, "config_flags": flags, "header": str(f.name),
    })

# ---------- 2. 编号式操作表 ----------
# 形如 #define __PREFIX_OP  <num>U?  (排除函数式宏/含括号值)
num_re = re.compile(r'^#define\s+__([A-Z0-9]+)_([A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+|\d+)U?U?L?\s*(?:/\*.*?\*/|//.*)?$')
for f in sorted(UAPI.rglob("*.h")):
    try:
        lines = f.read_text(errors="replace").splitlines()
    except OSError:
        continue
    for ln in lines:
        nm = num_re.match(ln.strip())
        if nm:
            prefix, op, val = nm.groups()
            out["numbered_ops"].setdefault(prefix, []).append(
                {"op": op, "value": int(val, 0), "header": str(f.relative_to(UAPI))})

# ---------- 2b. 枚举式操作表 (如 SMMU: enum __smmu_cmd) ----------
enum_re = re.compile(r'enum\s+__(\w+)\s*\{(.*?)\}', re.S)
for f in sorted(UAPI.rglob("*.h")):
    try:
        t = f.read_text(errors="replace")
    except OSError:
        continue
    for em in enum_re.finditer(t):
        ename, body = em.group(1), em.group(2)
        if not ename.lower().endswith("cmd"):
            continue
        prefix = ename[:-4].upper() if ename.lower().endswith("_cmd") else ename.upper()
        n = 0
        for e in body.splitlines():
            line = e.split("/*")[0].split("//")[0].strip().rstrip(",")
            if not line or line.startswith("#"):
                continue
            mm = re.match(r'__(\w+)\s*(?:=\s*(\d+))?$', line)
            if not mm:
                continue
            op, explicit = mm.group(1), mm.group(2)
            val = int(explicit) if explicit else n
            n = val + 1
            out["numbered_ops"].setdefault(prefix, []).append(
                {"op": op, "value": val, "header": str(f.relative_to(UAPI)), "enum": True})

# ---------- 3. lsyscall (Linux 兼容编号) ----------
lscno = ARCH / "mapi" / "uapi" / "hmasm" / "lscno_def.h"
if lscno.exists():
    ls_re = re.compile(r'LSCNO_DEF\(\s*(\w+)\s*,\s*(\d+)\s*\)')
    compat_re = re.compile(r'LSCNO_COMPAT_DEF\(\s*(\w+)\s*,\s*(\d+)\s*\)')
    text = lscno.read_text(errors="replace")
    out["lsyscalls"] = [{"name": n, "nr": int(v)} for n, v in ls_re.findall(text)]
    out["lsyscalls_compat"] = [{"name": n, "nr": int(v)} for n, v in compat_re.findall(text)]

# ---------- 4. bootargs 布局 ----------
boot = ARCH / "mapi" / "uapi" / "hmasm" / "boot" / "sysproc_bootargs.h"
if boot.exists():
    text = boot.read_text(errors="replace")
    off_re = re.compile(r'__sysproc_bootargs_assert_offset\(\s*(\w+)\s*,\s*(\w+)\s*\)')
    size_re = re.compile(r'__sysproc_bootargs_assert_size\([^,]+,\s*(\w+)\)')
    val_re = re.compile(r'#define\s+__SYSPROC_BOOTARGS_OFFSET_(\w+)\s+(\d+)')
    offs = {sym: int(v) for sym, v in val_re.findall(text)}
    fields = []
    for a, b in off_re.findall(text):
        fields.append({"field": a, "offset_symbol": b,
                       "offset": offs.get(b) if offs.get(b) is not None else offs.get(a.upper())})
    out["bootargs"] = {
        "fields": fields,
        "size_symbol": size_re.search(text).group(1) if size_re.search(text) else None,
        "struct": "struct __sysproc_bootargs_s (72 字节)",
    }

# ---------- 5. 布局断言统计 (mapi UAPI/内核侧 + arch 侧 mapi) ----------
asserts = defaultdict(int)
scan_roots = [("mapi", MAPI), ("arch_mapi", ARCH / "mapi")]
for root_tag, root in scan_roots:
    if not root.exists():
        continue
    for f in root.rglob("*.h"):
        try:
            t = f.read_text(errors="replace")
        except OSError:
            continue
        n = len(re.findall(r'_assert_(?:offset|size)\(', t))
        if n:
            asserts[f"{root_tag}/{f.relative_to(root)}"] = n
out["layout_asserts"] = dict(sorted(asserts.items(), key=lambda kv: -kv[1]))

# ---------- 6. 函数声明清单 (按子系统) ----------
decl_re = re.compile(r'^\s*(?:extern\s+|static\s+inline\s+|inline\s+)?[A-Za-z_][\w \t\*]*?([A-Za-z_]\w*)\s*\(')
by_subsys = defaultdict(int)
for f in sorted(UAPI.rglob("*.h")):
    rel = f.relative_to(UAPI).parts
    if rel[0] != "hmkernel":
        continue
    subsys = rel[1] if len(rel) > 2 else "."
    if subsys == "capability":
        subsys = "capability/" + (rel[2] if len(rel) > 3 else ".")
    try:
        t = f.read_text(errors="replace")
    except OSError:
        continue
    cnt = 0
    for ln in t.splitlines():
        s = ln.strip()
        if s.startswith("#") or s.startswith("/*") or s.startswith("*") or s.startswith("//"):
            continue
        if re.match(r'^[A-Za-z_][\w \t\*]*\**\s*\**[A-Za-z_]\w*\s*\(', s) and not re.match(r'^(typedef|CAPTYPE|CAPMETHOD|CAPERRNO|LSCNO)', s):
            cnt += 1
    by_subsys[subsys] += cnt
out["declarations"] = dict(sorted(by_subsys.items(), key=lambda kv: -kv[1]))

# ---------- meta ----------
out["meta"] = {
    "uapi_headers": sum(1 for _ in UAPI.rglob("*.h")),
    "cap_types": len(out["capability_types"]),
    "numbered_op_tables": {k: len(v) for k, v in out["numbered_ops"].items()},
    "lsyscall_count": len(out["lsyscalls"]),
    "lsyscall_compat_count": len(out.get("lsyscalls_compat", [])),
    "source": "hm-verif-kernel/kernel/include/mapi (官方开源合规包 UAPI)",
}

dest = Path(__file__).parent / "abi_inventory.json"
dest.write_text(json.dumps(out, ensure_ascii=False, indent=1))
print(f"OK -> {dest}")
print(json.dumps(out["meta"], ensure_ascii=False, indent=1))
