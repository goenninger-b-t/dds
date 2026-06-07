#!/usr/bin/env python3
"""Generate sbom.spdx.json — an SPDX 3.0.1 JSON-LD SBOM for Common Lisp DDS.

EU Cyber Resilience Act (Reg. (EU) 2024/2847, Annex I Part II §1) requires an SBOM
"covering at the very least the top-level dependencies"; BSI TR-03183-2 is its de-facto
technical baseline (mandatory fields: SBOM author + timestamp; per component: supplier,
name, version, dependency relationships, licence where determinable, hash where available,
a unique identifier). SPDX 3.0's native serialization is JSON-LD, so this emits SPDX 3.0.1.

Top-level dependencies are derived live from the ASDF *.asd `:depends-on` lists (so new
direct deps appear automatically); version/licence/supplier come from the pinned table
below (refresh from the Quicklisp dist when it changes). The runtime (SBCL) version is
queried live when `sbcl` is on PATH. Dynamic fields (timestamp, git revision) are computed
each run. Run before every commit (scripts/git-hooks/pre-commit) or via `make sbom`.
"""
import datetime
import glob
import json
import os
import re
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NS = "https://github.com/goenninger-b-t/dds/sbom#"
REPO_URL = "https://github.com/goenninger-b-t/dds"
SPEC = "3.0.1"
CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

# Pinned top-level dependency metadata (Quicklisp dist 2026-01-01). Versions from ASDF
# component-version; "NOASSERTION" where the system declares none. Licences per
# docs/provenance.md + each project's LICENSE. Update when the dist is bumped.
COMPONENTS = {
    "static-vectors":   {"version": "1.9.3", "license": "MIT",
                         "download": "https://github.com/sionescu/static-vectors",
                         "supplier": "Stelian Ionescu (sionescu)"},
    "cffi":             {"version": "NOASSERTION", "license": "MIT",
                         "download": "https://github.com/cffi/cffi",
                         "supplier": "The CFFI authors"},
    "bordeaux-threads": {"version": "0.9.4", "license": "MIT",
                         "download": "https://github.com/sionescu/bordeaux-threads",
                         "supplier": "The bordeaux-threads authors"},
}


def sh(*args, default=""):
    try:
        return subprocess.run(args, cwd=ROOT, capture_output=True, text=True,
                              timeout=20).stdout.strip() or default
    except Exception:
        return default


def git_revision():
    # The current HEAD short sha. (At pre-commit time this is the parent of the commit
    # being created; the "-dev" version marker already signals this is not an exact pin.)
    return sh("git", "rev-parse", "--short", "HEAD", default="unknown")


def sbcl_version():
    out = sh("sbcl", "--version")          # e.g. "SBCL 2.6.5-85913ede1"
    parts = out.split()
    return parts[1] if len(parts) >= 2 and parts[0].upper() == "SBCL" else "NOASSERTION"


def asd_dependencies():
    deps = set()
    for path in glob.glob(os.path.join(ROOT, "*.asd")):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        for block in re.findall(r":depends-on\s*\(([^)]*)\)", text):
            for name in re.findall(r'"([^"]+)"', block):
                if not name.lower().startswith("dds"):
                    deps.add(name)
    return sorted(deps)


def slug(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-")


def main():
    created = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    revision = git_revision()
    version = "0.0.0-dev+git." + revision
    deps = asd_dependencies()

    ci = "_:creationinfo"
    org_root = NS + "agent/goenninger-b-t"
    tool = NS + "tool/generate-sbom"
    lic_mit = NS + "license/MIT"
    lic_cc0 = NS + "license/CC0-1.0"
    sbom_id = NS + "sbom"
    doc_id = NS + "document"
    root_pkg = NS + "package/common-lisp-dds"
    rt_pkg = NS + "package/sbcl"

    graph = []
    elements = []   # every spdxId-bearing element (for SpdxDocument.element)

    graph.append({"@id": ci, "type": "CreationInfo", "specVersion": SPEC,
                  "created": created, "createdBy": [org_root], "createdUsing": [tool]})

    # Agents (root supplier + one Organization per distinct dependency supplier) + tool.
    suppliers = {"goenninger-b-t": org_root}
    graph.append({"spdxId": org_root, "type": "Organization", "creationInfo": ci,
                  "name": "goenninger-b-t"})
    elements.append(org_root)
    for name in deps:
        sup = COMPONENTS.get(name, {}).get("supplier")
        if sup and sup not in suppliers:
            sid = NS + "agent/" + slug(sup)
            suppliers[sup] = sid
            graph.append({"spdxId": sid, "type": "Organization", "creationInfo": ci, "name": sup})
            elements.append(sid)
    graph.append({"spdxId": tool, "type": "Tool", "creationInfo": ci,
                  "name": "common-lisp-dds scripts/generate-sbom.py"})
    elements.append(tool)

    # Licences (referenced by software_declaredLicense / dataLicense).
    graph.append({"spdxId": lic_mit, "type": "simplelicensing_LicenseExpression",
                  "creationInfo": ci, "simplelicensing_licenseExpression": "MIT"})
    graph.append({"spdxId": lic_cc0, "type": "simplelicensing_LicenseExpression",
                  "creationInfo": ci, "simplelicensing_licenseExpression": "CC0-1.0"})
    elements += [lic_mit, lic_cc0]

    # Root product package.
    root = {"spdxId": root_pkg, "type": "software_Package", "creationInfo": ci,
            "name": "common-lisp-dds", "software_packageVersion": version,
            "software_downloadLocation": REPO_URL, "software_homePage": REPO_URL,
            "software_packageUrl": "pkg:github/goenninger-b-t/dds@" + revision,
            "software_primaryPurpose": "library", "suppliedBy": org_root,
            "comment": "OMG DDS 1.4 / DDSI-RTPS 2.5 / XCDR middleware in Common Lisp. "
                       "No LICENSE file declared in-repo yet -> declared licence omitted "
                       "(NOASSERTION)."}
    graph.append(root)
    elements.append(root_pkg)

    # Dependency packages (top-level, CRA Annex I minimum).
    dep_ids = []
    relationships = []
    for i, name in enumerate(deps):
        meta = COMPONENTS.get(name, {})
        pid = NS + "package/" + slug(name)
        dep_ids.append(pid)
        pkg = {"spdxId": pid, "type": "software_Package", "creationInfo": ci,
               "name": name, "software_packageVersion": meta.get("version", "NOASSERTION"),
               "software_primaryPurpose": "library", "software_packageUrl": "pkg:generic/" + name}
        if meta.get("download"):
            pkg["software_downloadLocation"] = meta["download"]
        if meta.get("license") == "MIT":
            pkg["software_declaredLicense"] = lic_mit
        if meta.get("supplier"):
            pkg["suppliedBy"] = suppliers[meta["supplier"]]
        graph.append(pkg)
        elements.append(pid)
        rid = NS + "relationship/dependsOn-" + slug(name)
        relationships.append(rid)
        graph.append({"spdxId": rid, "type": "Relationship", "creationInfo": ci,
                      "from": root_pkg, "to": [pid], "relationshipType": "dependsOn"})

    # Runtime: the Common Lisp implementation (SBCL queried live; Clasp is the alternative).
    graph.append({"spdxId": rt_pkg, "type": "software_Package", "creationInfo": ci,
                  "name": "sbcl", "software_packageVersion": sbcl_version(),
                  "software_downloadLocation": "https://www.sbcl.org/",
                  "software_homePage": "https://www.sbcl.org/",
                  "software_primaryPurpose": "application",
                  "comment": "Common Lisp runtime (alternative landed target: Clasp). "
                             "SBCL is public-domain with BSD/MIT portions -> declared "
                             "licence omitted (NOASSERTION)."})
    elements.append(rt_pkg)
    rt_rel = NS + "relationship/runtime-sbcl"
    relationships.append(rt_rel)
    graph.append({"spdxId": rt_rel, "type": "Relationship", "creationInfo": ci,
                  "from": root_pkg, "to": [rt_pkg], "relationshipType": "dependsOn",
                  "comment": "runtime dependency"})

    # The SBOM element (its rootElement is the product; contents are deps + relationships).
    graph.append({"spdxId": sbom_id, "type": "software_Sbom", "creationInfo": ci,
                  "software_sbomType": ["source"], "rootElement": [root_pkg],
                  "element": dep_ids + [rt_pkg] + relationships})
    elements.append(sbom_id)

    # The containing document.
    graph.append({"spdxId": doc_id, "type": "SpdxDocument", "creationInfo": ci,
                  "name": "common-lisp-dds SBOM", "profileConformance":
                  ["core", "software", "simplelicensing"], "dataLicense": lic_cc0,
                  "rootElement": [sbom_id], "element": elements + [sbom_id]})

    out = {"@context": CONTEXT, "@graph": graph}
    path = os.path.join(ROOT, "sbom.spdx.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, sort_keys=True, ensure_ascii=False)
        fh.write("\n")
    print("generate-sbom: wrote sbom.spdx.json  (SPDX %s JSON-LD; %d top-level deps + runtime; rev %s)"
          % (SPEC, len(deps), revision))


if __name__ == "__main__":
    main()
