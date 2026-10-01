import pathlib, tomllib
from collections import defaultdict
for path in pathlib.Path(".").rglob("Cargo.toml"):
    if any(p in ("target", ".git") for p in path.parts):
        continue
    text = path.read_text()
    data = tomllib.loads(text)
    def check(node):
        if isinstance(node, dict):
            url = node.get("git", "")
            if any(org in url for org in ("corbet-foss/", "corbet-libs/")):
                assert node.get("branch") == "main" and "rev" not in node and "tag" not in node, f"non-main dependency in {path}"
            for value in node.values():
                check(value)
    check(data)
versions = defaultdict(list)
for package in tomllib.loads(pathlib.Path("Cargo.lock").read_text())["package"]:
    source = package.get("source", "")
    if any(org in source for org in ("corbet-foss/", "corbet-libs/")):
        assert "?rev=" not in source and "&rev=" not in source, "transitive revision pin"
        assert "?tag=" not in source and "&tag=" not in source, "transitive tag pin"
        assert "?branch=main#" in source, "transitive first-party dependency is not on main"
        versions[package["name"]].append(source.split("#")[-1])
assert all(len(v) == 1 for v in versions.values()), "duplicate first-party crate entries"
print("First-party dependencies use main with one locked revision per crate")
