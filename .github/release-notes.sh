#!/bin/sh
# release-notes.sh TAG prints the GitHub release notes for TAG: the optional
# introduction in docs/release-notes/<TAG>.md, the commits since the previous tag
# grouped by their conventional-commit type, and how to verify the binaries.
# The introduction is read from the tagged tree, which means it is committed
# before the tag is pushed.
set -eu

tag=${1:?usage: release-notes.sh TAG}
repo=${GITHUB_REPOSITORY:-devlab-group/mcp-scanner}
# A tag not created yet previews the notes for the commits up to HEAD
if git rev-parse -q --verify "$tag^{commit}" >/dev/null; then
	end=$tag
	prev=$(git describe --tags --abbrev=0 "$tag^" 2>/dev/null || true)
else
	end=HEAD
	prev=$(git describe --tags --abbrev=0 HEAD 2>/dev/null || true)
fi

intro=docs/release-notes/$tag.md
if [ -f "$intro" ]; then
	cat "$intro"
	echo
fi

echo "## Changes"
git log --reverse --no-merges --format='%h %s' "${prev:+$prev..}$end" | awk '
{
	hash = $1
	subject = substr($0, length(hash) + 2)
	group = "Other changes"
	if (match(subject, /^[a-z]+(\([^)]*\))?!?: /)) {
		type = substr(subject, 1, RLENGTH)
		sub(/[(!:].*/, "", type)
		subject = substr(subject, RLENGTH + 1)
		if (type == "fix") group = "Fixes"
		else if (type == "feat") group = "Features"
		else if (type == "build" || type == "ci") group = "Build and release"
		else if (type == "docs") group = "Documentation"
	}
	lines[group] = lines[group] "- " toupper(substr(subject, 1, 1)) substr(subject, 2) " (" hash ")\n"
}
END {
	n = split("Features|Fixes|Build and release|Documentation|Other changes", order, "|")
	for (i = 1; i <= n; i++)
		if (order[i] in lines)
			printf "\n### %s\n%s", order[i], lines[order[i]]
}'

if [ -n "$prev" ]; then
	echo
	echo "Full changelog: https://github.com/$repo/compare/$prev...$tag"
fi

sed -e "s|@TAG@|$tag|g" -e "s|@REPO@|$repo|g" <<'EOF'

## Verifying a download

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify mcp-scanner_linux_amd64 \
  --repo @REPO@ \
  --signer-workflow @REPO@/.github/workflows/dist.yml \
  --source-ref refs/tags/@TAG@
```

Linux binaries are statically linked and run on any distribution. Prebuilt
binaries do not include YARA signature matching; build with `-tags yara`
against libyara for it.
EOF
