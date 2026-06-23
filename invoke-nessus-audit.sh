#!/usr/bin/env sh
set -u

usage() {
  cat <<'EOF'
Usage: ./invoke-nessus-audit.sh AUDIT_FILE [-o output.csv] [--allow-command-exec]

Runs locally supported Nessus .audit checks on Linux/Unix hosts and writes:
CHECK, Actual Value, Expected Value, Pass/Fail/Manual

Embedded command checks are not executed unless --allow-command-exec is passed.
Unsupported audit item types are reported as Manual.
EOF
}

audit_path=""
output_path=""
allow_command_exec=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    -o|--output)
      shift
      output_path="${1:-}"
      ;;
    --allow-command-exec)
      allow_command_exec=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [ -z "$audit_path" ]; then
        audit_path="$1"
      else
        echo "Unexpected argument: $1" >&2
        usage >&2
        exit 2
      fi
      ;;
  esac
  shift
done

if [ -z "$audit_path" ] || [ ! -f "$audit_path" ]; then
  echo "Audit file not found: ${audit_path:-<missing>}" >&2
  usage >&2
  exit 2
fi

base_name=$(basename "$audit_path")
base_name=${base_name%.*}
if [ -z "$output_path" ]; then
  output_path="./${base_name}_results_$(date +%Y%m%d_%H%M%S).csv"
fi

tmp_checks=$(mktemp "${TMPDIR:-/tmp}/nessus-audit-checks.XXXXXX") || exit 1
trap 'rm -f "$tmp_checks"' EXIT INT TERM

awk '
function trim(s) { sub(/^[ \t\r\n]+/, "", s); sub(/[ \t\r\n]+$/, "", s); return s }
function unquote(s, q) {
  s = trim(s)
  if (length(s) >= 2) {
    q = substr(s, 1, 1)
    if ((q == "\"" || q == "'\''") && substr(s, length(s), 1) == q) {
      s = substr(s, 2, length(s) - 2)
      gsub("\\\\" q, q, s)
    }
  }
  return s
}
function resolve(s, key) {
  s = unquote(s)
  if (s ~ /^@[A-Za-z0-9_]+@$/) {
    key = substr(s, 2, length(s) - 2)
    if (key in vars) return vars[key]
  }
  return s
}
function field(line, key, value) {
  line = trim(line)
  if (line !~ /^[A-Za-z_][A-Za-z0-9_]*[ \t]*:/) return
  key = line
  sub(/[ \t]*:.*/, "", key)
  value = line
  sub(/^[^:]*:[ \t]*/, "", value)
  if (key == "value_data" || key == "expect" || key == "not_expect" || key == "regex") {
    f[key] = trim(value)
  } else {
    f[key] = unquote(value)
  }
}
function emit(  desc, id, title, typ, target, method, op, expected, manual, value) {
  typ = f["type"]
  desc = f["description"]
  item_count++
  id = sprintf("audit-%04d", item_count)
  title = desc
  if (match(desc, /^[0-9]+(\.[0-9]+)*/)) {
    id = substr(desc, RSTART, RLENGTH)
    title = trim(substr(desc, RLENGTH + 1))
    sub(/^\(L[0-9]+\)[ \t]*/, "", title)
  }

  method = "Manual"; target = ""; op = ""; expected = ""; manual = "Unsupported Nessus audit item type for this local runner: " typ

  if (typ ~ /^FILE/ || typ == "FILE_CHECK" || typ == "FILE_CONTENT_CHECK") {
    method = "File"
    target = f["file"]; if (target == "") target = f["path"]; if (target == "") target = f["file_path"]
    value = resolve(f["not_expect"])
    if (value != "") { op = "NotRegex"; expected = value }
    else {
      value = resolve(f["expect"])
      if (value != "") { op = "Regex"; expected = value }
      else {
        value = resolve(f["regex"])
        if (value != "") { op = "Regex"; expected = value }
        else { op = "Exists"; expected = "File exists" }
      }
    }
    if (f["file_mode"] != "" || f["mode"] != "" || f["owner"] != "" || f["group"] != "") {
      method = "FileMetadata"
      op = "Metadata"
      expected = "mode=" f["file_mode"] f["mode"] " owner=" f["owner"] " group=" f["group"]
    }
    manual = ""
  } else if (typ ~ /CMD|COMMAND|SHELL/ || f["cmd"] != "" || f["command"] != "") {
    method = "Command"
    target = f["cmd"]; if (target == "") target = f["command"]; if (target == "") target = f["shell_command"]
    value = resolve(f["not_expect"])
    if (value != "") { op = "NotRegex"; expected = value }
    else {
      value = resolve(f["expect"]); if (value == "") value = resolve(f["value_data"])
      if (f["check_type"] == "CHECK_NOT_REGEX") op = "NotRegex"; else op = "Regex"
      expected = value
    }
    manual = ""
  } else if (typ ~ /PACKAGE/ || f["package"] != "" || f["pkg"] != "") {
    method = "Package"
    target = f["package"]; if (target == "") target = f["pkg"]; if (target == "") target = f["rpm"]
    op = "Installed"; expected = "Installed"; manual = ""
  } else if (typ ~ /PROCESS/ || f["process"] != "") {
    method = "Process"
    target = f["process"]
    op = "Running"; expected = "Running"; manual = ""
  } else if (typ ~ /SERVICE/ || f["service"] != "") {
    method = "Service"
    target = f["service"]
    op = "EnabledOrActive"; expected = "Enabled or active"; manual = ""
  }

  printf "%s\034%s\034%s\034%s\034%s\034%s\034%s\034%s\n", id, title, method, target, op, expected, typ, manual
}

/<variable>/ { invar = 1; vname = ""; vdefault = "" }
invar && /<name>/ { vname = $0; sub(/.*<name>/, "", vname); sub(/<\/name>.*/, "", vname); vname = trim(vname) }
invar && /<default>/ { vdefault = $0; sub(/.*<default>/, "", vdefault); sub(/<\/default>.*/, "", vdefault); vdefault = trim(vdefault) }
/<\/variable>/ { if (vname != "") vars[vname] = vdefault; invar = 0 }

/<custom_item>/ { incustom = 1; delete f; next }
/<\/custom_item>/ { if (incustom && f["type"] != "" && f["description"] != "") emit(); incustom = 0; next }
incustom { field($0) }
' "$audit_path" > "$tmp_checks"

csv_escape() {
  printf '%s' "$1" | tr '\n\r' '  ' | sed 's/"/""/g; s/^/"/; s/$/"/'
}

write_row() {
  csv_escape "$1"; printf ','
  csv_escape "$2"; printf ','
  csv_escape "$3"; printf ','
  csv_escape "$4"; printf '\n'
}

number_from_text() {
  printf '%s' "$1" | sed -n 's/[^0-9-]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p'
}

test_value() {
  tv_actual=$1
  tv_op=$2
  tv_expected=$3
  case "$tv_op" in
    Regex) printf '%s\n' "$tv_actual" | grep -Eq "$tv_expected" ;;
    NotRegex) ! printf '%s\n' "$tv_actual" | grep -Eq "$tv_expected" ;;
    Equals) [ "$tv_actual" = "$tv_expected" ] ;;
    NotEqual) [ "$tv_actual" != "$tv_expected" ] ;;
    Range)
      n=$(number_from_text "$tv_actual")
      min=$(printf '%s' "$tv_expected" | sed -n 's/^\[\{0,1\}\([0-9][0-9]*\|MIN\)\.\.\([0-9][0-9]*\|MAX\)\]\{0,1\}$/\1/p')
      max=$(printf '%s' "$tv_expected" | sed -n 's/^\[\{0,1\}\([0-9][0-9]*\|MIN\)\.\.\([0-9][0-9]*\|MAX\)\]\{0,1\}$/\2/p')
      [ -n "$n" ] || return 1
      { [ "$min" = "MIN" ] || [ "$n" -ge "$min" ]; } && { [ "$max" = "MAX" ] || [ "$n" -le "$max" ]; }
      ;;
    *) [ "$tv_actual" = "$tv_expected" ] ;;
  esac
}

{
  write_row "CHECK" "Actual Value" "Expected Value" "Pass/Fail/Manual"

  while IFS="$(printf '\034')" read -r id title method target op expected source_type manual_reason; do
    check="$id $title"
    actual=""
    status="Manual"

    case "$method" in
      File)
        if [ -z "$target" ]; then
          actual="No file path in audit item"
          status="Manual"
        elif [ "$op" = "Exists" ]; then
          if [ -e "$target" ]; then actual="Exists"; status="Pass"; else actual="Missing"; status="Fail"; fi
        elif [ ! -f "$target" ]; then
          actual="Missing"
          status="Fail"
        else
          actual=$(grep -E "$expected" "$target" 2>/dev/null | head -n 5)
          [ -n "$actual" ] || actual="<no matching lines>"
          if test_value "$(cat "$target" 2>/dev/null)" "$op" "$expected"; then status="Pass"; else status="Fail"; fi
        fi
        ;;
      FileMetadata)
        if [ ! -e "$target" ]; then
          actual="Missing"
          status="Fail"
        else
          mode=$(stat -c "%a" "$target" 2>/dev/null || stat -f "%Lp" "$target" 2>/dev/null)
          owner=$(stat -c "%U" "$target" 2>/dev/null || stat -f "%Su" "$target" 2>/dev/null)
          group=$(stat -c "%G" "$target" 2>/dev/null || stat -f "%Sg" "$target" 2>/dev/null)
          actual="mode=$mode owner=$owner group=$group"
          status="Manual"
        fi
        ;;
      Command)
        if [ "$allow_command_exec" -ne 1 ]; then
          actual="Embedded command was not executed. Re-run with --allow-command-exec if this audit file is trusted."
          status="Manual"
        else
          actual=$(sh -c "$target" 2>&1)
          if test_value "$actual" "$op" "$expected"; then status="Pass"; else status="Fail"; fi
        fi
        ;;
      Package)
        if command -v dpkg-query >/dev/null 2>&1; then
          if dpkg-query -W -f='${Status}' "$target" 2>/dev/null | grep -q "install ok installed"; then actual="Installed"; status="Pass"; else actual="Not installed"; status="Fail"; fi
        elif command -v rpm >/dev/null 2>&1; then
          if rpm -q "$target" >/dev/null 2>&1; then actual="Installed"; status="Pass"; else actual="Not installed"; status="Fail"; fi
        else
          actual="No supported package manager found"
          status="Manual"
        fi
        ;;
      Process)
        if pgrep -f "$target" >/dev/null 2>&1; then actual="Running"; status="Pass"; else actual="Not running"; status="Fail"; fi
        ;;
      Service)
        if command -v systemctl >/dev/null 2>&1; then
          enabled=$(systemctl is-enabled "$target" 2>/dev/null)
          active=$(systemctl is-active "$target" 2>/dev/null)
          actual="enabled=$enabled active=$active"
          if [ "$enabled" = "enabled" ] || [ "$active" = "active" ]; then status="Pass"; else status="Fail"; fi
        else
          actual="systemctl not found"
          status="Manual"
        fi
        ;;
      *)
        actual="$manual_reason"
        status="Manual"
        ;;
    esac

    write_row "$check" "$actual" "$expected" "$status"
  done < "$tmp_checks"
} > "$output_path"

echo "Wrote Nessus audit results to: $output_path"
