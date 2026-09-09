#!/usr/bin/env bash
# Reduce nextest JUnit to structural status. Captured output, host metadata,
# and unrecognized XML never reach the published diagnostic artifact.
set -euo pipefail
umask 077

refuse_sanitizer() {
  printf '[ci] %s: %s\n' "$1" "$2" >&2
  exit 1
}

[[ "$#" -eq 2 ]] \
  || refuse_sanitizer JUNIT_SANITIZER_USAGE 'expected INPUT OUTPUT'
source_path="$1"
destination="$2"
[[ -f "$source_path" ]] || refuse_sanitizer JUNIT_MISSING "$source_path"
for tool in awk mktemp mv sync; do
  command -v "$tool" >/dev/null 2>&1 \
    || refuse_sanitizer JUNIT_SANITIZER_TOOL_MISSING "$tool"
done

destination_dir="$(dirname "$destination")"
mkdir -p "$destination_dir"
if [[ -e "$destination" || -L "$destination" ]]; then
  [[ -f "$destination" && ! -L "$destination" ]] \
    || refuse_sanitizer JUNIT_SANITIZER_DESTINATION_INVALID \
      "$destination is not a non-symlink regular file"
fi
temporary="$(mktemp "$destination_dir/.$(basename "$destination").XXXXXX.tmp")"
cleanup() { rm -f -- "$temporary"; }
trap cleanup EXIT

if ! LC_ALL=C awk '
function refuse(reason, detail) {
  print "[ci] JUNIT_SANITIZATION_FAILED: " reason ": " detail > "/dev/stderr"
  exit 1
}
function trim(value) {
  sub(/^[ \t\r\n]+/, "", value)
  sub(/[ \t\r\n]+$/, "", value)
  return value
}
function indent(count, result, position_index) {
  result = ""
  for (position_index = 0; position_index < count; position_index++) result = result "    "
  return result
}
function allowed_tag(name) {
  return name == "testsuites" || name == "testsuite" || name == "testcase" ||
    name == "failure" || name == "error" || name == "skipped"
}
function dropped_tag(name) {
  return name == "system-out" || name == "system-err" || name == "properties"
}
function allowed_attribute(tag, key) {
  if (tag == "testsuites" || tag == "testsuite")
    return key == "name" || key == "tests" || key == "errors" ||
      key == "failures" || key == "disabled" || key == "time"
  if (tag == "testcase")
    return key == "name" || key == "classname" || key == "time"
  return 0
}
function entities_valid(value, offset, amp, semi, entity) {
  offset = 1
  while ((amp = index(substr(value, offset), "&")) != 0) {
    amp += offset - 1
    semi = index(substr(value, amp), ";")
    if (semi == 0) return 0
    entity = substr(value, amp + 1, semi - 2)
    if (entity !~ /^(amp|lt|gt|quot|apos|#[0-9]+|#x[0-9A-Fa-f]+)$/) return 0
    offset = amp + semi
  }
  return 1
}
function sanitized_attributes(raw, tag, result, equals, key, rest, quote_end, value, gap) {
  result = ""
  attribute_generation++
  raw = trim(raw)
  while (length(raw) != 0) {
    equals = index(raw, "=")
    if (equals <= 1) refuse("attribute", raw)
    key = trim(substr(raw, 1, equals - 1))
    if (key !~ /^[A-Za-z_][A-Za-z0-9_.:-]*$/) refuse("attribute name", key)
    rest = substr(raw, equals + 1)
    sub(/^[ \t\r\n]+/, "", rest)
    if (substr(rest, 1, 1) != "\"") refuse("attribute quote", key)
    quote_end = index(substr(rest, 2), "\"")
    if (quote_end == 0) refuse("unterminated attribute", key)
    value = substr(rest, 2, quote_end - 1)
    if (value ~ /</ || !entities_valid(value)) refuse("attribute value", key)
    rest = substr(rest, quote_end + 2)
    if (length(rest) != 0 && rest !~ /^[ \t\r\n]/) refuse("attribute separator", key)
    if (allowed_attribute(tag, key)) {
      if (attribute_seen[key] == attribute_generation) refuse("duplicate attribute", key)
      attribute_seen[key] = attribute_generation
      result = result " " key "=\"" value "\""
    }
    raw = trim(rest)
  }
  return result
}
function valid_parent(name, parent) {
  if (name == "testsuites") return parent == ""
  if (name == "testsuite") return parent == "testsuites"
  if (name == "testcase") return parent == "testsuite"
  return parent == "testcase"
}
{
  document = document $0 "\n"
}
END {
  position = 1
  depth = 0
  roots = 0
  declaration_seen = 0
  output = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
  while (position <= length(document)) {
    relative = index(substr(document, position), "<")
    if (relative == 0) {
      text = substr(document, position)
      if (depth == 0 && trim(text) != "") refuse("text outside root", trim(text))
      position = length(document) + 1
      break
    }
    opening = position + relative - 1
    text = substr(document, position, opening - position)
    if (depth == 0 && trim(text) != "") refuse("text outside root", trim(text))

    quoted = 0
    closing = 0
    for (cursor = opening + 1; cursor <= length(document); cursor++) {
      character = substr(document, cursor, 1)
      if (character == "\"") quoted = !quoted
      else if (character == ">" && !quoted) {
        closing = cursor
        break
      }
    }
    if (closing == 0 || quoted) refuse("unterminated tag", substr(document, opening, 80))
    content = trim(substr(document, opening + 1, closing - opening - 1))
    position = closing + 1
    if (content == "") refuse("empty tag", "<>")

    if (substr(content, 1, 1) == "?") {
      if (content != "?xml version=\"1.0\" encoding=\"UTF-8\"?" ||
          declaration_seen || roots || depth)
        refuse("processing instruction", content)
      declaration_seen = 1
      continue
    }
    if (substr(content, 1, 1) == "!") refuse("declaration", content)

    if (substr(content, 1, 1) == "/") {
      name = trim(substr(content, 2))
      if (name !~ /^[A-Za-z_][A-Za-z0-9_.:-]*$/) refuse("closing tag", name)
      if (depth == 0 || stack_name[depth] != name) refuse("mismatched closing tag", name)
      if (stack_emit[depth]) output = output indent(depth - 1) "</" name ">\n"
      delete stack_name[depth]
      delete stack_emit[depth]
      delete stack_drop[depth]
      depth--
      continue
    }

    self_closing = 0
    if (substr(content, length(content), 1) == "/") {
      self_closing = 1
      content = trim(substr(content, 1, length(content) - 1))
    }
    split_at = match(content, /[ \t\r\n]/)
    if (split_at == 0) {
      name = content
      raw_attributes = ""
    } else {
      name = substr(content, 1, split_at - 1)
      raw_attributes = substr(content, split_at)
    }
    if (name !~ /^[A-Za-z_][A-Za-z0-9_.:-]*$/) refuse("opening tag", name)
    parent_dropped = depth > 0 && stack_drop[depth]
    drop = parent_dropped || dropped_tag(name)
    if (depth == 0 && drop) refuse("dropped root", name)
    if (!drop) {
      if (!allowed_tag(name)) refuse("unexpected JUnit element", name)
      parent = depth == 0 ? "" : stack_name[depth]
      if (!valid_parent(name, parent)) refuse("invalid parent", parent " -> " name)
      attributes = sanitized_attributes(raw_attributes, name)
      output = output indent(depth) "<" name attributes
      if (self_closing) output = output "/>\n"
      else output = output ">\n"
      if (depth == 0) roots++
    }
    if (!self_closing) {
      depth++
      stack_name[depth] = name
      stack_emit[depth] = !drop
      stack_drop[depth] = drop
    }
  }
  if (depth != 0) refuse("unclosed tag", stack_name[depth])
  if (roots != 1) refuse("root count", roots)
  printf "%s", output
}
' "$source_path" >"$temporary"; then
  exit 1
fi

sync -f "$temporary"
mv -fT -- "$temporary" "$destination"
sync -f "$destination_dir"
trap - EXIT
