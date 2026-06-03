$src = Get-Content c:\www\rust\quiche\quiche\src\h3\qpack\static_table.rs -Raw
$decStart = $src.IndexOf('pub const STATIC_DECODE_TABLE')
$decBlock = $src.Substring($decStart)
$openIdx = $decBlock.IndexOf('= [') + 2
$lvl = 0
$end = -1
for ($i = $openIdx; $i -lt $decBlock.Length; $i++) {
  $c = $decBlock[$i]
  if ($c -eq '[') { $lvl++ }
  elseif ($c -eq ']') { $lvl--; if ($lvl -eq 0) { $end = $i; break } }
}
$body = $decBlock.Substring($openIdx + 1, $end - $openIdx - 1)
$pattern = [regex]'\(\s*b"((?:[^"\\]|\\.)*)"\s*,\s*b"((?:[^"\\]|\\.)*)"\s*,?\s*\)'
$ms = $pattern.Matches($body)
"matches: $($ms.Count)"

$out = New-Object System.Text.StringBuilder
[void]$out.AppendLine("// Copyright (C) 2018-2026, Cloudflare, Inc.")
[void]$out.AppendLine("// SPDX-License-Identifier: BSD-2-Clause")
[void]$out.AppendLine("//")
[void]$out.AppendLine("// QPACK static table (RFC 9204 Appendix A). Mechanically extracted from")
[void]$out.AppendLine("// quiche's quiche/src/h3/qpack/static_table.rs STATIC_DECODE_TABLE.")
[void]$out.AppendLine("")
[void]$out.AppendLine("import 'dart:typed_data';")
[void]$out.AppendLine("")
[void]$out.AppendLine("class StaticTableEntry {")
[void]$out.AppendLine("  final Uint8List name;")
[void]$out.AppendLine("  final Uint8List value;")
[void]$out.AppendLine("  const StaticTableEntry(this.name, this.value);")
[void]$out.AppendLine("}")
[void]$out.AppendLine("")
[void]$out.AppendLine("final List<StaticTableEntry> staticDecodeTable = [")
foreach ($m in $ms) {
  $name = $m.Groups[1].Value
  $value = $m.Groups[2].Value
  # Escape for Dart single-quoted strings.
  $nameEsc = $name.Replace('\', '\\').Replace("'", "\'")
  $valueEsc = $value.Replace('\', '\\').Replace("'", "\'")
  [void]$out.AppendLine("  StaticTableEntry(Uint8List.fromList('$nameEsc'.codeUnits), Uint8List.fromList('$valueEsc'.codeUnits)),")
}
[void]$out.AppendLine("];")
[void]$out.AppendLine("")
[void]$out.AppendLine("/// Looks up `(name, value)` in the static table.")
[void]$out.AppendLine("///")
[void]$out.AppendLine("/// Returns `(index, fullMatch)` where `fullMatch` is true when both the")
[void]$out.AppendLine("/// name (case-insensitive ASCII) and value (case-sensitive) match an entry,")
[void]$out.AppendLine("/// false when only the name matches (returns the first name match). Returns")
[void]$out.AppendLine("/// null if no entry has a matching name.")
[void]$out.AppendLine("(int, bool)? lookupStatic(List<int> name, List<int> value) {")
[void]$out.AppendLine("  int? firstNameMatch;")
[void]$out.AppendLine("  for (var i = 0; i < staticDecodeTable.length; i++) {")
[void]$out.AppendLine("    final entry = staticDecodeTable[i];")
[void]$out.AppendLine("    if (!_asciiEqIgnoreCase(entry.name, name)) continue;")
[void]$out.AppendLine("    if (_bytesEq(entry.value, value)) return (i, true);")
[void]$out.AppendLine("    firstNameMatch ??= i;")
[void]$out.AppendLine("  }")
[void]$out.AppendLine("  if (firstNameMatch != null) return (firstNameMatch, false);")
[void]$out.AppendLine("  return null;")
[void]$out.AppendLine("}")
[void]$out.AppendLine("")
[void]$out.AppendLine("bool _bytesEq(List<int> a, List<int> b) {")
[void]$out.AppendLine("  if (a.length != b.length) return false;")
[void]$out.AppendLine("  for (var i = 0; i < a.length; i++) {")
[void]$out.AppendLine("    if (a[i] != b[i]) return false;")
[void]$out.AppendLine("  }")
[void]$out.AppendLine("  return true;")
[void]$out.AppendLine("}")
[void]$out.AppendLine("")
[void]$out.AppendLine("bool _asciiEqIgnoreCase(List<int> lower, List<int> b) {")
[void]$out.AppendLine("  if (lower.length != b.length) return false;")
[void]$out.AppendLine("  for (var i = 0; i < lower.length; i++) {")
[void]$out.AppendLine("    var x = b[i];")
[void]$out.AppendLine("    if (x >= 0x41 && x <= 0x5A) x |= 0x20;")
[void]$out.AppendLine("    if (lower[i] != x) return false;")
[void]$out.AppendLine("  }")
[void]$out.AppendLine("  return true;")
[void]$out.AppendLine("}")

Set-Content -Path c:\www\dart\dart-quiche\lib\src\qpack_static_table.dart -Value $out.ToString() -NoNewline
"wrote $((Get-Item c:\www\dart\dart-quiche\lib\src\qpack_static_table.dart).Length) bytes"
