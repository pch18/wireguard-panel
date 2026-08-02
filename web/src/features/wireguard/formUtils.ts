export function linesToValues(value: string) {
  return value
    .split(/[\n,]/)
    .map((part) => part.trim())
    .filter(Boolean);
}

export function valuesToLines(values: string[]) {
  return values.join("\n");
}

export function valuesToInline(values: string[]) {
  return values.join(", ");
}

export function digitsOnly(value: string) {
  return value.replace(/[^0-9]/g, "");
}

export function interfaceNameOnly(value: string) {
  return value.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 15);
}

export function nextInterfaceName(existingNames: Iterable<string>) {
  const names = new Set(existingNames);
  let index = 0;
  while (names.has(`wg${index}`)) index += 1;
  return `wg${index}`;
}
