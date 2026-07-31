export function linesToValues(value: string) {
  return value
    .split(/[\n,]/)
    .map((part) => part.trim())
    .filter(Boolean);
}

export function valuesToLines(values: string[]) {
  return values.join("\n");
}
