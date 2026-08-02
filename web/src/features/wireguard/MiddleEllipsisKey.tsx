type Props = {
  value: string;
};

export default function MiddleEllipsisKey({ value }: Props) {
  const tailLength = Math.min(8, value.length);
  const splitAt = value.length - tailLength;

  return (
    <code className="peer-middle-ellipsis-key" aria-label={value}>
      <span>{value.slice(0, splitAt)}</span>
      <span>{value.slice(splitAt)}</span>
    </code>
  );
}
