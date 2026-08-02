import AllowedIPsEditor from "./AllowedIPsEditor";

type InterfaceAddressEditorProps = {
  initialValues: string[];
  allowedRanges?: string[];
  showBlankRowWhenEmpty?: boolean;
  onChange(values: string[], complete: boolean): void;
};

export default function InterfaceAddressEditor({
  initialValues,
  allowedRanges,
  showBlankRowWhenEmpty,
  onChange,
}: InterfaceAddressEditorProps) {
  return (
    <AllowedIPsEditor
      mode="interface"
      initialValues={initialValues}
      allowedRanges={allowedRanges}
      showBlankRowWhenEmpty={showBlankRowWhenEmpty}
      onChange={onChange}
    />
  );
}
