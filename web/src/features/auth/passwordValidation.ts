export function validatePasswordChange(
  currentPassword: string,
  newPassword: string,
  confirmation: string,
) {
  if (Array.from(newPassword).length < 8) {
    return "新密码至少需要 8 个字符";
  }
  if (new TextEncoder().encode(newPassword).length > 72) {
    return "新密码不能超过 72 字节";
  }
  if (newPassword === currentPassword) {
    return "新密码不能与当前密码相同";
  }
  if (newPassword !== confirmation) {
    return "两次输入的新密码不一致";
  }
  return "";
}
