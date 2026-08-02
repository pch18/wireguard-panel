import { useState, type FormEvent } from "react";
import { ApiError } from "../../app/apiClient";
import Modal from "../../ui/Modal";
import { useToast } from "../../ui/Toast";
import { changePassword } from "./api";
import { validatePasswordChange } from "./passwordValidation";

type ChangePasswordModalProps = {
  onClose(): void;
};

export default function ChangePasswordModal({
  onClose,
}: ChangePasswordModalProps) {
  const { showToast, updateToast } = useToast();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [currentInvalid, setCurrentInvalid] = useState(false);
  const [newPasswordError, setNewPasswordError] = useState("");
  const [pending, setPending] = useState(false);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setCurrentInvalid(false);
    setNewPasswordError("");

    const validationError = validatePasswordChange(
      currentPassword,
      newPassword,
      confirmation,
    );
    if (validationError) {
      setNewPasswordError(validationError);
      showToast(validationError, "warning");
      return;
    }

    setPending(true);
    const toastID = showToast("正在保存新密码…", "loading", 0);
    try {
      await changePassword(currentPassword, newPassword);
      updateToast(toastID, "密码已修改，其他会话已退出", "success");
      onClose();
    } catch (error) {
      if (
        error instanceof ApiError &&
        error.code === "invalid_current_password"
      ) {
        setCurrentInvalid(true);
      }
      updateToast(
        toastID,
        error instanceof Error ? error.message : "密码修改失败",
        "error",
      );
    } finally {
      setPending(false);
    }
  };

  return (
    <Modal
      title="修改登录密码"
      description="保存后，其他登录会话将退出。"
      variant="input"
      closeDisabled={pending}
      onClose={onClose}
      className="is-compact"
    >
      <form className="modal-form password-form" onSubmit={submit}>
        <label htmlFor="current-password">
          当前密码
          <input
            id="current-password"
            name="currentPassword"
            type="password"
            value={currentPassword}
            autoComplete="current-password"
            autoFocus
            required
            disabled={pending}
            aria-invalid={currentInvalid}
            onChange={(event) => {
              setCurrentPassword(event.target.value);
              setCurrentInvalid(false);
            }}
          />
        </label>
        <div className="validation-slot" aria-live="polite">
          {currentInvalid ? "当前密码错误" : ""}
        </div>

        <label htmlFor="new-password">
          新密码
          <input
            id="new-password"
            name="newPassword"
            type="password"
            value={newPassword}
            autoComplete="new-password"
            required
            disabled={pending}
            aria-invalid={Boolean(newPasswordError)}
            onChange={(event) => {
              setNewPassword(event.target.value);
              setNewPasswordError("");
            }}
          />
          <span className="field-hint">至少 8 个字符，最多 72 字节</span>
        </label>

        <label htmlFor="confirm-password">
          确认新密码
          <input
            id="confirm-password"
            name="confirmPassword"
            type="password"
            value={confirmation}
            autoComplete="new-password"
            required
            disabled={pending}
            aria-invalid={Boolean(newPasswordError)}
            onChange={(event) => {
              setConfirmation(event.target.value);
              setNewPasswordError("");
            }}
          />
        </label>
        <div className="validation-slot" aria-live="polite">
          {newPasswordError}
        </div>

        <footer className="modal-actions">
          <button
            className="button"
            type="button"
            disabled={pending}
            onClick={onClose}
          >
            取消
          </button>
          <button className="button is-primary" type="submit" disabled={pending}>
            {pending && <span className="spinner is-small" />}
            {pending ? "保存中" : "保存新密码"}
          </button>
        </footer>
      </form>
    </Modal>
  );
}
