import { useEffect, useRef, useState } from "react";
import Icon from "../../ui/Icon";
import { useToast } from "../../ui/Toast";
import {
  deriveWireGuardPublicKey,
  generateWireGuardKeyPair,
} from "./browserKeys";
import { isWireGuardKey, wireGuardKeyOnly } from "./keyUtils";

type WireGuardKeyEditorProps = {
  idPrefix: string;
  privateKey: string;
  publicKey: string;
  privateRequired: boolean;
  publicEditable: boolean;
  autoGenerate?: boolean;
  allowRegenerate?: boolean;
  regenerateLabel?: string;
  regenerateInPrivateHeader?: boolean;
  showPublicKey?: boolean;
  privatePlaintext?: boolean;
  className?: string;
  onRegenerateRequest?(): void;
  onChange(privateKey: string, publicKey: string): void;
};

export default function WireGuardKeyEditor({
  idPrefix,
  privateKey,
  publicKey,
  privateRequired,
  publicEditable,
  autoGenerate = false,
  allowRegenerate = false,
  regenerateLabel = "重新生成密钥对",
  regenerateInPrivateHeader = false,
  showPublicKey = true,
  privatePlaintext = false,
  className = "",
  onRegenerateRequest,
  onChange,
}: WireGuardKeyEditorProps) {
  const { showToast } = useToast();
  const [showPrivateKey, setShowPrivateKey] = useState(false);
  const [generationPending, setGenerationPending] = useState(false);
  const [derivePending, setDerivePending] = useState(false);
  const [derivedPublicKey, setDerivedPublicKey] = useState("");
  const resolvedPrivateKey = useRef("");
  const privateInputRef = useRef<HTMLInputElement>(null);
  const publicInputRef = useRef<HTMLInputElement>(null);
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  const trimmedPrivateKey = privateKey.trim();
  const trimmedPublicKey = publicKey.trim();
  const privateKeyInvalid =
    trimmedPrivateKey !== "" && !isWireGuardKey(trimmedPrivateKey);
  const publicKeyInvalid =
    trimmedPublicKey !== "" && !isWireGuardKey(trimmedPublicKey);
  const keyPairMismatch =
    trimmedPrivateKey !== "" &&
    derivedPublicKey !== "" &&
    trimmedPublicKey !== derivedPublicKey;

  useEffect(() => {
    if (!autoGenerate) return;
    let active = true;
    setGenerationPending(true);
    void generateWireGuardKeyPair()
      .then((pair) => {
        if (!active) return;
        resolvedPrivateKey.current = pair.privateKey;
        setDerivedPublicKey(pair.publicKey);
        onChangeRef.current(pair.privateKey, pair.publicKey);
      })
      .catch((error) => {
        if (active) {
          showToast(
            error instanceof Error ? error.message : "WireGuard 密钥生成失败",
            "error",
          );
        }
      })
      .finally(() => {
        if (active) setGenerationPending(false);
      });
    return () => {
      active = false;
    };
  }, [autoGenerate, showToast]);

  useEffect(() => {
    if (
      !isWireGuardKey(trimmedPrivateKey) ||
      trimmedPrivateKey === resolvedPrivateKey.current
    ) {
      if (!trimmedPrivateKey || !isWireGuardKey(trimmedPrivateKey)) {
        setDerivedPublicKey("");
      }
      setDerivePending(false);
      return;
    }
    let active = true;
    setDerivePending(true);
    const timer = window.setTimeout(() => {
      void deriveWireGuardPublicKey(trimmedPrivateKey)
        .then((nextPublicKey) => {
          if (!active) return;
          resolvedPrivateKey.current = trimmedPrivateKey;
          setDerivedPublicKey(nextPublicKey);
          if (!publicEditable) {
            onChangeRef.current(trimmedPrivateKey, nextPublicKey);
          }
        })
        .catch((error) => {
          if (active) {
            showToast(
              error instanceof Error ? error.message : "无法从私钥推导公钥",
              "error",
            );
          }
        })
        .finally(() => {
          if (active) setDerivePending(false);
        });
    }, 180);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [publicEditable, showToast, trimmedPrivateKey]);

  const regenerate = async () => {
    setGenerationPending(true);
    try {
      const pair = await generateWireGuardKeyPair();
      resolvedPrivateKey.current = pair.privateKey;
      setDerivedPublicKey(pair.publicKey);
      onChangeRef.current(pair.privateKey, pair.publicKey);
    } catch (error) {
      showToast(
        error instanceof Error ? error.message : "WireGuard 密钥生成失败",
        "error",
      );
    } finally {
      setGenerationPending(false);
    }
  };

  const requestRegeneration = () => {
    if (onRegenerateRequest) {
      onRegenerateRequest();
      return;
    }
    void regenerate();
  };

  const privateValidation = privateKeyInvalid
    ? "PrivateKey 必须是 WireGuard 使用的 32 字节 Base64 密钥"
    : keyPairMismatch
      ? "PrivateKey 与 PublicKey 不是同一个 WireGuard 密钥对"
      : "";
  const publicValidation = publicKeyInvalid
    ? "PublicKey 必须是 WireGuard 使用的 32 字节 Base64 密钥"
    : "";

  useEffect(() => {
    privateInputRef.current?.setCustomValidity(privateValidation);
  }, [privateValidation]);

  useEffect(() => {
    publicInputRef.current?.setCustomValidity(publicValidation);
  }, [publicValidation]);

  return (
    <div className={`wireguard-key-editor ${className}`.trim()}>
      {allowRegenerate && !regenerateInPrivateHeader && (
        <div className="key-editor-actions">
          <button
            className="button is-quiet"
            type="button"
            disabled={generationPending}
            onClick={requestRegeneration}
          >
            {generationPending ? (
              <span className="spinner is-small" />
            ) : (
              <Icon name="refresh" />
            )}
            {generationPending ? "生成中" : regenerateLabel}
          </button>
        </div>
      )}

      <div className="field">
        <div className="field-label-row">
          <label htmlFor={`${idPrefix}-private-key`}>
            PrivateKey
            {privateRequired && <span aria-hidden="true"> *</span>}
          </label>
          <span className="private-key-actions">
            {allowRegenerate && regenerateInPrivateHeader && (
              <button
                className="button is-quiet key-rotate-button"
                type="button"
                disabled={generationPending}
                onClick={requestRegeneration}
              >
                {generationPending ? (
                  <span className="spinner is-small" />
                ) : (
                  <Icon name="refresh" />
                )}
                {generationPending ? "生成中" : regenerateLabel}
              </button>
            )}
          </span>
        </div>
        <div className="secret-input">
          <input
            ref={privateInputRef}
            id={`${idPrefix}-private-key`}
            type={privatePlaintext || showPrivateKey ? "text" : "password"}
            value={privateKey}
            required={privateRequired}
            autoComplete="new-password"
            aria-invalid={Boolean(privateValidation) || undefined}
            placeholder={
              privateRequired
                ? "32 字节 Base64 私钥"
                : "可选"
            }
            onInvalid={() => {
              showToast(privateValidation || "PrivateKey 不能为空", "error");
            }}
            onChange={(event) => {
              const nextPrivateKey = wireGuardKeyOnly(event.target.value);
              resolvedPrivateKey.current = "";
              setDerivedPublicKey("");
              onChangeRef.current(
                nextPrivateKey,
                publicEditable
                  ? publicKey
                  : nextPrivateKey.trim() === ""
                    ? publicKey
                    : "",
              );
            }}
          />
          {!privatePlaintext && (
            <button
              className="icon-button"
              type="button"
              aria-label={showPrivateKey ? "隐藏私钥" : "显示私钥"}
              onClick={() => setShowPrivateKey((shown) => !shown)}
            >
              <Icon name={showPrivateKey ? "eye-off" : "eye"} />
            </button>
          )}
        </div>
        {privateValidation && (
          <small className={privateValidation ? "field-error" : ""}>
            {privateValidation}
          </small>
        )}
      </div>

      {showPublicKey && (publicEditable ? (
        <div className="field">
          <label htmlFor={`${idPrefix}-public-key`}>
            PublicKey <span aria-hidden="true">*</span>
          </label>
          <input
            ref={publicInputRef}
            id={`${idPrefix}-public-key`}
            value={publicKey}
            required
            autoComplete="off"
            aria-invalid={publicKeyInvalid || undefined}
            placeholder="Peer 的 32 字节 Base64 公钥"
            onInvalid={() => {
              showToast(publicValidation || "PublicKey 不能为空", "error");
            }}
            onChange={(event) =>
              onChangeRef.current(
                privateKey,
                wireGuardKeyOnly(event.target.value),
              )
            }
          />
          {publicValidation && (
            <small className="field-error">
              {publicValidation}
            </small>
          )}
        </div>
      ) : (
        <div className="field" aria-live="polite">
          <label htmlFor={`${idPrefix}-public-key`}>PublicKey</label>
          <input
            ref={publicInputRef}
            id={`${idPrefix}-public-key`}
            value={publicKey}
            disabled
            placeholder={derivePending ? "正在推导…" : "根据 PrivateKey 自动生成"}
          />
        </div>
      ))}
    </div>
  );
}
