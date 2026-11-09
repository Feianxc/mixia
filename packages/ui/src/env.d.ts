/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** 构建时写入的默认服务器地址，自己部署时用，见 docs/部署与运维.md。不设时第一次使用要手动填写 */
  readonly VITE_MIXIA_DEFAULT_SERVER?: string;
}
