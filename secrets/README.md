# 高安全环境可选配置

普通单机部署不需要使用本目录：容器会自动把 Session 密钥和 AES 密钥生成到持久化的 `data/` 目录。

如果开启 `OPS_SSH_STRICT_HOST_KEY=1`，可自行挂载核对过的 `known_hosts` 到容器运行用户的 `/home/ops/.ssh/known_hosts`。

如需手工准备 AES 密钥，可创建 32 字节原始文件，并通过 `OPS_AES_KEY_FILE` 指定路径：

```bash
mkdir -p secrets/ssh
python -c "import os; open('secrets/ops_aes_key', 'wb').write(os.urandom(32))"
chown root:1000 secrets/ops_aes_key
chmod 640 secrets/ops_aes_key
```

这里的组 ID `1000` 必须与 `.env` 中的 `OPS_GID` 一致。Compose 的本地 secret 实际通过只读 bind mount 提供；密钥需要对容器运行组可读，但不应对其他用户开放。

`ops_aes_key` 必须随数据库一起备份，重新部署时继续使用同一文件；更换后，数据库中已有的服务器密码和模型 API Key 将无法解密。

启用 SSH 严格主机指纹验证前，把目标服务器公钥写入 `secrets/ssh/known_hosts`，例如：

```bash
ssh-keyscan -H 10.0.0.10 >> secrets/ssh/known_hosts
chmod 644 secrets/ssh/known_hosts
```

请通过可信网络或线下渠道核对 `ssh-keyscan` 得到的指纹。
