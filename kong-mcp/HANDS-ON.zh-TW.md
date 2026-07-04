# kong-mcp 安裝與驗證手冊（macOS 實機操作版）

這份手冊帶你在 **macOS** 上，從零把 `mcp-signet` plugin 跑起來，並用一個本機
測試簽發者（test issuer）完整走完 MCP OAuth 握手，逐列驗證安全性質——**不需要
真的 Signet**。

> 本手冊的每個指令都在 Apple Silicon（M1 Max / arm64）+ colima + Docker 24
> 上實機跑過。Intel Mac 請把 `GOARCH=arm64` 改成 `GOARCH=amd64`。

產品說明、設定欄位、設計理由請看 [README.md](README.md) / [README.zh-TW.md](README.zh-TW.md)。
這裡只談「怎麼一步步跑起來並驗證」。

---

## 0. 前置需求

| 工具           | 確認指令                                             | 備註                                                         |
| -------------- | ---------------------------------------------------- | ------------------------------------------------------------ |
| Go 1.25.10+    | `go version`                                         | 編譯 plugin 與 test issuer（`go.mod` 的 `go` 指令為 1.25.10）|
| Docker         | `docker version`                                     | Docker Desktop、colima、OrbStack 皆可                        |
| Docker Compose | `docker compose version` 或 `docker-compose version` | v2 即可。本機若只有獨立版 `docker-compose`，下面指令照用即可 |
| curl / openssl | 內建                                                 | 驗證用                                                       |
| python3        | 內建                                                 | 只用來把 JSON 印得好看，非必要                               |

> **colima 使用者**：先確認 daemon 起來了（`colima status`，沒有就 `colima start`）。
> 本手冊用到的 `host.docker.internal`（容器連回 macOS host）在 colima / 一般
> dockerd 上預設沒有，靠 compose 檔裡的 `extra_hosts: host.docker.internal:host-gateway`
> 補上——已經幫你寫好，不用改。

切到範例目錄：

```bash
cd kong-mcp
```

---

## 1. 為什麼有「本機版」compose 檔

倉庫附的 [`docker-compose.yml`](docker-compose.yml) 走 [`Dockerfile`](Dockerfile)，
**在 Docker 內** `go mod download` 再編譯 plugin。這在一般網路沒問題，但若你在
**有 TLS 攔截 proxy 的公司網路**（例如憑證被替換），Docker build 會卡在：

```bash
go: github.com/Kong/go-pdk@v0.11.0: ... tls: failed to verify certificate:
x509: certificate signed by unknown authority
```

因為 BuildKit 容器內不帶你 macOS 的企業根憑證。為了繞過這點、也讓驗證更快，本
手冊改用 **本機交叉編譯 + 把 binary 掛進現成 `kong:3.9` image** 的方式，對應檔案：

- [`docker-compose.local.yml`](docker-compose.local.yml)：掛載本機編好的 binary，
  並補上 `host.docker.internal` 與 test-issuer 設定。
- [`kong.local.yml`](kong.local.yml)：把 plugin 指向本機 test issuer 的設定
  （正式設定請看 [`kong.yml`](kong.yml) 的 placeholder）。

> 公司網路沒有攔截 proxy 的話，你也可以直接 `docker compose up --build` 走原始
> 流程，跳過第 2 步的交叉編譯；但仍需要第 3 步的 test issuer 才能驗證 token。

---

## 2. 編譯 plugin

go-pdk plugin 是一支普通的執行檔（講 pluginserver RPC，無 cgo、無 `.so`）。

**本機自用 / 手動 smoke test：**

```bash
go mod tidy
go build -o mcp-signet .
./mcp-signet -dump | head        # 應印出 plugin schema（JSON）
```

**給 Linux 容器掛載用（本手冊主線）——交叉編譯：**

```bash
# Apple Silicon：
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o mcp-signet-linux .
# Intel Mac：把 arm64 換成 amd64
file mcp-signet-linux   # 應顯示 ELF 64-bit ... ARM aarch64（或 x86-64）
```

> `GOARCH` 要對齊 **Docker VM 的架構**，不是你 shell 的架構。Apple Silicon 上的
> colima / Docker Desktop 預設跑 arm64 VM，所以用 `arm64`。

---

## 3. 啟動本機 test issuer（假 Signet）

倉庫附了一個本機簽發者 [`../go-jwks-multi/testissuer`](../go-jwks-multi/testissuer)：
啟動時產生一對 RSA-2048 金鑰，提供 OIDC discovery、JWKS，以及一個 `/sign` 端點
讓你任意鑄造 RS256 JWT。**它會幫你簽任何東西，純測試用，只綁 loopback、絕不可
對外。** 鑄出的 token 預設帶 `type=access`（plugin 只接受 access token）；想看
plugin 擋掉非 access token，在 Row 3 的 `/sign` 指令多加一行
`--data-urlencode 'type=refresh'` 重打會拿到 401。

> **`aud` 必帶**：`kong.local.yml` 兩條路由都開了 `require_audience: true`
> （出廠即啟用），預期 `aud` = `gateway_origin + resource_path`。test issuer 的
> 預設 `aud` 是 `https://api.example.com`，**不帶 `aud=` 鑄出來的 token 一律
> 401**——所以下面每個需要有效 token 的指令都帶了
> `aud=http://localhost:8000/mcp/gitea`（或 `/mcp/sentry`）。

開一個**新終端機分頁**，讓它在前景跑：

```bash
cd ../go-jwks-multi
go run ./testissuer
```

看到這樣就成功了（`auth-a` 在 `:9001`，`auth-b` 在 `:9002`）：

```
issuer "auth-a" on http://127.0.0.1:9001  (kid=auth-a-...)
issuer "auth-b" on http://127.0.0.1:9002  (kid=auth-b-...)
```

快速確認 JWKS 出得來：

```bash
curl -s http://127.0.0.1:9001/jwks.json | head -c 120; echo
```

> **issuer 與 jwks_uri 的關鍵差異**（已寫進 `kong.local.yml`）：
> - `issuer`：拿來跟 token 的 `iss` claim **逐字元比對**。test issuer 鑄的 token
>   `iss` 是 `http://127.0.0.1:9001`，所以設定也填這個。
> - `jwks_uri`：由 **Kong 容器**去抓金鑰，所以要填**容器連得到 host** 的位址——
>   `http://host.docker.internal:9001/jwks.json`，不能用 `127.0.0.1`（那是容器自己）。

---

## 4. 啟動 Kong demo stack

回到 `kong-mcp` 目錄，用本機版 compose 啟動（DB-less Kong + 兩個 stub MCP upstream）：

```bash
cd ../kong-mcp
docker-compose -f docker-compose.local.yml up -d
# 若你的 Docker 有 compose v2 子指令，等價於：
#   docker compose -f docker-compose.local.yml up -d
```

確認三個容器都 Up：

```bash
docker-compose -f docker-compose.local.yml ps
```

- proxy（MCP 流量入口）：`http://localhost:8000`
- admin API：**只綁容器內 loopback、不對外發布**（未認證、可整份換掉設定）。需要
  除錯時用 `docker exec <kong 容器> curl http://127.0.0.1:8001/...`。

看 plugin 有沒有正常掛載：

```bash
docker-compose -f docker-compose.local.yml logs kong | grep -i pluginserver
# 應看到 "loading protocol ProtoBuf:1 for plugin mcp-signet"
```

---

## 5. 驗證矩陣（逐列實測）

設一個方便的變數：

```bash
GW=http://localhost:8000
```

### Row 1 — 沒帶 token → 401 挑戰

```bash
curl -si $GW/mcp/gitea | sed -n '1p;/WWW-Authenticate/p'
```

預期：

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="http://localhost:8000/.well-known/oauth-protected-resource/mcp/gitea"
```

### Row 2 — PRM 文件（Protected Resource Metadata, RFC 9728）

```bash
curl -s $GW/.well-known/oauth-protected-resource/mcp/gitea
```

預期（含 `resource`、`authorization_servers`、`scopes_supported`）：

```json
{"authorization_servers":["http://127.0.0.1:9001"],"bearer_methods_supported":["header"],"resource":"http://localhost:8000/mcp/gitea","scopes_supported":["mcp:gitea"]}
```

### Row 3 — 有效 token → 轉發到 upstream（200）

向 test issuer 鑄一顆帶正確 scope **與正確 `aud`** 的 token，再打 gitea 路由：

```bash
GOOD=$(curl -sG 'http://127.0.0.1:9001/sign' \
  --data-urlencode 'scope=mcp:gitea' \
  --data-urlencode 'sub=alice' \
  --data-urlencode 'aud=http://localhost:8000/mcp/gitea')
curl -si $GW/mcp/gitea -H "Authorization: Bearer $GOOD" | sed -n '1p;$p'
```

預期：

```
HTTP/1.1 200 OK
hello from mcp-gitea
```

### Row 4 — 過期 token → 401

`kong.local.yml` 設了 `leeway_seconds: 60`（容忍 60 秒時鐘誤差），所以要真的過期
**得超過 ttl + 60 秒**。鑄一顆 5 秒 token，等 70 秒：

```bash
EXP=$(curl -sG 'http://127.0.0.1:9001/sign' \
  --data-urlencode 'scope=mcp:gitea' \
  --data-urlencode 'ttl=5' \
  --data-urlencode 'aud=http://localhost:8000/mcp/gitea')
sleep 70
curl -si $GW/mcp/gitea -H "Authorization: Bearer $EXP" | sed -n '1p;$p'
```

預期：

```
HTTP/1.1 401 Unauthorized
{"error":"invalid_token","error_description":"invalid or expired access token"}
```

### Row 5a — 缺少必要 scope → 403

`aud` 給對（先通過 aud 檢查），但 scope 故意給錯——才能驗到的是 **scope** 那一關：

```bash
NOSCOPE=$(curl -sG 'http://127.0.0.1:9001/sign' \
  --data-urlencode 'scope=email' \
  --data-urlencode 'sub=alice' \
  --data-urlencode 'aud=http://localhost:8000/mcp/gitea')
curl -si $GW/mcp/gitea -H "Authorization: Bearer $NOSCOPE" | sed -n '1p;/WWW-Authenticate/p'
```

預期（challenge 帶 `insufficient_scope` + 缺的 scope）：

```
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer resource_metadata="...", error="insufficient_scope", scope="mcp:gitea"
```

### Row 5b — audience 不符 → 401（安全關鍵）

兩條路由都開了 `require_audience: true`，各自預期 `aud` 等於
`gateway_origin + resource_path`。這列直接示範它擋下的攻擊——**跨資源重放**：
一顆綁定 gitea 的 token，scope 再對也打不進 sentry。

先拿**綁定另一個資源**的 token（`aud` 指向 gitea，scope 卻是 `mcp:sentry`）：

```bash
CROSS=$(curl -sG 'http://127.0.0.1:9001/sign' \
  --data-urlencode 'scope=mcp:sentry' \
  --data-urlencode 'aud=http://localhost:8000/mcp/gitea')
curl -si $GW/mcp/sentry -H "Authorization: Bearer $CROSS" | sed -n '1p;$p'
# 預期 401 invalid_token（aud 不符——跨資源重放被擋）
```

再用**正確的 aud**：

```bash
GOODAUD=$(curl -sG 'http://127.0.0.1:9001/sign' \
  --data-urlencode 'scope=mcp:sentry' \
  --data-urlencode 'aud=http://localhost:8000/mcp/sentry')
curl -si $GW/mcp/sentry -H "Authorization: Bearer $GOODAUD" | sed -n '1p;$p'
# 預期 200 hello from mcp-sentry
```

### Row 5c — HS256 偽造（alg confusion）→ 401（安全關鍵）

plugin 把接受的演算法 pin 在 `RS256/384/512`，任何 `HS*` 一律拒絕——擋掉「拿
RSA 公鑰當 HMAC 密鑰簽 HS256」的經典偽造。用 openssl 手刻一顆 HS256：

```bash
header=$(printf '{"alg":"HS256","typ":"JWT","kid":"x"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
payload=$(printf '{"iss":"http://127.0.0.1:9001","scope":"mcp:gitea","exp":9999999999,"sub":"attacker"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
sig=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -hmac "secret" -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
HS="$header.$payload.$sig"
curl -si $GW/mcp/gitea -H "Authorization: Bearer $HS" | sed -n '1p;$p'
```

預期：

```
HTTP/1.1 401 Unauthorized
{"error":"invalid_token","error_description":"invalid or expired access token"}
```

---

## 6. 驗證最近修掉的三個安全問題

### 6a. 偽造身分 header 會被覆寫（trust-header smuggling）

plugin 在轉發前會**先清掉** client 自帶的 `X-MCP-Subject` / `X-MCP-Scope`，再填入
**token 裡驗證過的** `sub` / `scope`。後端被告知「無條件信任這兩個 header」，所以
這道清除是身分不被偽造的關鍵。

stub 的 `http-echo` upstream 不會回放 header，要看到效果，臨時把 gitea upstream
換成會回放 header 的 echo 服務：

```bash
# 1) 在 Kong 的網路上起一個 header echo 容器
NET=$(docker inspect "$(docker-compose -f docker-compose.local.yml ps -q kong)" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}')
docker run -d --rm --name mcp-echo --network "$NET" mendhak/http-https-echo:31

# 2) 暫時把 kong.local.yml 的 gitea upstream 指到 echo，重建 kong
cp kong.local.yml /tmp/kong.local.yml.bak
sed -i '' 's#url: http://mcp-gitea:3000#url: http://mcp-echo:8080#' kong.local.yml
docker-compose -f docker-compose.local.yml up -d --force-recreate kong
sleep 8

# 3) 帶有效 token，同時偽造 X-MCP-Subject / X-MCP-Scope
GOOD=$(curl -sG 'http://127.0.0.1:9001/sign' \
  --data-urlencode 'scope=mcp:gitea' \
  --data-urlencode 'sub=alice@corp' \
  --data-urlencode 'aud=http://localhost:8000/mcp/gitea')
curl -s $GW/mcp/gitea \
  -H "Authorization: Bearer $GOOD" \
  -H "X-MCP-Subject: attacker@evil" \
  -H "X-MCP-Scope: admin:everything" \
  | python3 -c "import sys,json; h=json.load(sys.stdin)['headers']; print('x-mcp-subject ->', h.get('x-mcp-subject')); print('x-mcp-scope   ->', h.get('x-mcp-scope'))"
```

預期——偽造值被丟棄，換成 token 裡的真實身分：

```
x-mcp-subject -> alice@corp
x-mcp-scope   -> mcp:gitea
```

還原設定、清掉 echo 容器：

```bash
cp /tmp/kong.local.yml.bak kong.local.yml
docker rm -f mcp-echo
docker-compose -f docker-compose.local.yml up -d --force-recreate kong
```

### 6b. 重複 Authorization header → 400

```bash
GOOD=$(curl -sG 'http://127.0.0.1:9001/sign' \
  --data-urlencode 'scope=mcp:gitea' \
  --data-urlencode 'sub=alice' \
  --data-urlencode 'aud=http://localhost:8000/mcp/gitea')
curl -si $GW/mcp/gitea \
  -H "Authorization: Bearer $GOOD" \
  -H "Authorization: token stolen-pat" | sed -n '1p'
# 預期 HTTP/1.1 400 Bad Request
```

> **觀察到的細節**：在 Kong 前面，底層 nginx 會在 plugin 執行**之前**就以 400
> 擋掉重複的 `Authorization` header（回應是 Kong 的通用 `{"message":"Bad request"}`、
> 帶 `Connection: close`、沒有 `WWW-Authenticate`）。plugin 內的多值檢查是
> **深度防禦**——在非 Kong 前置或 nginx 行為改變時才會由 plugin 自己回
> `400 invalid_request`。兩種情況都不會把未驗證的第二組憑證轉發出去。

### 6c. 垃圾 token → 401（不是 5xx）

```bash
curl -si $GW/mcp/gitea -H "Authorization: Bearer not.a.jwt" | sed -n '1p;$p'
# 預期 401 invalid_token
```

---

## 7. JWKS 失效時的行為（503，不是 401）

金鑰抓不到是 **gateway 端**的事，plugin 回 `503 temporarily_unavailable`（而非
401），這樣 spec-compliant 的 client 不會誤以為「token 壞了」去重跑整套 OAuth。
模擬：把 test issuer 關掉，再用一顆**沒被 cache 過的新 kid**……實務上 keyfunc 會
快取已抓到的金鑰，最直接的觀察是「placeholder 設定（`auth.example.com` 無 JWKS）
下打 Row 3 會得到 503」。在本機 test issuer 流程中，停掉 issuer 後既有金鑰仍可用，
屬於正常的高可用設計（已抓到的金鑰每小時背景刷新、抓取逾時上限 10 秒、失敗的抓取
永不被 cache）。

---

## 8. 接真 Signet（替換掉 test issuer）

前面 §3–§7 用本機 test issuer 把流程跑通。要接你**自己架的 Signet**，把 token
來源從 test issuer 換成真的 Signet 即可——倉庫附了一組現成檔案：

- [`kong.signet.yml`](kong.signet.yml)：指向真 Signet 的 plugin 設定。
- [`docker-compose.signet.yml`](docker-compose.signet.yml)：掛上面那份設定 +
  本機 binary + `host.docker.internal`。

以下以 Signet 跑在 macOS host 的 `http://localhost:8080` 為例。

### 8.1 先從 Signet 的 discovery 抓真實值

**別用猜的**——`issuer` / `jwks_uri` 一律以 discovery 文件為準：

```bash
curl -s http://localhost:8080/.well-known/openid-configuration \
  | python3 -m json.tool | grep -iE '"issuer"|jwks_uri|token_endpoint|scopes_supported'
```

範例輸出（你的可能不同，以實際為準）：

```
"issuer": "http://localhost:8080",
"jwks_uri": "http://localhost:8080/.well-known/jwks.json",
"token_endpoint": "http://localhost:8080/oauth/token",
"scopes_supported": ["openid", "profile", "email"],
```

### 8.2 唯一的雷：`localhost` vs `host.docker.internal`

換成 `http://localhost:8080`（純 HTTP）少了自簽 TLS 與 `.local` DNS 兩個麻煩，但
**還剩一個**：Kong 在容器裡，容器的 `localhost` 是它自己，不是 macOS host。所以：

| 欄位 | 值 | 為什麼 |
| --- | --- | --- |
| `issuer` | `http://localhost:8080` | 拿來跟 token 的 `iss` **逐字元比對**（plugin 不連它，只比字串） |
| `jwks_uri` | `http://host.docker.internal:8080/.well-known/jwks.json` | 由 **Kong 容器**去抓，要填容器連得到 host 的位址 |
| `gateway_origin` | `http://localhost:8000` | 不變（這是 Kong proxy，給 host 端 client / 組 PRM URL 用） |

`kong.signet.yml` 已經照這樣寫好；`docker-compose.signet.yml` 也已含
`extra_hosts: host.docker.internal:host-gateway`，**都不用改**。把 `discovery` 抓到的
`issuer` / `jwks_uri` 主機名對齊你的環境即可。

### 8.3 ⚠️ scope：Signet 沒發的 scope 一定 403

上面 `scopes_supported` 只有 `openid profile email`，**沒有 `mcp:gitea`**。若 plugin
設 `required_scopes: [mcp:gitea]`，再有效的 token 也會 `403 insufficient_scope`。
`kong.signet.yml` 已避開這點：gitea 路由 `required_scopes: []`（不檢查），sentry
路由用 `email`（Signet 真的會發）示範強制。要照產品語意用 `mcp:gitea`，得先去
Signet 端註冊並發給該 client。

### 8.4 ⚠️ aud：先把資源註冊進 client 的 `allowed_resources`

`kong.signet.yml` 兩條路由都開了 `require_audience: true`（出廠值），token 的
`aud` 必須等於 `gateway_origin + resource_path`。Signet 用 **RFC 8707 resource
binding** 發 per-resource `aud`：取 token 時帶 `resource=<該 URL>`，Signet 就把
它寫進 `aud`。但有個前提——

> Signet 對 `resource` 參數有 **per-client 白名單**（`allowed_resources`，
> **空白名單 = 全拒**）。沒先註冊就帶 `resource` 取 token，會拿到
> `400 invalid_target`（"Requested resource is not allowed for this client"）。

到 Signet 的 client 設定（dashboard 的 **Allowed Resources** 欄位，多筆用逗號
分隔），把兩個資源 URL 加進去：

```
http://localhost:8000/mcp/gitea, http://localhost:8000/mcp/sentry
```

> 除錯期間若想先排除 aud 因素，可把 `kong.signet.yml` 的 `require_audience`
> 暫時改回 `false`（改完要 `--force-recreate kong`）——**驗完記得改回來**，
> 否則 token 可跨資源重放（見 README 的重放警告）。

### 8.5 切換到 Signet stack

```bash
cd ../kong-mcp
docker-compose -f docker-compose.local.yml down          # 停掉 test-issuer stack（同一個 :8000）
docker-compose -f docker-compose.signet.yml up -d
docker-compose -f docker-compose.signet.yml logs kong | grep -i pluginserver  # 確認 plugin 載入
```

### 8.6 不用帳密就能驗「JWKS 連線通不通」

接真 Signet 最常見的失敗是 `jwks_uri` 容器連不到 → 所有 token 變 `503`。有個小
技巧能**不用任何憑證**就分辨「連線問題」還是「token 問題」：拿一顆**格式正確但簽章
對不上**的 token（例如本機 test issuer 簽的）丟進去——

```bash
# test issuer 仍在 :9001 的話（probe 用，iss 本來就對不上，aud 帶不帶都一樣）：
WELLFORMED=$(curl -s 'http://127.0.0.1:9001/sign?scope=email&sub=probe')
curl -si http://localhost:8000/mcp/gitea -H "Authorization: Bearer $WELLFORMED" | sed -n '1p;$p'
```

- 回 **`401 invalid_token`** → plugin 成功抓到 Signet 的 JWKS（只是 kid 對不上）→
  **連線 OK** ✅
- 回 **`503 temporarily_unavailable`** → JWKS 抓不到 → 檢查 `jwks_uri` 是不是用了
  `host.docker.internal`、Signet 有沒有在跑。

### 8.7 拿真 token 跑 Row 3（需要 client 憑證）

token 來源從 test issuer 的 `/sign` 換成走 OAuth。`../go-jwks/get-token.sh` 走
client_credentials 但**不支援 `resource` 參數**，而 aud 已強制檢查（§8.4），所以
直接用 curl 打 token endpoint（端點以 §8.1 discovery 的 `token_endpoint` 為準），
**一個資源換一顆 token**：

```bash
TOKEN_URL=http://localhost:8080/oauth/token

# 綁定 gitea 的 token（resource 必須已在 client 的 allowed_resources，見 §8.4）
GOOD=$(curl -s -X POST "$TOKEN_URL" \
  -d grant_type=client_credentials \
  -d client_id=<id> -d client_secret=<secret> \
  -d 'scope=email' \
  -d 'resource=http://localhost:8000/mcp/gitea' | jq -r .access_token)

curl -si http://localhost:8000/mcp/gitea  -H "Authorization: Bearer $GOOD" | sed -n '1p;$p'  # 預期 200
curl -si http://localhost:8000/mcp/sentry -H "Authorization: Bearer $GOOD" | sed -n '1p;$p'  # 預期 401（aud 綁 gitea，跨資源被擋——這正是 Row 5b）

# sentry 要另外換一顆（scope 要含 email，sentry 路由有 required_scopes）
SENTRY=$(curl -s -X POST "$TOKEN_URL" \
  -d grant_type=client_credentials \
  -d client_id=<id> -d client_secret=<secret> \
  -d 'scope=email' \
  -d 'resource=http://localhost:8000/mcp/sentry' | jq -r .access_token)
curl -si http://localhost:8000/mcp/sentry -H "Authorization: Bearer $SENTRY" | sed -n '1p;$p'  # 預期 200
```

> 想先解碼確認 claims（`aud`、`iss`、`type=access`、header `alg=RS256`）：
>
> ```bash
> echo "$GOOD" | cut -d. -f2 | python3 -c "import sys,base64,json; s=sys.stdin.read().strip(); print(json.dumps(json.loads(base64.urlsafe_b64decode(s+'='*(-len(s)%4))), indent=2, ensure_ascii=False))"
> ```

需要帶真實使用者身分（`sub`）的 token 就改用 [`../bash-cli/main.sh`](../bash-cli) 或
`../go-cli`（Auth Code / Device Code）——但同樣注意：CLI 若沒在 `/authorize`、
`/token` 請求帶 `resource` 參數，拿到的 token 不會綁 `aud`，打過來會是 401。

> **preflight 四項**（README 也有，最容易漏）：
> 1. 用的是 **access token**、不是 `id_token`——解碼後 header `alg` 必須是
>    `RS256`、`kid` 對得上 JWKS。
> 2. token 的 `iss` 與設定的 `issuer` **逐字元相同**（差一個結尾 `/` 就 401）。
> 3. token 的 `aud` 等於 `gateway_origin + resource_path`（逐字元，含 scheme 與
>    斜線）——取 token 時必須帶 `resource=`，見 §8.4。
> 4. Signet 發固定非 URL `aud` 的話，把 plugin 的 `audience` 設成該字串覆寫
>    預設比對值。

§5 的其他列（Row 1/2 挑戰與 PRM、Row 5c HS256 偽造、§6 的 6a/6b/6c）與 token 來源
無關，照跑即可——只有「需要有效 token」的 Row 3/4/5a/5b 改用上面的真 token。

---

## 9. 收尾與清理

```bash
# 停掉 Kong demo stack（依你用的那一份）
docker-compose -f docker-compose.local.yml down       # test issuer 版
docker-compose -f docker-compose.signet.yml down    # 真 Signet 版

# 停掉 test issuer：回到它的終端機分頁按 Ctrl-C

# 移除編譯產物（已被 .gitignore 忽略）
rm -f mcp-signet mcp-signet-linux
```

---

## 10. 常見問題（macOS）

| 症狀                                                                | 原因 / 解法                                                                                                                                                                                            |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `docker compose up --build` 卡在 `go mod download` 的 x509 憑證錯誤 | 公司網路 TLS 攔截，BuildKit 容器內缺企業根憑證。改走本手冊第 2+4 步的本機交叉編譯 + `docker-compose.local.yml`。                                                                                       |
| Row 3 一直 `503 temporarily_unavailable`                            | Kong 容器抓不到 `jwks_uri`。確認 issuer 在跑，且 `jwks_uri` 用 `host.docker.internal`（不是 `127.0.0.1` / `localhost`），且 compose 檔有 `extra_hosts: host.docker.internal:host-gateway`。用 §8.6 的無帳密技巧分辨連線問題。 |
| Row 3 變成 `401 invalid_token`                                      | 兩個常見原因：① `issuer` 設定值與 token 的 `iss` 不一致（差一個結尾斜線也會錯）；② token 的 `aud` 與 `gateway_origin + resource_path` 不符——取 token 時沒帶 `aud=`（test issuer）或 `resource=`（真 Signet，見 §8.4）。解碼 token 比對 `iss` 和 `aud`，要逐字元相同。 |
| token endpoint 回 `400 invalid_target`                              | 帶了 `resource=` 但該 URL 不在 client 的 `allowed_resources` 白名單（空白名單 = 全拒）。到 Signet 的 client 設定把資源 URL 加進 Allowed Resources。見 §8.4。                                          |
| 接真 Signet，有效 token 卻 `403 insufficient_scope`               | `required_scopes` 要求了 Signet 沒發的 scope（例如 `mcp:gitea`，但 Signet 只有 `openid profile email`）。改成 Signet 真的會發的 scope，或在 Signet 端註冊該 scope。見 §8.3。                    |
| `exec format error` / plugin 起不來                                 | 交叉編譯的 `GOARCH` 跟 Docker VM 架構不符。Apple Silicon 用 `arm64`、Intel 用 `amd64`。                                                                                                                |
| Kong 啟動就掛在 `failed decoding plugin info: Expected value but found T_END at character 1` | Kong 跑 `QUERY_CMD`（`mcp-signet -dump`）拿到**空 stdout**。先驗 binary：`docker-compose -f docker-compose.local.yml run --rm --entrypoint /usr/local/bin/mcp-signet kong -dump` 應印出 `{"Protocol":"ProtoBuf:1",...}`。空白 / `exec format error` = binary 與 kong 容器架構錯位（見上一列）。本機掛載版：用對的 `GOARCH` 重新交叉編譯（見第 2 步）再 `docker-compose -f docker-compose.local.yml up -d --force-recreate kong`；走 `Dockerfile` build 版：架構由 build arg `TARGETARCH`（`docker build --platform` 帶入）釘住，重建用 `docker compose build --no-cache kong && docker compose up -d --force-recreate`。 |
| `docker compose` 說 unknown command                                 | 你的環境只有獨立版 `docker-compose`。把指令裡的 `docker compose` 換成 `docker-compose` 即可（功能相同）。                                                                                              |
| 改了 `kong.*.yml` 沒生效                                            | DB-less Kong 在啟動時讀設定。改完要 `docker-compose -f <compose 檔> up -d --force-recreate kong`。                                                                                                     |

---

## 附錄：驗證結果速查

| #   | 測試                      | 指令重點                                                     | 預期                                                        |
| --- | ------------------------- | ------------------------------------------------------------ | ----------------------------------------------------------- |
| 1   | 未認證挑戰                | `curl -si $GW/mcp/gitea`                                     | 401 + `WWW-Authenticate`                                    |
| 2   | PRM 文件                  | `curl -s $GW/.well-known/oauth-protected-resource/mcp/gitea` | JSON（resource / authorization_servers / scopes_supported） |
| 3   | 有效 token                | `Bearer $GOOD`（scope + `aud` 都要對）                       | 200，轉發 upstream                                          |
| 4   | 過期 token（>ttl+leeway） | `Bearer $EXP`（等 70s）                                      | 401 invalid_token                                           |
| 5a  | 缺 scope                  | `Bearer $NOSCOPE`（aud 對、scope 錯）                        | 403 insufficient_scope                                      |
| 5b  | audience 不符 / 相符      | 綁 gitea 的 token 打 sentry / 綁對 aud                       | 401 / 200                                                   |
| 5c  | HS256 偽造                | 手刻 HS256                                                   | 401（alg confusion 被擋）                                   |
| 6a  | 偽造身分 header           | 同時帶 `X-MCP-Subject: attacker`                             | 被覆寫成 token 的 `sub`                                     |
| 6b  | 重複 Authorization        | 兩個 `Authorization` header                                  | 400                                                         |
| 6c  | 垃圾 token                | `Bearer not.a.jwt`                                           | 401                                                         |
