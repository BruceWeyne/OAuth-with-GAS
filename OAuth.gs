function initOAuth(hostURL, orgId, password, clientKey, secretKey, ipAddress) {
  // Config を読み込み
  const conf = config();
  // インスタンスの生成
  const mdl = new Model();
  // 各種設定情報の取得
  const settings = mdl.getData("API設定");
  // OAuth 情報の取得
  const realOrgId = settings[0]["組織ID"];
  const realPassword = settings[0]["パスワード"];
  const realClientKey = settings[0]["クライアントキー"];
  const realSecretKey = settings[0]["シークレットキー"];
  const accessTokenExpire = settings[0]["アクセストークン有効期限(h)"];
  // 認証処理
  let response = {};
  let isAuthenticated = false;
  if (
    (hostURL === conf.hostURLProd || hostURL === conf.hostURLTest)
    &&
    orgId === realOrgId
    &&
    password === realPassword
    &&
    clientKey === realClientKey
    &&
    secretKey === realSecretKey
  ) {
    isAuthenticated = true;
    // 現在時刻を取得
    const nowUnix = Math.floor(Date.now() / 1000); // 現在の UNIX 時間を取得（秒単位）
    // 有効期限を UNIX Time に変換
    const accessTokenExpireUnix = Number(accessTokenExpire) * 60 * 60;
    // 現在から有効期限前の UNIX 時間を計算（秒単位）
    const expireTimeAgoUnix = nowUnix - accessTokenExpireUnix;
    // アクセストークン情報を取得
    const conditions = [
      {key: "IPアドレス", value: ipAddress},
      {key: "ホストURL", value: hostURL},
      {key: "アクセストークンタイムスタンプ >=", value: expireTimeAgoUnix} // 有効期限以内のもののみ
    ];
    const tokens = mdl.getData("トークン管理", conditions);
    // トークンの有効性ごとに処理を分岐
    if (tokens.length > 0) { // トークンが存在する場合
      response.accessToken = tokens[0]["アクセストークン"];
      response.accessTokenTimeStamp = tokens[0]["アクセストークンタイムスタンプ"];
      response.accessTokenExpire = accessTokenExpire;
    } else { // 有効期限が過ぎている場合
      // トークンの新規発行
      const newAccessToken = generateToken(64); // トークンの新規発行
      response.accessToken = newAccessToken;
      response.accessTokenTimeStamp = nowUnix; // 現在時刻 Unix
      response.accessTokenExpire = accessTokenExpire;
      // スプレッドシートにトークンを登録
      const keyValuePairs = [
        {
          "IPアドレス": ipAddress,
          "ホストURL": hostURL,
          "アクセストークン": newAccessToken,
          "アクセストークンタイムスタンプ": nowUnix
        }
      ];
      mdl.insertData("トークン管理", keyValuePairs);
    }
  }

  response.isAuthenticated = isAuthenticated;

  return response;
}


function authorizeToken(accessToken) {
  // インスタンスの生成
  const mdl = new Model();
  // 各種設定情報の取得
  const settings = mdl.getData("API設定");
  const accessTokenExpire = settings[0]["アクセストークン有効期限(h)"];
  const extensionTime = settings[0]["有効期限補正(h)"];
  // 現在時刻を取得
  const nowUnix = Math.floor(Date.now() / 1000); // 現在の UNIX 時間を取得（秒単位）
  // 有効期限を UNIX Time に変換
  const accessTokenExpireUnix = Number(accessTokenExpire + extensionTime) * 60 * 60;
  // 現在から有効期限前の UNIX 時間を計算（秒単位）
  const expireTimeAgoUnix = nowUnix - accessTokenExpireUnix;
  // アクセストークン情報を取得
  const conditions = [
    {key: "アクセストークン", value: accessToken},
    {key: "アクセストークンタイムスタンプ >=", value: expireTimeAgoUnix} // 有効期限以内のもののみ
  ];
  const tokens = mdl.getData("トークン管理", conditions);
  // 認証処理
  let isAuthenticated = false;
  if (tokens.length > 0) { // アクセストークンが存在する場合
    isAuthenticated = true;
  }

  return isAuthenticated;
}
