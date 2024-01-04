function doPost(e) {
  // リクエストパラメータから値を取得
  const body = e.postData.contents;
  // ボディパラメータをJSONにパース
  const requestBody = JSON.parse(body);

  const hostURL = requestBody.hostURL; // リクエスト元のホストURL
  const orgId = requestBody.orgId; // 会社ID（メールアドレス）
  const password = requestBody.password; // パスワード
  const clientKey = requestBody.clientKey; // クライアントキー
  const secretKey = requestBody.secretKey; // シークレットキー
  const ipAddress = requestBody.ipAddress; // クライアントの IP アドレス

  // 返却データの定義
  let responseData = {};
  // 認証処理
  const responseOAuth = initOAuth(hostURL, orgId, password, clientKey, secretKey, ipAddress);

  // 認証に成功したらアクセストークンを返却
  if (responseOAuth.isAuthenticated) { // 認証に成功した場合
    responseData["isAuthenticated"] = responseOAuth.isAuthenticated;
    responseData["accessToken"] = responseOAuth.accessToken;
    responseData["accessTokenTimeStamp"] = responseOAuth.accessTokenTimeStamp;
    responseData["accessTokenExpire"] = responseOAuth.accessTokenExpire;
  } else { // 認証に失敗した場合
    responseData["isAuthenticated"] = responseOAuth.isAuthenticated;
    responseData["accessToken"] = null;
    responseData["accessTokenTimeStamp"] = null;
    responseData["accessTokenExpire"] = null;
  }

  // データ返却
  const jsonString = JSON.stringify(responseData);
  return ContentService.createTextOutput(jsonString).setMimeType(ContentService.MimeType.JSON);
}