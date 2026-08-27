(function (global) {
  'use strict';

  const endpoint = 'http://127.0.0.1:18088';

  async function request(path, options) {
    const response = await fetch(endpoint + path, {
      cache: 'no-store',
      ...options,
      headers: { 'Content-Type': 'application/json', ...(options && options.headers) }
    });
    const result = await response.json();
    if (!response.ok || !result.ok) {
      throw new Error(result.error || `UKey Agent 请求失败（HTTP ${response.status}）`);
    }
    return result;
  }

  global.UKeyAgent = Object.freeze({
    health: () => request('/v1/health', { method: 'GET', headers: {} }),

    exportCertificate: ({ requestId = '', certificateType = 'sign' } = {}) =>
      request('/v1/certificate', {
        method: 'POST',
        body: JSON.stringify({ request_id: requestId, certificate_type: certificateType })
      }),

    signChallenge: ({ challengeBase64Url, pin, requestId = '', userId = '1234567812345678', userIdBase64Url }) => {
      if (!challengeBase64Url) throw new Error('缺少 challengeBase64Url');
      if (!pin) throw new Error('缺少 UKey PIN');
      const body = {
        challenge_base64url: challengeBase64Url,
        pin,
        request_id: requestId
      };
      if (userIdBase64Url !== undefined) body.user_id_base64url = userIdBase64Url;
      else body.user_id = userId;
      return request('/v1/sign', { method: 'POST', body: JSON.stringify(body) });
    }
  });
})(window);
