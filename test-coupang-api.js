const crypto = require('crypto');
const https = require('https');
const zlib = require('zlib');

const VENDOR_ID = 'A00163254';
const ACCESS_KEY = '2a16fa42-5b36-4f3f-abf9-ad93d0b9239c';
const SECRET_KEY = '0867264093e598f11564a19b0f887bb971df57c7';

// 쿠팡 공식 datetime 형식: yyMMddTHHmmssZ (UTC)
function getDatetimeGMT() {
  const now = new Date();
  const yy = String(now.getUTCFullYear()).slice(-2);
  const MM = String(now.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(now.getUTCDate()).padStart(2, '0');
  const HH = String(now.getUTCHours()).padStart(2, '0');
  const mm = String(now.getUTCMinutes()).padStart(2, '0');
  const ss = String(now.getUTCSeconds()).padStart(2, '0');
  return `${yy}${MM}${dd}T${HH}${mm}${ss}Z`;
}

// 공식 구현: message = datetimeGMT + method + path + queryString (? 제외)
function generateAuth(method, url) {
  const [path, ...queryParts] = url.split('?');
  const query = queryParts.length > 0 ? queryParts[0] : '';
  const datetime = getDatetimeGMT();

  const message = datetime + method + path + query;
  console.log(`  [datetime] ${datetime}`);
  console.log(`  [message]  "${message}"`);

  const signature = crypto.createHmac('sha256', SECRET_KEY).update(message).digest('hex');
  return {
    auth: `CEA algorithm=HmacSHA256, access-key=${ACCESS_KEY}, signed-date=${datetime}, signature=${signature}`,
    httpPath: url,
  };
}

function callAPI(url) {
  return new Promise((resolve) => {
    const { auth, httpPath } = generateAuth('GET', url);
    console.log(`  [auth]     ${auth}`);

    const options = {
      hostname: 'api-gateway.coupang.com',
      port: 443,
      path: httpPath,
      method: 'GET',
      headers: {
        'Authorization': auth,
        'Content-Type': 'application/json;charset=UTF-8',
      },
    };
    const req = https.request(options, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const raw = Buffer.concat(chunks);
        const decode = (buf) => {
          try { return JSON.parse(buf.toString('utf-8')); } catch (e) { return buf.toString('utf-8'); }
        };
        const encoding = res.headers['content-encoding'];
        if (encoding === 'gzip') {
          zlib.gunzip(raw, (err, decoded) => {
            resolve({ status: res.statusCode, body: err ? raw.toString() : decode(decoded) });
          });
        } else {
          resolve({ status: res.statusCode, body: decode(raw) });
        }
      });
    });
    req.on('error', (err) => resolve({ status: 'ERROR', body: err.message }));
    req.end();
  });
}

async function runTests() {
  const today = '2026-05-26';
  const basePath = `/v2/providers/openapi/apis/api/v4/vendors/${VENDOR_ID}/ordersheets`;

  const queryRaw = `createdAtFrom=${today}T00:00:00&createdAtTo=${today}T23:59:59&status=ACCEPT&maxPerPage=10&pageIndex=1`;
  const queryEnc = new URLSearchParams({
    createdAtFrom: `${today}T00:00:00`,
    createdAtTo: `${today}T23:59:59`,
    status: 'ACCEPT',
    maxPerPage: '10',
    pageIndex: '1',
  }).toString();

  const tests = [
    { label: 'ordersheets - 원본 쿼리',    url: `${basePath}?${queryRaw}` },
    { label: 'ordersheets - 인코딩 쿼리',  url: `${basePath}?${queryEnc}` },
  ];

  console.log('=== 쿠팡 Open API 테스트 (datetime: yyMMddTHHmmssZ) ===\n');

  for (let i = 0; i < tests.length; i++) {
    const t = tests[i];
    console.log(`[${i + 1}] ${t.label}`);
    const result = await callAPI(t.url);
    console.log(`  STATUS: ${result.status}`);
    console.log(`  BODY:   ${JSON.stringify(result.body)}`);
    if (result.status === 200) {
      console.log('\n✅ 연결 성공!');
      console.log(JSON.stringify(result.body, null, 2));
      return;
    }
    console.log();
  }
}

runTests().catch(console.error);
