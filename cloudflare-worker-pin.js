// Cloudflare Worker — PIN zámek pro teo.torok.sk
// Vloží se v Cloudflare dashboardu: Workers & Pages -> Create Worker -> Quick Edit
// a přiřadí jako Route: teo.torok.sk/*

const PIN = "1346";
const COOKIE_NAME = "teo_pin_ok";
const SECRET = "teo-torok-sk-lock-v1"; // interní sůl pro podpis cookie, nemusí se nikam zadávat

async function sign(value) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

function lockPage(error) {
  return `<!DOCTYPE html>
<html lang="cs">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Zamčeno 🔒</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    background:linear-gradient(160deg,#a2d2ff 0%,#9d4edd 55%,#ff5d8f 100%);}
  .card{background:#fff;padding:40px 32px;border-radius:24px;box-shadow:0 20px 50px rgba(0,0,0,.25);
    text-align:center;max-width:320px;width:90%;}
  .lock{font-size:56px;margin-bottom:8px;}
  h1{font-size:20px;margin:0 0 20px;color:#22223b;}
  input{font-size:28px;letter-spacing:12px;text-align:center;width:100%;padding:14px 0;
    border:2px solid #cdb4db;border-radius:14px;box-sizing:border-box;margin-bottom:16px;}
  button{width:100%;padding:14px;border:none;border-radius:14px;background:#9d4edd;color:#fff;
    font-size:18px;font-weight:700;cursor:pointer;}
  .err{color:#e5383b;font-size:14px;margin-bottom:12px;min-height:18px;}
</style>
</head>
<body>
  <form class="card" method="POST">
    <div class="lock">🔒</div>
    <h1>Zadej PIN</h1>
    <div class="err">${error ? "Špatný PIN, zkus to znovu." : ""}</div>
    <input type="password" name="pin" inputmode="numeric" pattern="[0-9]*" maxlength="4" autofocus required>
    <button type="submit">Odemknout</button>
  </form>
</body>
</html>`;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cookieHeader = request.headers.get("Cookie") || "";
    const cookies = Object.fromEntries(
      cookieHeader.split(";").map(c => c.trim().split("=")).filter(p => p.length === 2)
    );

    if (request.method === "POST") {
      const form = await request.formData();
      const pin = form.get("pin");
      if (pin === PIN) {
        const signature = await sign(PIN);
        const headers = new Headers({ "Location": "/" });
        headers.append(
          "Set-Cookie",
          `${COOKIE_NAME}=${signature}; Path=/; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax`
        );
        return new Response(null, { status: 302, headers });
      }
      return new Response(lockPage(true), {
        status: 401,
        headers: { "Content-Type": "text/html; charset=UTF-8" },
      });
    }

    const cookieValue = cookies[COOKIE_NAME];
    const expected = await sign(PIN);
    if (cookieValue === expected) {
      return fetch(request);
    }

    return new Response(lockPage(false), {
      status: 401,
      headers: { "Content-Type": "text/html; charset=UTF-8" },
    });
  },
};
