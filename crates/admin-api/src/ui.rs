use axum::response::Html;

pub(crate) async fn admin_page() -> Html<&'static str> {
    Html(ADMIN_PAGE)
}

const ADMIN_PAGE: &str = r#"<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>MouseVPN Admin</title>
  <style>
    :root{color-scheme:dark;--bg:#0e1117;--panel:#171c25;--line:#2c3442;--ink:#f1f5f9;--muted:#99a5b7;--accent:#7dd3fc;--danger:#fb7185}
    *{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#172134,var(--bg) 42%);color:var(--ink);font:15px/1.45 system-ui,sans-serif}
    main{width:min(920px,calc(100% - 28px));margin:36px auto}.card{background:color-mix(in srgb,var(--panel) 94%,transparent);border:1px solid var(--line);border-radius:18px;padding:22px;margin:16px 0;box-shadow:0 18px 50px #0005}
    h1,h2{margin:0 0 14px}h1{font-size:30px}h2{font-size:19px}.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:2fr 1fr 2fr auto;gap:10px}.login{display:flex;gap:10px}
    input,select,button,textarea{border:1px solid var(--line);border-radius:11px;background:#0d121a;color:var(--ink);padding:11px;font:inherit}input,select{width:100%}button{cursor:pointer;background:#243246;border-color:#38516e}button:hover{border-color:var(--accent)}button.danger{background:#321820;color:#fecdd3;border-color:#5d2534}
    table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid var(--line);padding:11px 7px}code{color:var(--accent)}textarea{width:100%;min-height:130px;resize:vertical}.result{display:none}.actions{display:flex;gap:9px;flex-wrap:wrap}.status{min-height:22px;margin-top:10px}.ok{color:#86efac}.error{color:#fda4af}
    @media(max-width:720px){.grid{grid-template-columns:1fr}.login{flex-direction:column}table,tbody,tr,td{display:block}thead{display:none}tr{padding:10px 0}td{border:0;padding:3px 0}}
  </style>
</head>
<body><main>
  <h1>MouseVPN Admin</h1><p class="muted">Панель доступна только внутри VPN. Токен хранится до закрытия вкладки.</p>
  <section class="card"><h2>Вход</h2><div class="login"><input id="token" type="password" autocomplete="off" placeholder="Админ-токен"><button id="login">Открыть</button></div><div id="status" class="status"></div></section>
  <section id="workspace" hidden>
    <section class="card"><h2>Новое устройство</h2><div class="grid"><input id="name" placeholder="Например: Мой телефон"><select id="platform"><option value="android">Android</option><option value="linux">Linux</option></select><input id="password" type="password" placeholder="Пароль MV1 (минимум 8)"><button id="create">Создать</button></div></section>
    <section id="result" class="card result"><h2>Ключ создан — сохраните сейчас</h2><p class="muted">Приватный ключ повторно получить нельзя.</p><div class="actions"><button id="copyProfile">Копировать MV1</button><button id="copyConfig">Копировать TOML</button></div><textarea id="secret" readonly></textarea></section>
    <section class="card"><h2>Устройства</h2><table><thead><tr><th>Имя</th><th>Тип</th><th>Адрес</th><th></th></tr></thead><tbody id="devices"></tbody></table></section>
  </section>
</main><script>
  const $=id=>document.getElementById(id); let token=sessionStorage.getItem('mousevpnAdminToken')||''; let last=null;
  $('token').value=token;
  async function api(path,options={}){const response=await fetch(path,{...options,headers:{'Authorization':`Bearer ${token}`,'Content-Type':'application/json',...(options.headers||{})}});const data=await response.json().catch(()=>({error:'Некорректный ответ сервера'}));if(!response.ok)throw new Error(data.error||`HTTP ${response.status}`);return data}
  function message(value,error=false){$('status').textContent=value;$('status').className=`status ${error?'error':'ok'}`}
  async function load(){try{const devices=await api('/v1/devices');$('workspace').hidden=false;$('devices').replaceChildren(...devices.map(row));message('Подключено')}catch(error){$('workspace').hidden=true;message(error.message,true)}}
  function row(device){const tr=document.createElement('tr');for(const value of [device.name,device.platform,device.address]){const td=document.createElement('td');td.textContent=value;tr.append(td)}const td=document.createElement('td');const button=document.createElement('button');button.className='danger';button.textContent='Отозвать';button.onclick=()=>revoke(device);td.append(button);tr.append(td);return tr}
  async function revoke(device){if(!confirm(`Отозвать ключ «${device.name}»?`))return;try{await api(`/v1/devices/${encodeURIComponent(device.public_key)}`,{method:'DELETE'});await load()}catch(error){message(error.message,true)}}
  $('login').onclick=()=>{token=$('token').value.trim();sessionStorage.setItem('mousevpnAdminToken',token);load()};
  $('create').onclick=async()=>{try{last=await api('/v1/devices',{method:'POST',body:JSON.stringify({name:$('name').value,platform:$('platform').value,profile_password:$('password').value||null})});$('password').value='';$('result').style.display='block';$('secret').value=last.profile_token||last.client_config;await load();message(`Создано: ${last.device.name}`)}catch(error){message(error.message,true)}};
  async function copy(value){if(!value)return;if(window.isSecureContext&&navigator.clipboard){await navigator.clipboard.writeText(value);return}const area=document.createElement('textarea');area.value=value;area.style.position='fixed';area.style.opacity='0';document.body.append(area);area.select();document.execCommand('copy');area.remove()}
  $('copyProfile').onclick=()=>copy(last?.profile_token);
  $('copyConfig').onclick=()=>copy(last?.client_config);
  if(token)load();
</script></body></html>"#;
