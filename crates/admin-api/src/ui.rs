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
    main{width:min(1080px,calc(100% - 28px));margin:36px auto}.card{background:color-mix(in srgb,var(--panel) 94%,transparent);border:1px solid var(--line);border-radius:18px;padding:22px;margin:16px 0;box-shadow:0 18px 50px #0005}
    h1,h2{margin:0 0 14px}h1{font-size:30px}h2{font-size:19px}.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:2fr 1fr 2fr auto;gap:10px}.login,.section-head,.periods,.legend{display:flex;gap:10px}.section-head{align-items:center;justify-content:space-between}.section-head h2{margin:0}.periods{margin:18px 0 8px}.periods button.active{background:#164e63;border-color:var(--accent);color:#cffafe}
    input,select,button,textarea{border:1px solid var(--line);border-radius:11px;background:#0d121a;color:var(--ink);padding:11px;font:inherit}input,select{width:100%}button{cursor:pointer;background:#243246;border-color:#38516e}button:hover{border-color:var(--accent)}button.danger{background:#321820;color:#fecdd3;border-color:#5d2534}
    table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid var(--line);padding:11px 7px}th.num,td.num{text-align:right;font-variant-numeric:tabular-nums}code{color:var(--accent)}textarea{width:100%;min-height:130px;resize:vertical}.result{display:none}.actions{display:flex;gap:9px;flex-wrap:wrap}.status{min-height:22px;margin-top:10px}.ok{color:#86efac}.error{color:#fda4af}
    .summary{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:20px 0}.metric{padding:17px;border:1px solid var(--line);border-radius:14px;background:#101620}.metric-label{color:var(--muted);font-size:13px}.metric-value{font-size:25px;font-weight:750;margin:5px 0}.metric-split{font-size:12px;color:var(--muted)}
    .chart-wrap{margin-top:14px;padding:18px 12px 8px;border:1px solid var(--line);border-radius:14px;background:#0d121a;overflow-x:auto}.chart{height:230px;min-width:680px;display:flex;align-items:flex-end;gap:5px;border-bottom:1px solid var(--line)}.bar-item{height:100%;flex:1;min-width:14px;display:flex;flex-direction:column;justify-content:flex-end;align-items:stretch}.bar-stack{display:flex;flex-direction:column;justify-content:flex-end;min-height:2px;border-radius:5px 5px 0 0;overflow:hidden;background:#263445}.bar-download{background:#38bdf8}.bar-upload{background:#a78bfa}.bar-label{text-align:center;color:var(--muted);font-size:10px;height:25px;padding-top:6px;white-space:nowrap}.legend{justify-content:flex-end;color:var(--muted);font-size:12px}.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px}.legend .down i{background:#38bdf8}.legend .up i{background:#a78bfa}.traffic-table{margin-top:20px}
    @media(max-width:720px){.grid,.summary{grid-template-columns:1fr}.login{flex-direction:column}.section-head{align-items:flex-start;flex-direction:column}table.responsive,table.responsive tbody,table.responsive tr,table.responsive td{display:block}table.responsive thead{display:none}table.responsive tr{padding:10px 0}table.responsive td{border:0;padding:3px 0;text-align:left}.metric-value{font-size:22px}}
  </style>
</head>
<body><main>
  <h1>MouseVPN Admin</h1><p class="muted">Панель доступна только внутри VPN. Токен хранится до закрытия вкладки.</p>
  <section class="card"><h2>Вход</h2><div class="login"><input id="token" type="password" autocomplete="off" placeholder="Админ-токен"><button id="login">Открыть</button></div><div id="status" class="status"></div></section>
  <section id="workspace" hidden>
    <section class="card">
      <div class="section-head"><div><h2>Трафик</h2><div class="muted">Считаются полезные IP-данные внутри VPN</div></div><button id="refreshTraffic">Обновить</button></div>
      <div class="summary">
        <div class="metric"><div class="metric-label">Текущий час</div><div id="trafficHour" class="metric-value">—</div><div id="trafficHourSplit" class="metric-split"></div></div>
        <div class="metric"><div class="metric-label">Последние 24 часа</div><div id="trafficDay" class="metric-value">—</div><div id="trafficDaySplit" class="metric-split"></div></div>
        <div class="metric"><div class="metric-label">Последние 7 дней</div><div id="trafficWeek" class="metric-value">—</div><div id="trafficWeekSplit" class="metric-split"></div></div>
      </div>
      <div class="section-head"><div class="periods"><button data-hours="24" class="active">24 часа</button><button data-hours="168">7 дней</button></div><div class="legend"><span class="down"><i></i>Скачано</span><span class="up"><i></i>Отправлено</span></div></div>
      <div class="chart-wrap"><div id="trafficChart" class="chart"></div></div>
      <div class="traffic-table"><h2>По устройствам</h2><table class="responsive"><thead><tr><th>Имя</th><th class="num">Скачано</th><th class="num">Отправлено</th><th class="num">Всего</th></tr></thead><tbody id="trafficDevices"></tbody></table></div>
    </section>
    <section class="card"><h2>Новое устройство</h2><div class="grid"><input id="name" placeholder="Например: Мой телефон"><select id="platform"><option value="android">Android</option><option value="linux">Linux</option></select><input id="password" type="password" placeholder="Пароль MV1 (минимум 8)"><button id="create">Создать</button></div></section>
    <section id="result" class="card result"><h2>Ключ создан — сохраните сейчас</h2><p class="muted">Приватный ключ повторно получить нельзя.</p><div class="actions"><button id="copyProfile">Копировать MV1</button><button id="copyConfig">Копировать TOML</button></div><textarea id="secret" readonly></textarea></section>
    <section class="card"><h2>Устройства</h2><table class="responsive"><thead><tr><th>Имя</th><th>Тип</th><th>Адрес</th><th></th></tr></thead><tbody id="devices"></tbody></table></section>
  </section>
</main><script>
  const $=id=>document.getElementById(id); let token=sessionStorage.getItem('mousevpnAdminToken')||''; let last=null; let selectedHours=24; let trafficLoading=false;
  $('token').value=token;
  async function api(path,options={}){const response=await fetch(path,{...options,headers:{'Authorization':`Bearer ${token}`,'Content-Type':'application/json',...(options.headers||{})}});const data=await response.json().catch(()=>({error:'Некорректный ответ сервера'}));if(!response.ok)throw new Error(data.error||`HTTP ${response.status}`);return data}
  function message(value,error=false){$('status').textContent=value;$('status').className=`status ${error?'error':'ok'}`}
  async function load(){try{const [devices,stats]=await Promise.all([api('/v1/devices'),api(`/v1/traffic?hours=${selectedHours}`)]);$('workspace').hidden=false;$('devices').replaceChildren(...devices.map(row));renderTraffic(stats);message('Подключено')}catch(error){$('workspace').hidden=true;message(error.message,true)}}
  function row(device){const tr=document.createElement('tr');for(const value of [device.name,device.platform,device.address]){const td=document.createElement('td');td.textContent=value;tr.append(td)}const td=document.createElement('td');const button=document.createElement('button');button.className='danger';button.textContent='Отозвать';button.onclick=()=>revoke(device);td.append(button);tr.append(td);return tr}
  async function revoke(device){if(!confirm(`Отозвать ключ «${device.name}»?`))return;try{await api(`/v1/devices/${encodeURIComponent(device.public_key)}`,{method:'DELETE'});await load()}catch(error){message(error.message,true)}}
  function formatBytes(value){if(!value)return '0 Б';const units=['Б','КБ','МБ','ГБ','ТБ'];const power=Math.min(Math.floor(Math.log(value)/Math.log(1024)),units.length-1);const number=value/1024**power;return `${number.toLocaleString('ru-RU',{maximumFractionDigits:number>=100?0:number>=10?1:2})} ${units[power]}`}
  function total(value){return value.upload_bytes+value.download_bytes}
  function showMetric(id,value){$(id).textContent=formatBytes(total(value));$(`${id}Split`).textContent=`↓ ${formatBytes(value.download_bytes)}  ·  ↑ ${formatBytes(value.upload_bytes)}`}
  function chartSeries(hourly){if(selectedHours===24)return hourly.map(point=>({...point,label:new Date(point.hour*1000).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'})}));const result=[];for(let index=0;index<hourly.length;index+=24){const part=hourly.slice(index,index+24);result.push({hour:part[0].hour,upload_bytes:part.reduce((sum,item)=>sum+item.upload_bytes,0),download_bytes:part.reduce((sum,item)=>sum+item.download_bytes,0),label:new Date(part[part.length-1].hour*1000).toLocaleDateString('ru-RU',{day:'2-digit',month:'2-digit'})})}return result}
  function renderChart(hourly){const series=chartSeries(hourly);const maximum=Math.max(1,...series.map(total));const bars=series.map((point,index)=>{const item=document.createElement('div');item.className='bar-item';item.title=`${new Date(point.hour*1000).toLocaleString('ru-RU')}\nСкачано: ${formatBytes(point.download_bytes)}\nОтправлено: ${formatBytes(point.upload_bytes)}`;const stack=document.createElement('div');stack.className='bar-stack';stack.style.height=`${Math.max(2,total(point)/maximum*190)}px`;const down=document.createElement('div');down.className='bar-download';down.style.flex=point.download_bytes||0;const up=document.createElement('div');up.className='bar-upload';up.style.flex=point.upload_bytes||0;stack.append(down,up);const label=document.createElement('div');label.className='bar-label';label.textContent=selectedHours===24&&index%3!==0?'':point.label;item.append(stack,label);return item});$('trafficChart').replaceChildren(...bars)}
  function trafficRow(device){const tr=document.createElement('tr');const values=[device.name,formatBytes(device.download_bytes),formatBytes(device.upload_bytes),formatBytes(device.download_bytes+device.upload_bytes)];values.forEach((value,index)=>{const td=document.createElement('td');td.textContent=value;if(index)td.className='num';tr.append(td)});return tr}
  function renderTraffic(stats){showMetric('trafficHour',stats.totals.hour);showMetric('trafficDay',stats.totals.day);showMetric('trafficWeek',stats.totals.week);renderChart(stats.hourly);const rows=stats.devices.map(trafficRow);if(!rows.length){const tr=document.createElement('tr');const td=document.createElement('td');td.colSpan=4;td.className='muted';td.textContent='За этот период трафика пока нет';tr.append(td);rows.push(tr)}$('trafficDevices').replaceChildren(...rows)}
  async function refreshTraffic(reportError=true){if(trafficLoading)return;trafficLoading=true;try{renderTraffic(await api(`/v1/traffic?hours=${selectedHours}`))}catch(error){if(reportError)message(error.message,true)}finally{trafficLoading=false}}
  async function selectPeriod(hours){selectedHours=hours;document.querySelectorAll('[data-hours]').forEach(button=>button.classList.toggle('active',Number(button.dataset.hours)===hours));await refreshTraffic()}
  $('login').onclick=()=>{token=$('token').value.trim();sessionStorage.setItem('mousevpnAdminToken',token);load()};
  $('create').onclick=async()=>{try{last=await api('/v1/devices',{method:'POST',body:JSON.stringify({name:$('name').value,platform:$('platform').value,profile_password:$('password').value||null})});$('password').value='';$('result').style.display='block';$('secret').value=last.profile_token||last.client_config;await load();message(`Создано: ${last.device.name}`)}catch(error){message(error.message,true)}};
  async function copy(value){if(!value)return;if(window.isSecureContext&&navigator.clipboard){await navigator.clipboard.writeText(value);return}const area=document.createElement('textarea');area.value=value;area.style.position='fixed';area.style.opacity='0';document.body.append(area);area.select();document.execCommand('copy');area.remove()}
  $('copyProfile').onclick=()=>copy(last?.profile_token);
  $('copyConfig').onclick=()=>copy(last?.client_config);
  $('refreshTraffic').onclick=()=>selectPeriod(selectedHours);
  document.querySelectorAll('[data-hours]').forEach(button=>button.onclick=()=>selectPeriod(Number(button.dataset.hours)));
  setInterval(()=>{if(token&&!$('workspace').hidden&&!document.hidden)refreshTraffic(false)},5000);
  if(token)load();
</script></body></html>"#;
