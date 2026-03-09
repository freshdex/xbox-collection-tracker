// XCT Live — Auth UI (injected by xct_server.py as extra_js)
(function(){
window._xctHosted=true;
var _API='';
var _xctApiKey=localStorage.getItem('xct_api_key')||'';
window._xctApiKey=_xctApiKey;
var _xctUser=localStorage.getItem('xct_username')||'';
var _xctXboxGt=localStorage.getItem('xct_gamertag')||'';
var _xctXuid=localStorage.getItem('xct_xuid')||'';
var _xctAvatarUrl=localStorage.getItem('xct_avatar_url')||'';
var _phLoaded=false,_purchLoaded=false;
var _phCount=0,_purchCount=0;

async function _fetchJSON(url,opts){
  var r=await fetch(url,opts||{});
  if(!r.ok){var e=new Error(r.status);e.response=r;throw e}
  return r.json()}

async function _loadCollection(){
  if(!_xctApiKey)return false;
  try{
    var data=await _fetchJSON(_API+'/api/v1/collection',{
      headers:{'Authorization':'Bearer '+_xctApiKey}});
    if(!data.uploaded)return false;
    LIB.length=0;LIB.push.apply(LIB,data.library||[]);
    HISTORY.length=0;HISTORY.push.apply(HISTORY,data.history||[]);
    ACCOUNTS.length=0;ACCOUNTS.push.apply(ACCOUNTS,data.accounts||[]);
    _phCount=data.phCount||0;
    _purchCount=data.purchasesCount||0;
    _phLoaded=false;_purchLoaded=false;
    PH.length=0;
    if(typeof PURCHASES!=='undefined')PURCHASES.length=0;
    _xctUser=data.username||_xctUser;
    if(data.settings&&Array.isArray(data.settings.myRegions)){
      _myRegions=data.settings.myRegions;
      localStorage.setItem('xct_my_regions',JSON.stringify(_myRegions));
      _initMyRegions()}
    if(data.settings&&data.settings.gamertagInfo){
      window._gamertagInfo=data.settings.gamertagInfo}
    var ownedPids=new Set(LIB.map(function(x){return x.productId}));
    if(MKT.length)MKT.forEach(function(x){x.owned=ownedPids.has(x.productId)});
    if(GP.length)GP.forEach(function(x){x.owned=ownedPids.has(x.productId)});
    console.log('[auth] Collection loaded:',LIB.length,'items (PH:',_phCount,'deferred, Purch:',_purchCount,'deferred)');
    return true
  }catch(e){
    console.error('[auth] _loadCollection error:',e);
    if(String(e).includes('401')){localStorage.removeItem('xct_api_key');_xctApiKey='';window._xctApiKey=''}
    return false}}

async function _lazyLoadPH(){
  if(_phLoaded||!_xctApiKey)return;
  try{
    var data=await _fetchJSON(_API+'/api/v1/collection/playhistory',{
      headers:{'Authorization':'Bearer '+_xctApiKey}});
    PH.length=0;PH.push.apply(PH,data.playHistory||[]);
    _phLoaded=true;
    console.log('[auth] Play history loaded:',PH.length,'items');
    try{filterPH()}catch(e){console.error('[auth] filterPH error:',e)}
    document.getElementById('tab-ph-cnt').textContent=PH.length;
  }catch(e){console.error('[auth] _lazyLoadPH error:',e)}}

async function _lazyLoadPurchases(){
  if(_purchLoaded||!_xctApiKey)return;
  try{
    var data=await _fetchJSON(_API+'/api/v1/collection/purchases',{
      headers:{'Authorization':'Bearer '+_xctApiKey}});
    if(typeof PURCHASES!=='undefined'){PURCHASES.length=0;PURCHASES.push.apply(PURCHASES,data.purchases||[])}
    _purchLoaded=true;
    console.log('[auth] Purchases loaded:',PURCHASES.length,'items');
    try{if(typeof filterPurchases==='function')filterPurchases()}catch(e){console.error('[auth] filterPurchases error:',e)}
    document.getElementById('tab-purch-cnt').textContent=PURCHASES.length;
  }catch(e){console.error('[auth] _lazyLoadPurchases error:',e)}}

// Hook into tab switching to lazy-load data
var _origSwitchTab=window.switchTab;
window.switchTab=function(id,el){
  if(id==='playhistory'&&!_phLoaded&&_xctApiKey)_lazyLoadPH();
  if(id==='purchases'&&!_purchLoaded&&_xctApiKey)_lazyLoadPurchases();
  if(_origSwitchTab)return _origSwitchTab(id,el)}

function _showLoading(){
  var o=document.getElementById('loading-overlay');
  if(o)o.style.display='flex'}
function _hideLoading(){
  var o=document.getElementById('loading-overlay');if(o)o.style.display='none'}

function _xctShowAuth(){
  var m=document.createElement('div');m.id='xct-auth-modal';
  m.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:10000';
  m.innerHTML='<div style="background:#1a1a1a;padding:24px;border-radius:8px;border:1px solid #333;width:320px">'+
    '<h3 style="margin:0 0 16px;color:#fff">Log In to XCT Live</h3>'+
    '<div style="color:#888;font-size:12px;margin-bottom:12px">Uses your CDN Sync account. New users will be registered automatically.</div>'+
    '<input id="xct-auth-user-input" placeholder="Username" style="width:100%;padding:8px;margin-bottom:8px;background:#222;color:#fff;border:1px solid #444;border-radius:4px;box-sizing:border-box">'+
    '<input id="xct-auth-pass-input" type="password" placeholder="Passphrase" style="width:100%;padding:8px;margin-bottom:12px;background:#222;color:#fff;border:1px solid #444;border-radius:4px;box-sizing:border-box">'+
    '<div id="xct-auth-error" style="color:#f44;font-size:12px;margin-bottom:8px;display:none"></div>'+
    '<div style="display:flex;gap:8px;justify-content:flex-end">'+
    "<button onclick=\"document.getElementById('xct-auth-modal').remove()\" style=\"padding:6px 16px;background:#333;color:#ccc;border:none;border-radius:4px;cursor:pointer\">Cancel</button>"+
    '<button onclick="_xctLogin()" id="xct-auth-submit" style="padding:6px 16px;background:#107c10;color:#fff;border:none;border-radius:4px;cursor:pointer">Log In</button>'+
    '</div></div>';
  document.body.appendChild(m);
  document.getElementById('xct-auth-user-input').focus();
  m.addEventListener('click',function(e){if(e.target===m)m.remove()});
  document.getElementById('xct-auth-pass-input').addEventListener('keydown',function(e){if(e.key==='Enter')_xctLogin()})}
window._xctShowAuth=_xctShowAuth;

window._xctLogin=async function(){
  var u=document.getElementById('xct-auth-user-input').value.trim();
  var p=document.getElementById('xct-auth-pass-input').value.trim();
  var errEl=document.getElementById('xct-auth-error');
  if(!u||!p){errEl.textContent='Username and passphrase required';errEl.style.display='block';return}
  var btn=document.getElementById('xct-auth-submit');
  btn.disabled=true;btn.textContent='...';
  try{
    var r=await _fetchJSON(_API+'/api/v1/register',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:u,passphrase:p})});
    console.log('[auth] Login success:',r.username);
    localStorage.setItem('xct_api_key',r.api_key);
    localStorage.setItem('xct_username',r.username);
    _xctApiKey=r.api_key;window._xctApiKey=_xctApiKey;_xctUser=r.username;
    document.getElementById('xct-auth-modal').remove();
    _showLoading();
    _updateAuthUI();
    _xctReloadCollection().then(function(){_hideLoading()}).catch(function(e){console.error('[auth] reload error:',e);_hideLoading()});
  }catch(e){
    console.error('[auth] Login error:',e);
    var msg='Connection error';
    try{if(e.response){var b=await e.response.json();msg=b.error||msg}}catch(x){}
    errEl.textContent=msg;errEl.style.display='block';
    btn.disabled=false;btn.textContent='Log In'}}

function _xctLogout(){
  localStorage.removeItem('xct_api_key');
  localStorage.removeItem('xct_username');
  localStorage.removeItem('xct_gamertag');
  localStorage.removeItem('xct_xuid');
  localStorage.removeItem('xct_avatar_url');
  _xctApiKey='';window._xctApiKey='';_xctUser='';_xctXboxGt='';_xctXuid='';_xctAvatarUrl='';
  _phLoaded=false;_purchLoaded=false;_phCount=0;_purchCount=0;
  LIB.length=0;PH.length=0;HISTORY.length=0;ACCOUNTS.length=0;
  if(typeof PURCHASES!=='undefined')PURCHASES.length=0;
  if(MKT.length)MKT.forEach(function(x){delete x.owned});
  GP.forEach(function(x){delete x.owned});
  try{filterLib();filterPH();filterMKT();filterGP();
    if(typeof filterPurchases==='function')filterPurchases()}catch(e){}
  document.getElementById('tab-purch').style.display='none';
  document.getElementById('tab-ph').style.display='none';
  _updateAuthUI()}

function _updateAuthUI(){
  var userEl=document.getElementById('xct-auth-user');
  var btnEl=document.getElementById('xct-auth-btn');
  var uploadBtn=document.getElementById('xct-upload-btn');
  var xboxBtn=document.getElementById('xct-xbox-btn');
  var xboxGt=document.getElementById('xct-xbox-gt');
  var avatarEl=document.getElementById('xct-avatar');
  if(_xctApiKey&&_xctUser){
    userEl.textContent=_xctUser;
    btnEl.textContent='Log Out';btnEl.onclick=_xctLogout;
    btnEl.style.background='#333';btnEl.style.border='1px solid #555';btnEl.style.color='#ccc';
    uploadBtn.style.display='inline-block';
    if(_xctXboxGt){
      xboxGt.textContent=_xctXboxGt;xboxGt.style.display='';
      if(_xctAvatarUrl&&avatarEl){avatarEl.src=_xctAvatarUrl;avatarEl.style.display='';avatarEl.onerror=function(){this.style.display='none'}}
      else if(avatarEl){avatarEl.style.display='none'}
      xboxBtn.textContent='Disconnect Xbox';
      xboxBtn.style.background='#333';xboxBtn.style.border='1px solid #555';xboxBtn.style.color='#ccc';
      xboxBtn.onclick=_xctXboxDisconnect;xboxBtn.style.display=''
    }else{
      xboxGt.style.display='none';
      if(avatarEl)avatarEl.style.display='none';
      xboxBtn.textContent='\u2B22 Sign in with Xbox';
      xboxBtn.style.background='#107c10';xboxBtn.style.border='none';xboxBtn.style.color='#fff';
      xboxBtn.onclick=_xctXboxAuth;xboxBtn.style.display=''}
    var adminTab=document.getElementById('tab-admin');
    var adminSec=document.getElementById('admin');
    if(_xctUser.toLowerCase()==='freshdex'){
      if(adminTab)adminTab.style.display='';
    }else{
      if(adminTab)adminTab.remove();
      if(adminSec)adminSec.remove();
    }
    var settingsTab=document.getElementById('tab-settings');
    if(settingsTab){settingsTab.style.display='';if(typeof _loadPriceSettings==='function')_loadPriceSettings()}
  }else{
    userEl.textContent='';
    btnEl.textContent='Log In';btnEl.onclick=_xctShowAuth;
    btnEl.style.background='#107c10';btnEl.style.border='none';btnEl.style.color='#fff';
    uploadBtn.style.display='none';xboxBtn.style.display='none';xboxGt.style.display='none';
    if(avatarEl)avatarEl.style.display='none';
    var adminTab=document.getElementById('tab-admin');
    var adminSec=document.getElementById('admin');
    if(adminTab)adminTab.remove();
    if(adminSec)adminSec.remove();
    var settingsTab=document.getElementById('tab-settings');
    if(settingsTab)settingsTab.style.display='none'}}

function _xctXboxAuth(){
  var link=_xctApiKey?'?link='+encodeURIComponent(_xctApiKey):'';
  window.location=_API+'/api/v1/xbox/auth/start'+link}
window._xctXboxAuth=_xctXboxAuth;

function _xctXboxDisconnect(){
  if(!confirm('Disconnect your Xbox account?'))return;
  fetch(_API+'/api/v1/xbox/auth/disconnect',{
    method:'POST',headers:{'Authorization':'Bearer '+_xctApiKey}}).then(function(){
    localStorage.removeItem('xct_gamertag');localStorage.removeItem('xct_xuid');
    localStorage.removeItem('xct_avatar_url');
    _xctXboxGt='';_xctXuid='';_xctAvatarUrl='';
    _updateAuthUI()}).catch(function(e){alert('Error: '+e.message)})}

function _xctHandleOAuthReturn(){
  var p=new URLSearchParams(location.search);
  if(p.get('xbox_auth')==='success'){
    var ak=p.get('api_key'),gt=p.get('gamertag'),xu=p.get('xuid'),av=p.get('avatar_url');
    if(ak){localStorage.setItem('xct_api_key',ak);_xctApiKey=ak;window._xctApiKey=ak}
    if(gt){localStorage.setItem('xct_gamertag',gt);_xctXboxGt=gt;
      if(!_xctUser){_xctUser=gt;localStorage.setItem('xct_username',gt)}}
    if(xu){localStorage.setItem('xct_xuid',xu);_xctXuid=xu}
    if(av){localStorage.setItem('xct_avatar_url',av);_xctAvatarUrl=av}
    history.replaceState(null,'','/');return true}
  if(p.get('xbox_auth')==='error'){
    var msg=p.get('message')||'Xbox login failed';
    alert(msg);history.replaceState(null,'/','/');return false}
  return false}

window._xctUploadFile=async function(input){
  if(!input.files||!input.files[0])return;
  var file=input.files[0];
  if(file.size>20*1024*1024){alert('File too large (max 20MB)');return}
  try{
    var text=await file.text();var data=JSON.parse(text);
    if(!data.library&&!Array.isArray(data)){alert('Invalid export file');return}
    var uploadBtn=document.getElementById('xct-upload-btn');
    uploadBtn.disabled=true;uploadBtn.textContent='Uploading...';
    var r=await fetch(_API+'/api/v1/collection/upload',{
      method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+_xctApiKey},body:text});
    if(!r.ok){var e=await r.json();throw new Error(e.error||'Upload failed')}
    uploadBtn.disabled=false;uploadBtn.textContent='Upload';
    await _xctReloadCollection()
  }catch(e){alert('Upload error: '+e.message);
    var uploadBtn=document.getElementById('xct-upload-btn');
    uploadBtn.disabled=false;uploadBtn.textContent='Upload'}
  input.value=''}

function _showTabCounts(){
  if(LIB.length){document.getElementById('tab-lib-cnt').textContent=LIB.length}
  if(_phCount){document.getElementById('tab-ph').style.display='';document.getElementById('tab-ph-cnt').textContent=_phCount}
  if(ACCOUNTS.length){document.getElementById('tab-acct').style.display='';document.getElementById('tab-acct-cnt').textContent=ACCOUNTS.length}
  if(_purchCount){document.getElementById('tab-purch').style.display='';document.getElementById('tab-purch-cnt').textContent=_purchCount}
}

async function _xctReloadCollection(){
  _showLoading();
  var ok=await _loadCollection();
  if(ok){
    try{initDropdowns();filterLib()}catch(e){console.error('[auth] render error:',e)}
    _showTabCounts();
    setTimeout(function(){
      try{filterMKT();filterGP();
        if(typeof renderAccounts==='function')renderAccounts()}catch(e){console.error('[auth] deferred render error:',e)}
      if(typeof _achFetch==='function'&&!_achLoaded)_achFetch();
    },50);
  }
  _hideLoading()}

// Init
console.log('[auth] init, apiKey:',_xctApiKey?'set':'none','user:',_xctUser||'none');
_xctHandleOAuthReturn();
if(_xctApiKey){
  _showLoading();
  _loadCollection().then(function(ok){
    console.log('[auth] initial load result:',ok,'LIB:',LIB.length);
    if(ok){
      try{initDropdowns();filterLib()}catch(e){console.error('[auth] init render error:',e)}
      _showTabCounts();
      // Defer non-visible tabs to avoid blocking the UI
      setTimeout(function(){
        try{filterMKT();filterGP();
          if(typeof renderAccounts==='function')renderAccounts()}catch(e){console.error('[auth] deferred render error:',e)}
        if(typeof _achFetch==='function'&&!_achLoaded)_achFetch();
      },50);
    }
    _updateAuthUI();_hideLoading()
  }).catch(function(e){console.error('[auth] init error:',e);_updateAuthUI();_hideLoading()})
}else{_updateAuthUI()}
})();
