/* ============================================================
   나의 할 일 다이어리 — JavaScript (동작 담당)
   ============================================================
   이 파일은 앱의 모든 "동작"을 담당합니다.
   - 구조는 diary.html, 디자인은 diary.css에 있습니다.

   [초보자 팁]
   - 데이터는 브라우저의 localStorage(로컬 저장소)에 저장됩니다.
     페이지를 닫아도 데이터가 남아 있는 이유입니다.
   - "렌더링(render)" = 데이터를 바탕으로 화면(HTML)을 새로 그리는 것.
     데이터가 바뀔 때마다 render() 계열 함수를 다시 불러 화면을 갱신합니다.
   - 할 일 1개는 이런 모양의 객체입니다:
     { id:고유번호, text:내용, importance:중요도, due:기한,
       origin:처음 만든 날, dates:[머물렀던 날들], current:현재 날,
       done:완료여부, doneDate:완료한 날, doneTime:완료 시각 }
   ============================================================ */

/* ===== 데이터: localStorage에서 불러오고 저장하기 ===== */
const KEY='diaryTasks_v1';                 // 할 일 저장 키(이름표) - 평문 모드용
const KEYM='diaryMemos_v1';                // 퀵 메모 저장 키 - 평문 모드용
const KEYT='diaryTrash_v1';                // 휴지통 저장 키 - 평문 모드용
const KEYA='diaryAuth_v1';                 // 인증 설정(모드, salt, 확인값)
const KEYE='diaryData_enc_v1';             // 암호화된 데이터 덩어리(비밀번호 모드용)
let tasks=[], memos=[], trash=[];          // 실제 데이터 (boot()에서 채워짐)
let cryptoKey=null;                        // 잠금 해제 후의 암호화 키 (메모리에만 존재)

/* 저장: 비밀번호 모드면 암호화해서, 아니면 그대로 저장 */
function persistAll(){
  if(cryptoKey){ encryptStore(); }
  else{
    localStorage.setItem(KEY, JSON.stringify(tasks));
    localStorage.setItem(KEYM, JSON.stringify(memos));
    localStorage.setItem(KEYT, JSON.stringify(trash));
  }
}
function save(){ persistAll(); }
function saveM(){ persistAll(); }
function saveT(){ persistAll(); }

/* ===== 보안: 비밀번호 잠금 + 데이터 암호화 (Web Crypto API) =====
   - 비밀번호에서 PBKDF2(20만 회 반복)로 AES-256 키를 만들어
     모든 데이터를 AES-GCM으로 암호화해 저장합니다.
   - 비밀번호 자체는 어디에도 저장되지 않습니다. (잊으면 복구 불가!)   */
function b64(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function unb64(s){ return Uint8Array.from(atob(s), c=>c.charCodeAt(0)); }
async function deriveKey(pw, salt){
  const mat=await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', salt:salt, iterations:200000, hash:'SHA-256'}, mat,
    {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}
async function encJSON(obj, key){
  const iv=crypto.getRandomValues(new Uint8Array(12));  // 매번 새로운 IV
  const ct=await crypto.subtle.encrypt({name:'AES-GCM', iv:iv}, key||cryptoKey, new TextEncoder().encode(JSON.stringify(obj)));
  return b64(iv)+'.'+b64(ct);
}
async function decJSON(s, key){
  const parts=s.split('.');
  const pt=await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(parts[0])}, key||cryptoKey, unb64(parts[1]));
  return JSON.parse(new TextDecoder().decode(pt));
}
let saving=false, savePending=false;
async function encryptStore(){  // 연속 저장 요청이 겹치지 않게 큐 처리
  if(saving){ savePending=true; return; }
  saving=true;
  try{ localStorage.setItem(KEYE, await encJSON({tasks:tasks,memos:memos,trash:trash})); }catch(e){}
  saving=false;
  if(savePending){ savePending=false; encryptStore(); }
}

/* ── 잠금 화면 흐름 ── */
let lockMode='login';  // 'login'(잠금 해제) | 'setup'(비밀번호 만들기)
function getAuth(){ try{ return JSON.parse(localStorage.getItem(KEYA)||'null'); }catch(e){ return null; } }
function lockMsg(s){ document.getElementById('lockMsg').textContent=s; }
function showLock(mode){
  lockMode=mode;
  document.getElementById('lockScreen').style.display='flex';
  const pw2=document.getElementById('lockPw2'), skip=document.getElementById('lockSkip');
  document.getElementById('lockPw').value=''; pw2.value=''; lockMsg('');
  if(mode==='setup'){
    document.getElementById('lockTitle').textContent='비밀번호 만들기 (회원가입)';
    document.getElementById('lockDesc').innerHTML='이 기기의 다이어리를 보호할 비밀번호를 만들어 주세요.<br>모든 데이터가 <b>암호화되어 저장</b>됩니다.<br>⚠ 비밀번호를 잊으면 복구할 수 없으니 💾 백업 파일도 함께 보관하세요.';
    pw2.style.display=''; skip.style.display='';
  }else{
    document.getElementById('lockTitle').textContent='잠금 해제 (로그인)';
    document.getElementById('lockDesc').textContent='비밀번호를 입력하면 데이터가 해독되어 열립니다.';
    pw2.style.display='none'; skip.style.display='none';
  }
  document.getElementById('lockPw').focus();
}
function hideLock(){ document.getElementById('lockScreen').style.display='none'; }
async function lockSubmit(){
  const pw=document.getElementById('lockPw').value;
  if(!pw){ lockMsg('비밀번호를 입력해 주세요.'); return; }
  if(lockMode==='setup'){
    const pw2=document.getElementById('lockPw2').value;
    if(pw.length<4){ lockMsg('4자 이상으로 만들어 주세요.'); return; }
    if(pw!==pw2){ lockMsg('비밀번호 확인이 일치하지 않아요.'); return; }
    const salt=crypto.getRandomValues(new Uint8Array(16));
    cryptoKey=await deriveKey(pw, salt);
    const check=await encJSON('diary-ok');  // 로그인 때 비밀번호가 맞는지 확인할 값
    localStorage.setItem(KEYA, JSON.stringify({mode:'pw', salt:b64(salt), check:check}));
    loadPlain();               // 기존 평문 데이터 가져와서
    await encryptStore();      // 암호화해 저장하고
    localStorage.removeItem(KEY); localStorage.removeItem(KEYM); localStorage.removeItem(KEYT);  // 평문은 삭제
    hideLock(); startApp();
  }else{
    const a=getAuth();
    try{
      const key=await deriveKey(pw, unb64(a.salt));
      const ok=await decJSON(a.check, key);
      if(ok!=='diary-ok') throw 0;
      cryptoKey=key;
      const blob=localStorage.getItem(KEYE);
      if(blob){ const d=await decJSON(blob); tasks=d.tasks||[]; memos=d.memos||[]; trash=d.trash||[]; }
      hideLock(); startApp();
    }catch(e){ lockMsg('비밀번호가 올바르지 않습니다.'); }
  }
}
function usePlain(){  // '비밀번호 없이 사용하기'
  localStorage.setItem(KEYA, JSON.stringify({mode:'plain'}));
  loadPlain(); hideLock(); startApp();
}
function loadPlain(){  // 평문 저장소에서 불러오기
  try{ tasks=JSON.parse(localStorage.getItem(KEY)||'[]'); }catch(e){ tasks=[]; }
  try{ memos=JSON.parse(localStorage.getItem(KEYM)||'[]'); }catch(e){ memos=[]; }
  try{ trash=JSON.parse(localStorage.getItem(KEYT)||'[]'); }catch(e){ trash=[]; }
}
function lockNow(){  // 🔒 버튼: 즉시 잠그기 (평문 모드라면 비밀번호 만들기 제안)
  const a=getAuth();
  if(a&&a.mode==='pw'){ cryptoKey=null; location.reload(); }
  else if(confirm('비밀번호를 만들어 데이터를 암호화할까요?')) showLock('setup');
}

/* 30일 지난 휴지통 항목 자동 삭제 */
function purgeTrash(){
  const limit=addDays(todayStr(),-30);     // 오늘로부터 30일 전 날짜
  const before=trash.length;
  trash=trash.filter(e=>e.deletedAt>limit); // 30일 이내 것만 남김
  if(trash.length!==before) saveT();
}

/* ===== 날짜 유틸: 날짜를 'YYYY-MM-DD' 문자열로 다루는 도우미들 ===== */
const DOW=['일','월','화','수','목','금','토'];
function fmt(d){ return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0'); }
function parse(s){ const [y,m,d]=s.split('-').map(Number); return new Date(y,m-1,d); }
function addDays(s,n){ const d=parse(s); d.setDate(d.getDate()+n); return fmt(d); }  // n일 더하기
function todayStr(){ return fmt(new Date()); }
function pretty(s){ const d=parse(s); return d.getFullYear()+'년 '+(d.getMonth()+1)+'월 '+d.getDate()+'일 ('+DOW[d.getDay()]+')'; }
function shortD(s){ const d=parse(s); return (d.getMonth()+1)+'/'+d.getDate(); }

/* ===== 상태: 지금 어떤 화면을 보고 있는지 기억하는 변수들 ===== */
let view='day';               // 'day' | 'week' | 'month' | 'trash'
let selDate=todayStr();       // 지금 보고 있는 날짜
let editingId=null, editingMemoId=null, editingTimeId=null;  // 수정 중인 항목의 id

/* ===== 자동 이월: 지난 날짜의 미완료 할 일을 오늘로 옮기기 ===== */
function autoCarry(){
  const t=todayStr(); let changed=false;
  tasks.forEach(tk=>{
    if(!tk.done && tk.current<t){
      let c=tk.current;
      // 밀린 날짜들을 dates 배열에 하나씩 기록하며 오늘까지 이동
      while(c<t){ c=addDays(c,1); if(!tk.dates.includes(c)) tk.dates.push(c); }
      tk.current=t; changed=true;
    }
  });
  if(changed) save();
}

/* ===== 퀵 메모 ===== */
function addMemo(){
  const el=document.getElementById('memoText'); const txt=el.value.trim();
  if(!txt) return;
  const n=new Date();
  memos.unshift({id:'m'+Date.now(), text:txt, ts:fmt(n)+' '+n.toTimeString().slice(0,5)});
  el.value=''; saveM(); renderMemos();
}
function delMemo(id){  // 삭제 → 휴지통으로 이동
  const m=memos.find(x=>x.id===id); if(!m) return;
  trash.unshift({tid:'tm'+Date.now(), type:'memo', item:m, deletedAt:todayStr()});
  memos=memos.filter(x=>x.id!==id);
  saveM(); saveT(); renderMemos(); updateTrashBtn();
}
function startMemoEdit(id){ editingMemoId=id; renderMemos(); }
function cancelMemoEdit(){ editingMemoId=null; renderMemos(); }
function saveMemoEdit(id){
  const m=memos.find(x=>x.id===id); if(!m) return;
  const txt=document.getElementById('memoEditText').value.trim();
  if(!txt) return;
  m.text=txt; editingMemoId=null; saveM(); renderMemos();
}
function memoToTask(id){  // 메모 → 오늘의 할 일로 전환
  const m=memos.find(x=>x.id===id); if(!m) return;
  const t=todayStr();
  tasks.push({id:Date.now()+Math.random().toString(16).slice(2), text:m.text, importance:'mid', due:null,
    origin:t, dates:[t], current:t, done:false, doneDate:null, doneTime:null});
  memos=memos.filter(x=>x.id!==id);
  save(); saveM(); renderMemos(); render();
}
function toggleMemo(){  // 퀵 메모 패널 접기/펼치기
  const b=document.getElementById('memoBody');
  const open=b.style.display==='none';
  b.style.display=open?'':'none';
  document.getElementById('memoArrow').textContent=open?'▾':'▸';
}
function renderMemos(){  // 퀵 메모 목록을 화면에 그리기
  const ul=document.getElementById('memoList');
  ul.innerHTML= memos.length? memos.map(m=>{
    if(m.id===editingMemoId){  // 수정 중인 메모는 입력창으로 표시
      return '<li class="memo-item">'
        +'<input type="text" id="memoEditText" value="'+esc(m.text)+'" style="flex:1;padding:7px 10px;border:1px solid var(--accent);border-radius:8px;font-size:13px" onkeydown="if(event.key===\'Enter\')saveMemoEdit(\''+m.id+'\')">'
        +'<button onclick="saveMemoEdit(\''+m.id+'\')">✔ 저장</button>'
        +'<button onclick="cancelMemoEdit()">✖ 취소</button></li>';
    }
    return '<li class="memo-item"><div style="flex:1"><div>'+esc(m.text)+'</div><div class="m-time">'+m.ts+'</div></div>'
    +'<button onclick="startMemoEdit(\''+m.id+'\')" title="수정">✏</button>'
    +'<button onclick="memoToTask(\''+m.id+'\')" title="오늘 할 일 목록에 추가">→ 할 일로</button>'
    +'<button onclick="delMemo(\''+m.id+'\')" title="휴지통으로">🗑</button></li>';
  }).join('')
  : '<li class="memo-item" style="color:var(--sub)">메모가 없습니다. 머릿속에 떠오른 건 뭐든 바로 적어두세요!</li>';
  renderSides();  // 오른쪽 스티커 사이드바도 함께 갱신
}

/* ===== 할 일 추가/완료/이월/삭제 ===== */
function addTask(){
  const txt=document.getElementById('newText').value.trim();
  if(!txt){ alert('할 일을 입력해 주세요.'); return; }
  const imp=document.getElementById('newImp').value;
  const sel=document.getElementById('newDueSel').value;
  // 기한 선택값을 실제 날짜로 바꾸기
  let due=null;
  if(sel==='today') due=selDate;
  else if(sel==='tomorrow') due=addDays(selDate,1);
  else if(sel==='week') due=addDays(weekStart(selDate),6);
  else if(sel==='pick') due=document.getElementById('newDue').value||null;
  else if(sel==='etc') due='etc';
  tasks.push({
    id:Date.now()+Math.random().toString(16).slice(2),  // 겹치지 않는 고유 id 만들기
    text:txt, importance:imp, due:due,
    origin:selDate, dates:[selDate], current:selDate,
    done:false, doneDate:null, doneTime:null
  });
  save(); render();
}
function toggleDone(id){  // 체크박스 클릭: 완료 <-> 미완료
  const tk=tasks.find(t=>t.id===id); if(!tk) return;
  if(!tk.done){
    tk.done=true; tk.doneDate=tk.current;
    tk.doneTime=new Date().toTimeString().slice(0,5);  // 현재 시각 'HH:MM'
  }else{
    tk.done=false; tk.current=tk.doneDate; tk.doneDate=null; tk.doneTime=null;
    autoCarry();  // 과거 날짜였다면 오늘로 다시 이월
  }
  save(); render();
}
function carryTomorrow(id){  // '내일로' 버튼: 하루 뒤로 넘기기
  const tk=tasks.find(t=>t.id===id); if(!tk||tk.done) return;
  const next=addDays(tk.current,1);
  if(!tk.dates.includes(next)) tk.dates.push(next);
  tk.current=next; save(); render();
}
function delTask(id){  // 삭제 → 휴지통으로 이동 (30일 보관)
  const tk=tasks.find(t=>t.id===id); if(!tk) return;
  trash.unshift({tid:'tt'+Date.now(), type:'task', item:tk, deletedAt:todayStr()});
  tasks=tasks.filter(t=>t.id!==id);
  save(); saveT(); render();
}

/* ===== 할 일 수정 ===== */
function startEdit(id){ editingId=id; render(); }
function cancelEdit(){ editingId=null; render(); }
function saveEdit(id){
  const tk=tasks.find(t=>t.id===id); if(!tk) return;
  const txt=document.getElementById('editText').value.trim();
  if(!txt){ alert('내용을 입력해 주세요.'); return; }
  tk.text=txt;
  tk.importance=document.getElementById('editImp').value;
  const sel=document.getElementById('editDueSel').value;
  if(sel==='') tk.due=null;
  else if(sel==='etc') tk.due='etc';
  else if(sel==='pick') tk.due=document.getElementById('editDue').value||null;
  editingId=null; save(); render();
}
function editDoneText(id){  // 완료된 항목의 내용 수정 (간단히 prompt 사용)
  const tk=tasks.find(t=>t.id===id); if(!tk) return;
  const txt=prompt('내용 수정', tk.text);
  if(txt&&txt.trim()){ tk.text=txt.trim(); save(); render(); }
}

/* ===== 완료 시간 수정 ===== */
function editDoneTime(id){
  editingTimeId=id; render();
  setTimeout(function(){ const i=document.getElementById('doneTimeInput'); if(i) i.focus(); },0);
}
function saveDoneTime(id){
  const tk=tasks.find(t=>t.id===id); if(!tk) return;
  const v=document.getElementById('doneTimeInput').value;
  if(v) tk.doneTime=v;
  editingTimeId=null; save(); render();
}
function cancelDoneTime(){ editingTimeId=null; render(); }

/* 수정 폼의 <option> 목록을 만들어 주는 도우미 */
function impOpts(cur){
  return [['high','상'],['mid','중'],['low','하'],['etc','기타']].map(function(o){
    return '<option value="'+o[0]+'"'+(cur===o[0]?' selected':'')+'>중요도 '+o[1]+'</option>';
  }).join('');
}
function dueOpts(due){
  const cur= !due?'':(due==='etc'?'etc':'pick');
  return [['','기한 없음'],['pick','날짜 선택'],['etc','기한 기타']].map(function(o){
    return '<option value="'+o[0]+'"'+(cur===o[0]?' selected':'')+'>'+o[1]+'</option>';
  }).join('');
}

/* ===== 휴지통 복원/영구 삭제 ===== */
function restoreTrash(tid){
  const e=trash.find(x=>x.tid===tid); if(!e) return;
  if(e.type==='task'){ tasks.push(e.item); save(); autoCarry(); }
  else{ memos.unshift(e.item); saveM(); renderMemos(); }
  trash=trash.filter(x=>x.tid!==tid); saveT(); render();
}
function purgeOne(tid){
  const e=trash.find(x=>x.tid===tid); if(!e) return;
  if(confirm('영구 삭제할까요? 복구할 수 없습니다.')){
    trash=trash.filter(x=>x.tid!==tid); saveT(); render();
  }
}

/* ===== 네비게이션: 탭 전환, 날짜 이동 ===== */
function setView(v){ editingId=null; editingTimeId=null; view=v; render(); }
function nav(dir){  // dir: -1(이전) 또는 1(다음)
  if(view==='trash') return;
  const d=parse(selDate);
  if(view==='day') d.setDate(d.getDate()+dir);
  else if(view==='week') d.setDate(d.getDate()+dir*7);
  else d.setMonth(d.getMonth()+dir);
  selDate=fmt(d); render();
}
function goToday(){ selDate=todayStr(); if(view==='trash')view='day'; render(); }
function jumpDay(s){ selDate=s; view='day'; render(); }

/* 우선순위 스티커 클릭 → 일간 목록의 해당 항목으로 스크롤 + 반짝 강조 */
function focusTask(id){
  const tk=tasks.find(t=>t.id===id); if(!tk) return;
  selDate=tk.current; view='day'; editingId=null; render();
  const el=document.querySelector('li.task[data-id="'+id+'"]');
  if(el){
    el.scrollIntoView({behavior:'smooth', block:'center'});
    el.classList.add('focused');                                    // CSS 애니메이션 시작
    setTimeout(function(){ el.classList.remove('focused'); }, 2300); // 끝나면 제거
  }
}

/* ===== 뱃지(작은 라벨) HTML을 만들어 주는 도우미 ===== */
const IMP={high:['상','b-high'], mid:['중','b-mid'], low:['하','b-low'], etc:['기타','b-etc']};
function impBadge(tk){ const i=IMP[tk.importance]||IMP.mid; return '<span class="badge '+i[1]+'">중요도 '+i[0]+'</span>'; }
function dueBadge(tk){
  if(!tk.due) return '';
  if(tk.due==='etc') return '<span class="badge b-due">기한 기타</span>';
  const od=!tk.done && tk.due<todayStr();  // 기한이 지났는지
  return '<span class="badge b-due'+(od?' overdue':'')+'">기한 '+shortD(tk.due)+(od?' ⚠지남':'')+'</span>';
}
function carryBadge(tk,day){
  if(tk.origin===day) return '';
  const n=tk.dates.indexOf(day);
  return '<span class="badge b-carry">이월 '+(n>0?n+'회':'')+' ('+shortD(tk.origin)+'부터)</span>';
}
/* XSS 방지: 사용자가 입력한 글자에 HTML 특수문자가 있으면 무해하게 바꿈 */
function esc(s){ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

/* ===== 일간 뷰 ===== */
/* 특정 날짜의 할 일을 세 그룹으로 나누기: 진행 중 / 그날 완료 / 다른 날로 넘어감 */
function dayTasks(day){
  const list=tasks.filter(t=>t.dates.includes(day));
  return {
    active: list.filter(t=>!t.done && t.current===day),
    done:   list.filter(t=>t.done && t.doneDate===day),
    moved:  list.filter(t=> (t.done && t.doneDate>day) || (!t.done && t.current>day))
  };
}
const impRank={high:0,mid:1,low:2,etc:3};  // 정렬용: 숫자가 작을수록 위로

/* 중요도에 맞는 색상 반환 (주간/월간 막대·점에 사용) */
function impColor(t){
  return t.importance==='high'?'var(--red)'
    : t.importance==='low'?'var(--blue)'
    : t.importance==='etc'?'#8a9a8e'
    : 'var(--orange)';
}
/* 특정 날짜에 "기한 막대"를 그려야 하는 진행 중 할 일 찾기
   조건: 미완료 + 날짜형 기한 보유 + 기한이 진행일보다 뒤 + day가 진행일~기한 사이 */
function spanTasksFor(day){
  return tasks.filter(t=>!t.done && t.due && t.due!=='etc' && t.current<t.due
    && day>=t.current && day<=t.due);
}
function renderDay(){
  document.getElementById('navTitle').textContent=pretty(selDate);
  const {active,done,moved}=dayTasks(selDate);
  // 중요도 순 → 기한 빠른 순으로 정렬
  active.sort((a,b)=>{
    const r=(impRank[a.importance]??1)-(impRank[b.importance]??1); if(r) return r;
    const ad=(a.due&&a.due!=='etc')?a.due:'9999', bd=(b.due&&b.due!=='etc')?b.due:'9999';
    return ad<bd?-1:1;
  });
  const total=active.length+done.length+moved.length;
  let h='';  // 만들어질 HTML을 담는 변수

  // 상단 통계 카드
  h+='<div class="stats">'
    +'<div class="stat"><div class="num">'+total+'</div><div class="lbl">전체</div></div>'
    +'<div class="stat g"><div class="num">'+done.length+'</div><div class="lbl">완료</div></div>'
    +'<div class="stat r"><div class="num">'+active.length+'</div><div class="lbl">진행 중</div></div>'
    +'<div class="stat p"><div class="num">'+moved.length+'</div><div class="lbl">다른 날로 이월</div></div>'
    +'</div>';

  // 할 일 입력 폼
  h+='<div class="addform">'
    +'<input type="text" id="newText" placeholder="할 일을 입력하세요 (예: 이력서, 자소서 수정)" onkeydown="if(event.key===\'Enter\')addTask()">'
    +'<label>중요도<select id="newImp"><option value="high">상</option><option value="mid" selected>중</option><option value="low">하</option><option value="etc">기타</option></select></label>'
    +'<label>기한<select id="newDueSel" onchange="document.getElementById(\'newDueLab\').style.display=this.value===\'pick\'?\'\':\'none\'">'
    +'<option value="">없음</option><option value="today">오늘</option><option value="tomorrow">내일</option><option value="week">이번 주</option><option value="pick">날짜 선택</option><option value="etc">기타</option></select></label>'
    +'<label id="newDueLab" style="display:none">날짜<input type="date" id="newDue"></label>'
    +'<button onclick="addTask()">+ 추가</button>'
    +'</div>';

  // 진행 중 목록
  h+='<div class="sec-title">📌 진행 중 <span class="cnt">'+active.length+'</span></div>';
  h+= active.length? '<ul class="tasklist">'+active.map(tk=>{
      if(tk.id===editingId){  // 수정 중인 항목은 수정 폼으로 표시
        return '<li class="task"><div class="edit-form">'
          +'<input type="text" id="editText" value="'+esc(tk.text)+'" onkeydown="if(event.key===\'Enter\')saveEdit(\''+tk.id+'\')">'
          +'<select id="editImp">'+impOpts(tk.importance)+'</select>'
          +'<select id="editDueSel" onchange="document.getElementById(\'editDue\').style.display=this.value===\'pick\'?\'\':\'none\'">'+dueOpts(tk.due)+'</select>'
          +'<input type="date" id="editDue" value="'+(tk.due&&tk.due!=='etc'?tk.due:'')+'" style="display:'+(tk.due&&tk.due!=='etc'?'inline-block':'none')+'">'
          +'<button class="btn-sm btn-save" onclick="saveEdit(\''+tk.id+'\')">저장</button>'
          +'<button class="btn-sm btn-cancel" onclick="cancelEdit()">취소</button>'
          +'</div></li>';
      }
      return '<li class="task" data-id="'+tk.id+'">'
      +'<div class="chk" onclick="toggleDone(\''+tk.id+'\')"></div>'
      +'<div class="t-body"><div class="t-text">'+esc(tk.text)+'</div>'
      +'<div class="badges">'+impBadge(tk)+dueBadge(tk)+carryBadge(tk,selDate)+'</div></div>'
      +'<div class="t-acts">'
      +'<button title="수정" onclick="startEdit(\''+tk.id+'\')">✏</button>'
      +'<button title="다음날로 넘기기" onclick="carryTomorrow(\''+tk.id+'\')">↪ 내일로</button>'
      +'<button title="휴지통으로" onclick="delTask(\''+tk.id+'\')">🗑</button>'
      +'</div></li>';
    }).join('')+'</ul>'
    : '<div class="empty">진행 중인 할 일이 없습니다 🎉</div>';

  // 완료됨 목록 (기록으로 계속 남음)
  h+='<div class="sec-title">✅ 완료됨 <span class="cnt">'+done.length+'</span></div>';
  h+= done.length? '<ul class="tasklist">'+done.map(tk=>
      '<li class="task is-done">'
      +'<div class="chk done" onclick="toggleDone(\''+tk.id+'\')">✓</div>'
      +'<div class="t-body"><div class="t-text">'+esc(tk.text)+'</div>'
      +'<div class="badges">'
      +(tk.id===editingTimeId
        ? '<span class="badge b-done">완료 <input type="time" id="doneTimeInput" value="'+(tk.doneTime||'')+'" style="font-size:11px;border:none;border-radius:4px;padding:0 2px;vertical-align:middle" onkeydown="if(event.key===\'Enter\')saveDoneTime(\''+tk.id+'\')"> <span style="cursor:pointer" onclick="saveDoneTime(\''+tk.id+'\')">✔</span> <span style="cursor:pointer" onclick="cancelDoneTime()">✖</span></span>'
        : '<span class="badge b-done" style="cursor:pointer" title="완료 시간 수정" onclick="editDoneTime(\''+tk.id+'\')">완료 '+(tk.doneTime||'--:--')+' ✎</span>')
      +impBadge(tk)+carryBadge(tk,selDate)+'</div></div>'
      +'<div class="t-acts">'
      +'<button title="내용 수정" onclick="editDoneText(\''+tk.id+'\')">✏</button>'
      +'<button title="휴지통으로" onclick="delTask(\''+tk.id+'\')">🗑</button>'
      +'</div></li>').join('')+'</ul>'
    : '<div class="empty">아직 완료한 항목이 없습니다.</div>';

  // 이 날에 있었지만 다른 날로 넘어간 항목 (흐리게 표시)
  if(moved.length){
    h+='<div class="sec-title">↪ 이 날에 있었지만 다른 날로 넘어간 항목 <span class="cnt">'+moved.length+'</span></div>';
    h+='<ul class="tasklist">'+moved.map(tk=>{
      const dest=tk.done? '('+shortD(tk.doneDate)+'에 완료됨)' : '('+shortD(tk.current)+'로 이월)';
      return '<li class="task ghost"><div class="chk" style="border-color:var(--carry)"></div>'
        +'<div class="t-body"><div class="t-text">'+esc(tk.text)+'</div>'
        +'<div class="badges"><span class="badge b-moved">'+dest+'</span>'+impBadge(tk)+'</div></div></li>';
    }).join('')+'</ul>';
  }
  document.getElementById('panel').innerHTML=h;  // 완성된 HTML을 화면에 넣기
}

/* ===== 주간 뷰 ===== */
function weekStart(s){ const d=parse(s); const off=(d.getDay()+6)%7; d.setDate(d.getDate()-off); return fmt(d); }  // 그 주의 월요일
function renderWeek(){
  const start=weekStart(selDate), end=addDays(start,6);
  document.getElementById('navTitle').textContent=shortD(start)+' ~ '+shortD(end)+' 주간';
  let h='<div class="week-grid">';
  for(let i=0;i<7;i++){  // 월~일 7일 반복
    const day=addDays(start,i); const d=parse(day);
    const {active,done,moved}=dayTasks(day);
    const cls=['wday']; if(day===todayStr())cls.push('today');
    if(d.getDay()===0)cls.push('sun'); if(d.getDay()===6)cls.push('sat');
    h+='<div class="'+cls.join(' ')+'" onclick="jumpDay(\''+day+'\')">'
      +'<div class="d-head">'+d.getDate()+' <span class="dow">'+DOW[d.getDay()]+'</span></div>';
    // 기한이 있는 진행 중 할 일: 진행일부터 기한일까지 가로 막대로 길게 표시
    spanTasksFor(day).forEach(t=>{
      const isStart=(day===t.current), isEnd=(day===t.due);
      const label=isStart||i===0;  // 막대 시작일(또는 주의 첫 칸)에만 글자 표시
      h+='<div class="wbar'+(isStart?' b-start':'')+(isEnd?' b-end':'')+'" style="background:'+impColor(t)
        +'" title="'+esc(t.text)+' (기한 '+shortD(t.due)+')">'+(label?esc(t.text):'&nbsp;')+'</div>';
    });
    const items=[...done.map(t=>({t,st:'done'})), ...active.map(t=>({t,st:'act'})), ...moved.map(t=>({t,st:'mv'}))];
    items.slice(0,6).forEach(({t,st})=>{  // 최대 6개까지만 표시
      const col= st==='done'?'var(--green)': st==='mv'?'var(--carry)': impColor(t);
      h+='<div class="witem'+(st==='done'?' wdone':'')+'"><span class="dot" style="background:'+col+'"></span>'+esc(t.text)+'</div>';
    });
    if(items.length>6) h+='<div class="wcnt">+'+(items.length-6)+'개 더</div>';
    h+='<div class="wcnt">✅'+done.length+' / 📌'+active.length+(moved.length?' / ↪'+moved.length:'')+'</div></div>';
  }
  h+='</div><div class="empty" style="margin-top:10px">날짜를 클릭하면 일간 보기로 이동합니다.</div>';
  document.getElementById('panel').innerHTML=h;
}

/* ===== 월간 뷰 (달력) ===== */
function renderMonth(){
  const d=parse(selDate); const y=d.getFullYear(), m=d.getMonth();
  document.getElementById('navTitle').textContent=y+'년 '+(m+1)+'월';
  const first=new Date(y,m,1);
  const gridStart=new Date(first); gridStart.setDate(1-first.getDay());  // 달력 첫 칸(일요일)
  let h='<div class="cal-dows">'+DOW.map(x=>'<span>'+x+'</span>').join('')+'</div><div class="cal-grid">';
  for(let i=0;i<42;i++){  // 최대 6주 x 7일 = 42칸
    const cd=new Date(gridStart); cd.setDate(gridStart.getDate()+i);
    const day=fmt(cd);
    const inM=cd.getMonth()===m;  // 이번 달 날짜인지
    const {active,done,moved}=dayTasks(day);
    const total=active.length+done.length+moved.length;
    const cls=['cal-cell']; if(!inM)cls.push('dim'); if(day===todayStr())cls.push('today');
    if(cd.getDay()===0)cls.push('c-sun'); if(cd.getDay()===6)cls.push('c-sat');
    h+='<div class="'+cls.join(' ')+'" onclick="jumpDay(\''+day+'\')"><div class="dnum">'+cd.getDate()+'</div>';
    // 기한이 있는 진행 중 할 일: 기한일까지 가로 막대로 길게 표시
    spanTasksFor(day).forEach(t=>{
      const isStart=(day===t.current), isEnd=(day===t.due);
      const label=isStart||cd.getDay()===0;  // 시작일(또는 주의 첫 칸=일요일)에만 글자 표시
      h+='<div class="mbar'+(isStart?' b-start':'')+(isEnd?' b-end':'')+'" style="background:'+impColor(t)
        +'" title="'+esc(t.text)+' (기한 '+shortD(t.due)+')">'+(label?esc(t.text):'&nbsp;')+'</div>';
    });
    if(done.length) h+='<span class="cal-tag tag-done">✓ '+done.length+'</span> ';
    if(active.length) h+='<span class="cal-tag tag-todo">○ '+active.length+'</span> ';
    if(moved.length) h+='<span class="cal-tag tag-carry">↪ '+moved.length+'</span>';
    if(total) h+='<div class="cal-bar"><i style="width:'+Math.round(done.length/total*100)+'%"></i></div>';  // 달성률 막대
    h+='</div>';
    if(i>=35 && cd.getMonth()!==m && cd.getDate()<8) break;  // 다음 달로 넘어가면 그만 그리기
  }
  h+='</div><div class="empty" style="margin-top:10px">✓ 완료 · ○ 미완료 · ↪ 이월 &nbsp;|&nbsp; 날짜를 클릭하면 일간 보기로 이동합니다.</div>';
  document.getElementById('panel').innerHTML=h;
}

/* ===== 휴지통 뷰 ===== */
function renderTrash(){
  document.getElementById('navTitle').textContent='🗑 휴지통';
  let h='<div class="trash-note">삭제된 할 일과 메모는 여기에 <b>30일간 보관</b>된 후 자동으로 완전 삭제됩니다. 실수로 지웠다면 복원할 수 있어요.</div>';
  if(!trash.length){
    h+='<div class="empty">휴지통이 비어 있습니다.</div>';
  }else{
    h+='<ul class="tasklist">'+trash.map(e=>{
      const it=e.item;
      // 남은 보관일 계산 (밀리초 차이를 일 수로 변환: 86400000ms = 하루)
      const dleft=Math.max(0, Math.round((parse(addDays(e.deletedAt,30))-parse(todayStr()))/86400000));
      return '<li class="task"><div class="t-body"><div class="t-text">'+esc(it.text)+'</div>'
        +'<div class="badges">'
        +'<span class="badge b-due">'+(e.type==='task'?'📋 할 일':'💭 메모')+'</span>'
        +'<span class="badge b-due">삭제일 '+shortD(e.deletedAt)+'</span>'
        +'<span class="badge b-dday">'+dleft+'일 후 자동 삭제</span>'
        +(e.type==='task'&&it.done?'<span class="badge b-done">완료 기록</span>':'')
        +'</div></div>'
        +'<div class="t-acts">'
        +'<button onclick="restoreTrash(\''+e.tid+'\')">↩ 복원</button>'
        +'<button onclick="purgeOne(\''+e.tid+'\')">✖ 영구 삭제</button>'
        +'</div></li>';
    }).join('')+'</ul>';
  }
  document.getElementById('panel').innerHTML=h;
}

/* ===== 백업(내보내기) / 복원(불러오기) ===== */
function exportData(){
  // 모든 데이터를 JSON 파일로 다운로드
  const blob=new Blob([JSON.stringify({tasks:tasks,memos:memos,trash:trash},null,2)],{type:'application/json'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='diary-backup-'+todayStr()+'.json';
  a.click();
}
function importData(ev){
  const f=ev.target.files[0]; if(!f)return;
  const r=new FileReader();
  r.onload=()=>{
    try{
      const data=JSON.parse(r.result);
      const tArr=Array.isArray(data)?data:data.tasks;   // 옛날 백업 형식도 지원
      const mArr=Array.isArray(data)?[]:(data.memos||[]);
      if(!Array.isArray(tArr)) throw 0;
      if(confirm('현재 데이터를 백업 파일로 교체할까요? (할 일 '+tArr.length+'개)')){
        tasks=tArr; memos=mArr;
        trash=Array.isArray(data)?[]:(data.trash||[]);
        save(); saveM(); saveT(); purgeTrash(); autoCarry(); render(); renderMemos();
      }
    }catch(e){ alert('올바른 백업 파일이 아닙니다.'); }
  };
  r.readAsText(f); ev.target.value='';
}

/* ===== 좌우 스티커메모 사이드바 ===== */
function renderSides(){
  // 왼쪽: 오늘의 우선순위 (오늘 진행 중 + 중요도 상/중만)
  const hot=document.getElementById('hotList');
  const t=todayStr();
  const list=tasks.filter(x=>!x.done && x.current===t && (x.importance==='high'||x.importance==='mid'))
    .sort((a,b)=>(impRank[a.importance]??1)-(impRank[b.importance]??1));
  hot.innerHTML=list.length? list.map(x=>
    '<div class="sticky '+(x.importance==='high'?'hot':'midp')+'" title="일간 목록에서 이 항목 보기" onclick="focusTask(\''+x.id+'\')">'+esc(x.text)
    +'<div class="s-date">중요도 '+(x.importance==='high'?'상':'중')
    +(x.due?(' · 기한 '+(x.due==='etc'?'기타':shortD(x.due))):'')+'</div></div>').join('')
  :'<div class="side-empty">오늘 우선순위(상·중) 할 일이 없어요 🎉</div>';

  // 오른쪽: 퀵 메모 스티커
  const sm=document.getElementById('stickyMemos');
  sm.innerHTML=memos.length? memos.map(m=>
    '<div class="sticky">'+esc(m.text)+'<div class="s-date">'+m.ts+'</div></div>').join('')
  :'<div class="side-empty">메모가 없어요</div>';
}

/* ===== 화면 전체 렌더링 ===== */
function updateTrashBtn(){  // 휴지통 버튼에 개수 표시
  const b=document.getElementById('trashBtn');
  if(b) b.textContent='🗑 휴지통'+(trash.length?' ('+trash.length+')':'');
}
function render(){
  // 현재 view에 맞는 탭에 'on' 클래스 붙이기
  ['day','week','month'].forEach(v=>document.getElementById('tab-'+v).classList.toggle('on',v===view));
  updateTrashBtn();
  renderSides();
  if(view==='day') renderDay();
  else if(view==='week') renderWeek();
  else if(view==='month') renderMonth();
  else renderTrash();
}

/* ===== 시작! (페이지가 열리면 아래가 순서대로 실행됨) ===== */
function startApp(){   // 잠금 해제(또는 평문 모드 확인) 후 실제 앱 시작
  purgeTrash();   // 1. 30일 지난 휴지통 항목 정리
  autoCarry();    // 2. 지난 날짜 미완료 할 일을 오늘로 이월
  render();       // 3. 화면 그리기
  renderMemos();  // 4. 퀵 메모 그리기
}
function boot(){       // 첫 진입: 잠금 상태에 따라 화면 결정
  if(!(window.crypto&&crypto.subtle)){  // 암호화를 지원하지 않는 브라우저
    localStorage.setItem(KEYA, JSON.stringify({mode:'plain'}));
    loadPlain(); startApp(); return;
  }
  const a=getAuth();
  if(!a) showLock('setup');             // 처음 사용 → 비밀번호 만들기(회원가입)
  else if(a.mode==='plain'){ loadPlain(); startApp(); }  // 비밀번호 없이 사용 중
  else showLock('login');               // 비밀번호 모드 → 잠금 해제(로그인)
}
boot();
