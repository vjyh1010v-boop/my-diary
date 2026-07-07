/* ============================================================
   나의 할 일 다이어리 — 클라우드 동기화 (Firebase 백엔드)
   ============================================================
   기기 간(PC ↔ 폰) 데이터 백업·동기화를 담당하는 선택 모듈입니다.
   diary.js와 별개로 동작하며, 없어도 다이어리는 정상 작동해요.

   [동작 원리 — 초보자용]
   1. 이메일/비밀번호로 클라우드 계정을 만들고 로그인합니다. (Firebase Authentication)
   2. ⬆ 업로드: 이 기기의 다이어리 데이터를 내 계정 전용 공간에 저장. (Firestore)
   3. ⬇ 다운로드: 다른 기기에서 로그인 후 내려받으면 같은 데이터가 복원됩니다.

   [보안]
   - 다이어리에 비밀번호 잠금을 켜둔 상태라면, "암호화된 덩어리" 그대로
     업로드되므로 서버(구글)조차 내용을 읽을 수 없습니다. (종단간 암호화)
   - 다른 기기에서 내려받은 뒤에는 같은 다이어리 비밀번호로 잠금을 풀면 됩니다.

   ⚠ 이 파일은 '백엔드-동기화-설정가이드.md'를 따라
     Firebase 설정값을 붙여넣어야 동작합니다. (호스팅 필요: GitHub Pages 등)
   ============================================================ */

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js";
import { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword,
         onAuthStateChanged, signOut } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js";
import { getFirestore, doc, getDoc, setDoc } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js";

/* ▼▼▼ [여기에 붙여넣기] Firebase 콘솔 > 프로젝트 설정 > 내 앱 > SDK 구성 ▼▼▼ */
const firebaseConfig = {
  apiKey:     "여기에_apiKey_붙여넣기",
  authDomain: "프로젝트이름.firebaseapp.com",
  projectId:  "프로젝트이름",
  appId:      "여기에_appId_붙여넣기"
};
/* ▲▲▲ ------------------------------------------------------------ ▲▲▲ */

const configured = !/여기에/.test(firebaseConfig.apiKey);  // 키를 붙여넣었는지 확인
let auth=null, db=null, user=null;

if(configured){
  const app = initializeApp(firebaseConfig);
  auth = getAuth(app);
  db   = getFirestore(app);
  onAuthStateChanged(auth, u => { user=u; refreshUI(); });  // 로그인 상태 변화 감지
}

/* ── 동기화 대상: 다이어리가 localStorage에 저장하는 모든 키 ──
   (비밀번호 모드면 enc에 암호화 덩어리가, 평문 모드면 tasks/memos/trash에 데이터가 있음) */
const SYNC_KEYS = ['diaryAuth_v1','diaryData_enc_v1','diaryTasks_v1','diaryMemos_v1','diaryTrash_v1'];

/* ── 동기화 팝업 UI 만들기 (잠금 화면과 같은 디자인 재사용) ── */
function ensureUI(){
  if(document.getElementById('syncScreen')) return;
  document.body.insertAdjacentHTML('beforeend', `
  <div id="syncScreen" class="lock-screen" style="display:none">
    <div class="lock-card">
      <div class="lock-logo">☁️</div>
      <h2>클라우드 동기화</h2>

      <!-- 로그인 전 화면 -->
      <div id="syncAuthBox">
        <p class="lock-desc">이메일 계정으로 로그인하면<br>PC와 폰에서 같은 데이터를 쓸 수 있어요.</p>
        <input type="email" id="syncEmail" placeholder="이메일" autocomplete="email">
        <input type="password" id="syncPw" placeholder="비밀번호 (6자 이상)" autocomplete="current-password"
               onkeydown="if(event.key==='Enter')cloudLogin()">
        <div class="lock-msg" id="syncMsg"></div>
        <button class="lock-btn" onclick="cloudLogin()">로그인</button>
        <button class="lock-skip" onclick="cloudSignup()">처음이에요 — 회원가입</button>
      </div>

      <!-- 로그인 후 화면 -->
      <div id="syncBox" style="display:none">
        <p class="lock-desc" id="syncStatus"></p>
        <button class="lock-btn" onclick="cloudUpload()">⬆ 클라우드에 업로드</button>
        <button class="lock-btn" style="margin-top:8px" onclick="cloudDownload()">⬇ 클라우드에서 다운로드</button>
        <div class="lock-msg" id="syncMsg2"></div>
        <button class="lock-skip" onclick="cloudLogout()">로그아웃</button>
      </div>

      <button class="lock-skip" onclick="cloudSyncClose()">닫기</button>
    </div>
  </div>`);
}

function msg(id, s){ const e=document.getElementById(id); if(e) e.textContent=s; }

/* 로그인 상태에 따라 화면 전환 + 마지막 업로드 시각 표시 */
async function refreshUI(){
  ensureUI();
  document.getElementById('syncAuthBox').style.display = user ? 'none' : '';
  document.getElementById('syncBox').style.display     = user ? '' : 'none';
  if(user){
    let last='아직 업로드한 적 없음';
    try{
      const snap = await getDoc(doc(db,'diaries',user.uid));
      if(snap.exists() && snap.data().updatedAt) last='마지막 업로드: '+new Date(snap.data().updatedAt).toLocaleString('ko-KR');
    }catch(e){}
    document.getElementById('syncStatus').innerHTML = '👤 '+user.email+'<br>'+last;
  }
}

/* 친절한 오류 메시지 변환 */
function friendly(e){
  const c=(e&&e.code)||'';
  if(c.includes('invalid-email')) return '이메일 형식이 올바르지 않아요.';
  if(c.includes('email-already-in-use')) return '이미 가입된 이메일이에요. 로그인해 주세요.';
  if(c.includes('weak-password')) return '비밀번호는 6자 이상이어야 해요.';
  if(c.includes('invalid-credential')||c.includes('wrong-password')||c.includes('user-not-found')) return '이메일 또는 비밀번호가 올바르지 않아요.';
  if(c.includes('network')) return '인터넷 연결을 확인해 주세요.';
  return '오류: '+c;
}

/* ── 화면 열기/닫기 ── */
window.cloudSyncOpen = function(){
  ensureUI();
  if(!configured){
    alert('클라우드 동기화를 쓰려면 먼저 설정이 필요해요.\n"백엔드-동기화-설정가이드.md" 문서를 따라 Firebase 키를 diary-sync.js에 붙여넣어 주세요.');
    return;
  }
  document.getElementById('syncScreen').style.display='flex';
  refreshUI();
};
window.cloudSyncClose = function(){ document.getElementById('syncScreen').style.display='none'; };

/* ── 회원가입 / 로그인 / 로그아웃 ── */
window.cloudSignup = async function(){
  try{
    await createUserWithEmailAndPassword(auth, document.getElementById('syncEmail').value.trim(), document.getElementById('syncPw').value);
    msg('syncMsg','');
  }catch(e){ msg('syncMsg', friendly(e)); }
};
window.cloudLogin = async function(){
  try{
    await signInWithEmailAndPassword(auth, document.getElementById('syncEmail').value.trim(), document.getElementById('syncPw').value);
    msg('syncMsg','');
  }catch(e){ msg('syncMsg', friendly(e)); }
};
window.cloudLogout = async function(){ await signOut(auth); };

/* ── ⬆ 업로드: 이 기기의 데이터를 내 계정 공간에 저장 ── */
window.cloudUpload = async function(){
  if(!user) return;
  try{
    const dump={ updatedAt: Date.now() };
    SYNC_KEYS.forEach(k=>{ dump[k]=localStorage.getItem(k); });  // null이면 null 그대로 저장
    await setDoc(doc(db,'diaries',user.uid), dump);
    msg('syncMsg2','✅ 업로드 완료!');
    refreshUI();
  }catch(e){ msg('syncMsg2', friendly(e)); }
};

/* ── ⬇ 다운로드: 클라우드 데이터로 이 기기를 덮어쓰기 ── */
window.cloudDownload = async function(){
  if(!user) return;
  try{
    const snap=await getDoc(doc(db,'diaries',user.uid));
    if(!snap.exists()){ msg('syncMsg2','클라우드에 저장된 데이터가 없어요. 먼저 업로드해 주세요.'); return; }
    if(!confirm('이 기기의 데이터를 클라우드 데이터로 교체할까요?\n(교체 전 데이터가 걱정되면 먼저 💾 백업을 해두세요)')) return;
    const d=snap.data();
    SYNC_KEYS.forEach(k=>{
      if(d[k]===null||d[k]===undefined) localStorage.removeItem(k);
      else localStorage.setItem(k, d[k]);
    });
    alert('✅ 다운로드 완료! 페이지를 새로 열게요.\n(비밀번호 잠금을 쓰는 중이라면, 업로드한 기기와 같은 다이어리 비밀번호로 잠금을 풀면 됩니다)');
    location.reload();
  }catch(e){ msg('syncMsg2', friendly(e)); }
};
