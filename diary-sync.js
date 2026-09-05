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
         GoogleAuthProvider, signInWithPopup,
         onAuthStateChanged, signOut } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js";
import { getFirestore, doc, getDoc, setDoc } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js";

/* ▼▼▼ Firebase 설정값 (콘솔 > 프로젝트 설정 > 내 앱 > SDK 구성) ▼▼▼
   ※ 이 값들은 공개되어도 안전한 "프로젝트 이름표"입니다.
      실제 보안은 Firestore 보안 규칙이 담당합니다.                      */
const firebaseConfig = {
  apiKey:            "AIzaSyD1CSN9Lk_1tmU_geFAjukT4q5-odGAKBg",
  authDomain:        "my-diary-7.firebaseapp.com",
  projectId:         "my-diary-7",
  storageBucket:     "my-diary-7.firebasestorage.app",
  messagingSenderId: "969654501721",
  appId:             "1:969654501721:web:c409cdf8b9ddee88210c48"
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
        <p class="lock-desc">로그인하면 PC와 폰에서<br>같은 데이터를 쓸 수 있어요.</p>

        <!-- 구글 계정으로 한 번에 로그인 (공식 4색 로고를 SVG로 직접 그림) -->
        <button class="g-login-btn" onclick="googleLogin()">
          <svg class="g-logo" viewBox="0 0 48 48" aria-hidden="true">
            <path fill="#4285F4" d="M45.12 24.5c0-1.56-.14-3.06-.4-4.5H24v8.51h11.84c-.51 2.75-2.06 5.08-4.39 6.64v5.52h7.11c4.16-3.83 6.56-9.47 6.56-16.17z"/>
            <path fill="#34A853" d="M24 46c5.94 0 10.92-1.97 14.56-5.33l-7.11-5.52c-1.97 1.32-4.49 2.1-7.45 2.1-5.73 0-10.58-3.87-12.31-9.07H4.34v5.7C7.96 41.07 15.4 46 24 46z"/>
            <path fill="#FBBC05" d="M11.69 28.18C11.25 26.86 11 25.45 11 24s.25-2.86.69-4.18v-5.7H4.34C2.85 17.09 2 20.45 2 24s.85 6.91 2.34 9.88l7.35-5.7z"/>
            <path fill="#EA4335" d="M24 10.75c3.23 0 6.13 1.11 8.41 3.29l6.31-6.31C34.91 4.18 29.93 2 24 2 15.4 2 7.96 6.93 4.34 14.12l7.35 5.7c1.73-5.2 6.58-9.07 12.31-9.07z"/>
          </svg>
          <span>Google 계정으로 계속하기</span>
        </button>
        <div class="or-line"><span>또는 이메일로</span></div>

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

/* ── 구글 계정으로 로그인 (팝업) ── */
window.googleLogin = async function(){
  try{
    await signInWithPopup(auth, new GoogleAuthProvider());
    msg('syncMsg','');
  }catch(e){
    const c=(e&&e.code)||'';
    if(c.includes('popup-closed')||c.includes('cancelled-popup')) return;  // 사용자가 창을 닫음
    if(c.includes('operation-not-allowed'))
      msg('syncMsg','Firebase 콘솔에서 Google 로그인을 켜주세요.');
    else if(c.includes('popup-blocked'))
      msg('syncMsg','브라우저가 팝업을 막았어요. 팝업 허용 후 다시 시도해 주세요.');
    else msg('syncMsg', friendly(e));
  }
};

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
